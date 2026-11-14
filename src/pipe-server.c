/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (c) Invisible Things Lab
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <windows.h>
#include <stdlib.h>
#include <strsafe.h>

#include "buffer.h"
#include "log.h"
#include "qubes-io.h"
#include "list.h"

#include "pipe-server.h"

typedef struct _PIPE_CLIENT
{
    LIST_ENTRY ListEntry;
    LONGLONG Id;
    HANDLE WritePipe;
    HANDLE ReadPipe;
    CMQ_BUFFER *ReadBuffer;
    CMQ_BUFFER *WriteBuffer;
    BOOL Disconnecting;
    CRITICAL_SECTION Lock;
    HANDLE ReaderThread;
    HANDLE WriterThread;
    LONG RefCount;
    PVOID UserData;
} PIPE_CLIENT, *PPIPE_CLIENT;

typedef struct _PIPE_SERVER
{
    WCHAR PipeName[256];
    DWORD PipeBufferSize;
    DWORD InternalBufferSize;
    DWORD WriteTimeout;
    PSECURITY_ATTRIBUTES SecurityAttributes;
    LONGLONG NumberClients;
    LONGLONG NextClientId;
    LIST_ENTRY Clients;
    BOOL AcceptConnections;
    // Set by QpsDestroy, which does NOT free this object - see there. Read by QpsGetClientRaw,
    // which every function that takes a client id goes through, so a call that arrives after the
    // destroy is answered with "no such client" instead of searching a list that is gone.
    BOOL Destroyed;
    CRITICAL_SECTION Lock;

    PVOID UserContext;

    QPS_CLIENT_CONNECTED ConnectCallback;
    QPS_CLIENT_DISCONNECTED DisconnectCallback;
    QPS_DATA_RECEIVED ReadCallback;
} *PIPE_SERVER;

// used for passing data to worker threads
struct THREAD_PARAM
{
    PIPE_SERVER Server;
    LONGLONG ClientId;
};

// Initialize data for a newly connected client.
static DWORD QpsConnectClient(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    IN  HANDLE WritePipe,
    IN  HANDLE ReadPipe
    );

// Disconnect can be called from inside worker threads, we don't want to
// wait for them in that case.
static void QpsDisconnectClientInternal(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    IN  BOOL WriterExiting,
    IN  BOOL ReaderExiting
    );

// Create the server.
DWORD QpsCreate(
    IN  PWCHAR PipeName, // This is a client->server pipe name (clients write, server reads). server->client pipes have "-%PID%" appended.
    IN  DWORD PipeBufferSize, // Pipe read/write buffer size. Shouldn't be too big.
    IN  DWORD InternalBufferSize, // Internal read/write buffer (per client).
    IN  DWORD WriteTimeout, // If a client doesn't read written data in this amount of milliseconds, it's disconnected.
    IN  QPS_CLIENT_CONNECTED ConnectCallback, // "Client connected" callback.
    IN  QPS_CLIENT_DISCONNECTED DisconnectCallback OPTIONAL, // "Client disconnected" callback.
    IN  QPS_DATA_RECEIVED ReadCallback OPTIONAL, // "Data received" callback.
    IN  PVOID Context OPTIONAL, // Opaque parameter that will be passed to callbacks.
    IN  PSECURITY_ATTRIBUTES SecurityAttributes OPTIONAL, // Must be valid for the whole lifetime of the server.
    OUT PIPE_SERVER *Server // Server object.
    )
{
    DWORD Status = ERROR_NOT_ENOUGH_MEMORY;

    LogVerbose("pipe name '%s'", PipeName);
    *Server = malloc(sizeof(struct _PIPE_SERVER));
    if (*Server == NULL)
        goto cleanup;

    ZeroMemory(*Server, sizeof(struct _PIPE_SERVER));

    StringCbCopyW((*Server)->PipeName, sizeof((*Server)->PipeName), PipeName);
    (*Server)->PipeBufferSize = PipeBufferSize;
    (*Server)->InternalBufferSize = InternalBufferSize;
    (*Server)->WriteTimeout = WriteTimeout;
    (*Server)->SecurityAttributes = SecurityAttributes;

    (*Server)->ConnectCallback = ConnectCallback;
    (*Server)->DisconnectCallback = DisconnectCallback;
    (*Server)->ReadCallback = ReadCallback;
    (*Server)->UserContext = Context;

    InitializeListHead(&(*Server)->Clients);

    InitializeCriticalSection(&(*Server)->Lock);

    (*Server)->AcceptConnections = TRUE;

    Status = ERROR_SUCCESS;

cleanup:
    if (Status != ERROR_SUCCESS)
    {
        QpsDestroy(*Server);
        *Server = NULL;
    }
    return Status;
}

void QpsDestroy(
    PIPE_SERVER Server
    )
{
    if (!Server)
        return;

    // get list of current clients
    EnterCriticalSection(&Server->Lock);
    Server->AcceptConnections = FALSE;
    LONGLONG* clientIds = malloc(Server->NumberClients * sizeof(clientIds[0]));
    if (!clientIds)
        exit(ERROR_OUTOFMEMORY);

    LONGLONG clientCount = 0;
    PLIST_ENTRY entry = Server->Clients.Flink;
    while (entry != &Server->Clients)
    {
        PPIPE_CLIENT client = (PPIPE_CLIENT)CONTAINING_RECORD(entry, PIPE_CLIENT, ListEntry);
        clientIds[clientCount++] = client->Id; // can't call disconnect here, would deadlock on QpsReleaseClient

        entry = entry->Flink;
    }
    LeaveCriticalSection(&Server->Lock);

    // disconnect all clients, need to be not holding the global lock
    LogDebug("Removing %ll clients", clientCount);
    LONGLONG clientsAtDestroy = clientCount;
    while (clientCount > 0)
    {
        --clientCount;
        // if a client is disconnected in the meantime it's ok
        QpsDisconnectClientInternal(Server, clientIds[clientCount], FALSE, FALSE);
    }

    // THE SERVER OBJECT IS DELIBERATELY RETAINED, AND ITS LOCK LEFT VALID. A caller can still
    // legally reach this pointer after QpsDestroy returns, because the per-client threads that use
    // it are not this library's and nothing joins them.
    //
    // MEASURED on a Win10 Qubes guest, 2026-10-26, acceptance cell WIN10-reinstall of campaign
    // rel-40243956400-r2 (qubesdb-daemon ver 4.3.1.0, pid 3488), four lines from one clock:
    //   092152.485 [3788-I] mainloop: service stopped, exiting          <- the daemon enters cleanup
    //   092153.517 [3788-I] QpsDisconnectClientInternal: [9] (000001C9A2CCEDB0) disconnecting,
    //                       WriterExiting 0, ReaderExiting 0            <- THIS function, main thread
    //   092153.533 [4624-W] pipe_thread_client: QpsRead from client 9 failed: 109
    //   092153.535 [4624-E] ErrUEF: Unhandled exception c0000005 at 00007FF8CCD3FAAD, flags: 0
    // The daemon's own cleanup path (qubes-core-qubesdb daemon/db-daemon.c) waits for the ACCEPT
    // thread only, then calls QpsDestroy and nulls its pointer; its per-client threads are created
    // with CreateThread + an immediate CloseHandle and are never joined. Such a thread returns from
    // QpsRead with ERROR_BROKEN_PIPE - the 109 above, which this file's own disconnecting branch
    // returns - and its next statement is QpsDisconnectClient(d->pipe_server, id), whose first act
    // is EnterCriticalSection(&Server->Lock). Eighteen milliseconds separated the two threads, and
    // the three lines below are what made that window fatal rather than harmless.
    //
    // SO THE FIX IS HERE AND NOT IN THE CALLER: qubesdb-daemon.exe is deliberately not built by the
    // QWT fork (wave 3, boot-critical) while windows-utils.dll is, and the stock exe RUNS THIS
    // FILE out of that DLL. Proven from the same capture by a line that is ABSENT: pristine
    // QpsDisconnectClientInternal logs both "disconnecting, WriterExiting .." and "disconnected
    // (%lld total)" at LogInfo, and windows-utils-percall-mechanics-debug.patch demotes the second
    // to LogDebug. qubesdb-daemon's logs hold 61 of the first and ZERO of the second, with no
    // DEBUG-level line anywhere in the file - so the code that wrote them is the patched copy, not
    // the stock one. (The QWTBIRTH banner and the one-file-per-module name prove only that log.c is
    // ours.) A patch to the caller would change nothing on a guest; this one ships.
    //
    // THE COST IS ONE RETAINED ALLOCATION PER DESTROYED SERVER, sizeof(struct _PIPE_SERVER), on a
    // path that runs when a server is torn down - twice per process at most in the shipped callers,
    // both in teardown paths of main. That is the whole price of a pointer that stays safe to call.
    // Nothing else leaks: every client's buffers, locks and handles were freed by the disconnect
    // loop above, and clientIds is freed below as before.
    //
    // (The ZeroMemory this replaces took sizeof(PIPE_SERVER) - the size of the POINTER, 8 bytes -
    // not sizeof(struct _PIPE_SERVER). It cleared the head of PipeName and nothing else, which is
    // its own small sign that this teardown had never been exercised under a live client.)
    // NO LOCK IS TAKEN TO SET THIS FLAG, deliberately. Two TerminateThread calls can orphan
    // &Server->Lock while this function runs - the one in QpsDisconnectClientInternal above
    // ("reader thread didn't terminate in time, killing it"), whose own comment already says it
    // "may leak memory or do other nasty things", and the caller's own TerminateThread on the
    // accept thread after its 1000 ms wait. A lock taken here would then wait for ever, and a
    // destroy that hangs at service stop is worse than the crash this patch removes. An
    // InterlockedExchange publishes the flag with a full barrier and cannot block; readers take it
    // with a single load and need nothing more.
    InterlockedExchange((LONG *)&Server->Destroyed, TRUE);

    free(clientIds);

    LogInfo("QPSDESTROYED server object retained and marked destroyed after %lld client(s) were disconnected; a late caller is answered, not crashed", clientsAtDestroy);
}

static LONGLONG QpsAllocateClientId(
    IN  PIPE_SERVER Server
    )
{
    return InterlockedIncrement64(&Server->NextClientId);
}

// Get client's data by ID and optionally increase the client's refcount.
// DO NOT USE unless you know EXACTLY why you want to NOT increase the refcount.
static PPIPE_CLIENT QpsGetClientRaw(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    IN  BOOL IncreaseRefcount
    )
{
    PLIST_ENTRY entry;
    PPIPE_CLIENT returnClient = NULL;

    // A CALL CAN ARRIVE AFTER THE SERVER WAS DESTROYED, and until 2026-10-26 it was answered with
    // an access violation - see QpsDestroy for the measurement. Every public function that takes a
    // client id reaches the client list through this one lookup and every one of them already
    // handles a NULL result (ERROR_NOT_CONNECTED, or the "not connected" warning in
    // QpsDisconnectClientInternal), so this is the single place the condition has to be stated.
    // NULL is checked too: the shipped caller nulls its server pointer right after the destroy, so
    // a late call carries either the retained object or NULL, and both arrive here.
    if (!Server || Server->Destroyed)
    {
        LogDebug("[%lld] no client list to search: the server is %s", ClientId, Server ? "destroyed" : "NULL");
        return NULL;
    }

    EnterCriticalSection(&Server->Lock);
    entry = Server->Clients.Flink;
    while (entry != &Server->Clients)
    {
        PPIPE_CLIENT client = (PPIPE_CLIENT)CONTAINING_RECORD(entry, PIPE_CLIENT, ListEntry);
        if (client->Id == ClientId)
        {
            returnClient = client;
            // The reference is taken under the list lock. The last release unlinks and frees the
            // client under this same lock, so it cannot happen between the find and the count.
            if (IncreaseRefcount)
                InterlockedIncrement(&returnClient->RefCount);
            break;
        }

        entry = entry->Flink;
    }
    LeaveCriticalSection(&Server->Lock);

    if (returnClient)
    {
        LogVerbose("[%lld] (%p) refs: %ld", returnClient->Id, returnClient, returnClient->RefCount);
    }
    else
    {
        LogVerbose("[%lld] not found", ClientId);
    }

    return returnClient;
}

// Use this function to access client's data by ID. It increases the client's refcount.
// Call QpsReleaseClient after you're done touching the client's data.
static PPIPE_CLIENT QpsGetClient(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId
    )
{
    return QpsGetClientRaw(Server, ClientId, TRUE);
}

// Release the client (decreases the client's refcount).
// Server or client lock must *NOT* be held.
static void QpsReleaseClient(
    IN  PIPE_SERVER Server,
    IN  PPIPE_CLIENT Client
    )
{
    // it's possible that multiple threads hit the refcount==0 comparison simultaneously, locking is needed
    // can't use the client lock obviously since client's data is being freed
    // the global server lock isn't ideal but we would use it anyway to protect access to the client list...
    EnterCriticalSection(&Server->Lock);
    InterlockedDecrement(&Client->RefCount);
    LogVerbose("[%lld] (%p) refs: %ld", Client->Id, Client, Client->RefCount);

    if (Client->RefCount == 0)
    {
        // Free client's data.
        // This should only occur on disconnection as reader/writer threads always have a ref to client's data.
        LogDebug("[%lld] freeing client data %p", Client->Id, Client);
        CmqDestroy(Client->ReadBuffer);
        CmqDestroy(Client->WriteBuffer);

        DeleteCriticalSection(&Client->Lock);

        RemoveEntryList(&Client->ListEntry);

        ZeroMemory(Client, sizeof(PIPE_CLIENT));
        free(Client);

        InterlockedDecrement64(&Server->NumberClients);
    }
    LeaveCriticalSection(&Server->Lock);
}

/*
MSDN says:
The ReadFile function returns when one of the following conditions occur:
- The number of bytes requested is read.
- A write operation completes on the write end of the pipe.
- An asynchronous handle is being used and the read is occurring asynchronously.
- An error occurs.

That means we can do ReadFile synchronously with a large buffer and not block until
the whole buffer is read. The read will return once *something* is written to the other end.
*/
static DWORD WINAPI QpsReaderThread(
    PVOID Param
    )
{
    struct THREAD_PARAM *param = Param;
    PIPE_SERVER server = param->Server;
    PPIPE_CLIENT client = QpsGetClient(server, param->ClientId);

    // THE CLIENT CAN BE GONE BEFORE THIS THREAD RUNS, and then there is nothing to read from.
    // QpsConnectClient starts this thread and returns; a disconnect landing in between unlinks the
    // client, QpsGetClient returns NULL, and the dereference below used to be this thread's FIRST
    // statement. Every other function in this file answers the same race with ERROR_NOT_CONNECTED;
    // the two thread entries answered it with an access violation, which kills the whole service.
    // MEASURED on a Qubes Windows guest 2026-10-14: qrexec-agent.exe took c0000005 reading address
    // 0x18 - WritePipe, the writer thread's version of this line - 116 ms after "[2] (...)
    // connected" and 54 ms after a disconnect had logged "[2] not connected", and the Qubes RPC
    // agent service stopped (System/7031). In the same seconds a client call got the HANDLED form
    // of the race, ERROR_NOT_CONNECTED (0x8ca), from QpsRead.
    // A DISCONNECT IS NOT THE ONLY WAY IN. QpsConnectClient creates both threads BEFORE
    // InsertTailList, and each of its error paths after the first CreateThread returns without
    // inserting the client, without stopping the thread it already started and without freeing
    // anything - so that thread looks up an id the list will never hold. The lookup failing is
    // therefore an ordinary outcome, not an exotic race, and it is handled rather than assumed away.
    // The line below states the FACT the lookup gives - the id is not in the list - and not a
    // cause: "disconnected" would be wrong on the never-inserted path.
    if (!client)
    {
        LogWarning("[%lld] not in the client list; reader thread exits", param->ClientId);
        free(param);
        return 1;
    }

    HANDLE pipe = client->ReadPipe;
    PVOID buffer = malloc(server->PipeBufferSize);
    DWORD transferred;

    LogVerbose("[%lld] (%p) start", client->Id, client);
    if (!buffer)
    {
        LogError("no memory");
        QpsReleaseClient(server, client);
        QpsDisconnectClientInternal(server, param->ClientId, FALSE, TRUE);
        free(param);
        return 1;
    }

    // This thread endlessly tries to read from the client's read pipe.
    // Read data is enqueued into the internal buffer.
    while (TRUE)
    {
        LogVerbose("[%lld] reading...", client->Id);

        // Only as many bytes as the read buffer has room for are taken from the pipe. The rest
        // stay in the pipe, where they hold back the peer's next write until they are read, so
        // nothing is thrown away for arriving faster than the host reads. While the buffer is
        // full this thread looks again every 10 ms for QpsRead to have made room, for as long
        // as the host takes: a client is dropped by a disconnect, not by a clock.
        UINT64 room = 0;
        for (;;)
        {
            EnterCriticalSection(&client->Lock);
            room = CmqGetFreeSize(client->ReadBuffer);
            LeaveCriticalSection(&client->Lock);
            if (room > 0 || client->Disconnecting)
                break;
            Sleep(10);
        }

        // No read is started once a disconnect is under way.
        if (client->Disconnecting)
        {
            LogDebug("[%lld] client is disconnecting, exiting", client->Id);
            QpsReleaseClient(server, client);
            QpsDisconnectClientInternal(server, param->ClientId, FALSE, TRUE);
            free(param);
            free(buffer);
            return 1;
        }

        if (room > server->PipeBufferSize)
            room = server->PipeBufferSize;

        // A blocked read fails when QpsDisconnectClientInternal cancels the I/O on this handle.
        if (!ReadFile(pipe, buffer, (DWORD)room, &transferred, NULL)) // this can block
        {
            // WHY THE READ ENDED, instead of one warning for every reason. This pipe protocol has
            // no goodbye message - EOF IS the disconnect (qdb_close just closes the handles, and
            // qrexec-client-vm's last act before exiting is CloseHandle(writePipe)) - so every
            // completed session ended here, the error code was DISCARDED (the win_perror below was
            // commented out) and an ordinary disconnect printed the same line as a real fault.
            // Measured on a Qubes guest: 199 of these from qrexec-agent and ~60 from the qubesdb
            // daemon in one install and three boots, all of them successful sessions. The Linux
            // side returns the same event silently (qubes-core-qubesdb db-cmds.c: "/* EOF */ if
            // (ret == 0) return 0;"), so this is a port artefact rather than the design.
            // Every case that is NOT an expected end is now LOUDER than before: it gets ERROR
            // level AND the Win32 code, which the old code-less warning never gave.
            DWORD readError = GetLastError();
            if (client->Disconnecting)
                LogDebug("[%lld] read cancelled by our own disconnect (%lu)", client->Id, readError);
            else if (readError == ERROR_BROKEN_PIPE || readError == ERROR_PIPE_NOT_CONNECTED)
                LogDebug("[%lld] peer closed the pipe (end of session)", client->Id);
            else
                win_perror2(readError, "ReadFile(client pipe)");
            // disconnect the client if the read failed because of other errors (broken pipe etc), it's harmless if we're already disconnecting
            QpsReleaseClient(server, client);
            QpsDisconnectClientInternal(server, param->ClientId, FALSE, TRUE);
            free(param);
            free(buffer);
            return 1;
        }
        // disconnect could happen after a successful read but before entering the client lock below
        if (client->Disconnecting)
        {
            LogDebug("[%lld] client is disconnecting, exiting", client->Id);
            QpsReleaseClient(server, client);
            free(param);
            free(buffer);
            return 1;
        }

        // we have some data from the pipe, add it to the read buffer
        EnterCriticalSection(&client->Lock);
        LogVerbose("[%lld] read %lu 0x%lx", client->Id, transferred, transferred);

        if (!CmqAddData(client->ReadBuffer, buffer, transferred))
        {
            // Not reached while the read above asks for no more than the room it found: only this
            // thread adds to the read buffer, so that room cannot shrink before the add.
            LeaveCriticalSection(&client->Lock);
            LogError("[%lld] read buffer full", client->Id);
            QpsReleaseClient(server, client);
            QpsDisconnectClientInternal(server, param->ClientId, FALSE, TRUE);
            free(param);
            free(buffer);
            return 1;
        }
        LeaveCriticalSection(&client->Lock);

        if (param->Server->ReadCallback)
            param->Server->ReadCallback(param->Server, client->Id, buffer, transferred, param->Server->UserContext);
    }
}

static DWORD WINAPI QpsWriterThread(
    PVOID Param
    )
{
    struct THREAD_PARAM *param = Param;
    PIPE_SERVER server = param->Server;
    PPIPE_CLIENT client = QpsGetClient(server, param->ClientId);

    // The same race, and THIS is the one measured killing the service: 0x18 is WritePipe's offset
    // in PIPE_CLIENT (ListEntry 16 + Id 8). See QpsReaderThread above for the full record.
    if (!client)
    {
        LogWarning("[%lld] not in the client list; writer thread exits", param->ClientId);
        free(param);
        return 1;
    }

    HANDLE pipe = client->WritePipe;
    PVOID data = malloc(server->InternalBufferSize);
    UINT64 size;

    if (!data)
    {
        LogError("no memory");
        QpsReleaseClient(server, client);
        QpsDisconnectClientInternal(server, param->ClientId, TRUE, FALSE);
        free(param);
        return 1;
    }

    // This thread endlessly tries to flush the client's write buffer to the client's write pipe.
    while (TRUE)
    {
        EnterCriticalSection(&client->Lock);
        // if the client is disconnecting, QpsWrite() calls will fail so no new data may be added to the write buffer
        if (client->Disconnecting)
        {
            LeaveCriticalSection(&client->Lock);
            LogDebug("[%lld] client is disconnecting, exiting", client->Id);
            QpsReleaseClient(server, client);
            free(param);
            free(data);
            return 1;
        }

        size = CmqGetUsedSize(client->WriteBuffer);
        if (size > 0)
        {
            // there's data to write
            if (!CmqGetData(client->WriteBuffer, data, &size, CMQ_NO_UNDERFLOW))
            { // shouldn't happen
                LeaveCriticalSection(&client->Lock);
                LogError("CmqGetData(client->WriteBuffer) failed");
                QpsReleaseClient(server, client);
                QpsDisconnectClientInternal(server, param->ClientId, TRUE, FALSE);
                free(param);
                free(data);
                return 1;
            }
            LeaveCriticalSection(&client->Lock);

            LogVerbose("[%lld] writing %lu 0x%lx", client->Id, size, size);
            // A blocked write fails when QpsDisconnectClientInternal cancels the I/O on this handle.
            if (!QioWriteBuffer(pipe, data, (DWORD)size)) // this can block
            {
                // win_perror("QioWriteBuffer");
                LogWarning("[%lld] write failed", client->Id);
                QpsReleaseClient(server, client);
                QpsDisconnectClientInternal(server, param->ClientId, TRUE, FALSE);
                free(param);
                free(data);
                return 1;
            }
        }
        else
            LeaveCriticalSection(&client->Lock);

        if (size == 0)
            Sleep(1);
    }
}

static DWORD QpsConnectClient(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    IN  HANDLE WritePipe,
    IN  HANDLE ReadPipe
    )
{
    // A CLIENT IS PUBLISHED BEFORE ITS THREADS CAN RUN, and that ordering is the whole point of
    // this function's shape.
    //
    // It used to insert the client into Server->Clients as its LAST statement, with both worker
    // threads running since several statements earlier. Each thread's first act is to look itself
    // up in that list (QpsGetClient by id), so a thread could run before its own client existed
    // there and get NULL - and both thread entries then dereferenced it. MEASURED 2026-10-14 on a
    // Qubes Windows guest: qrexec-agent.exe took c0000005 reading address 0x18 (WritePipe's offset
    // in PIPE_CLIENT) and the Qubes RPC agent service stopped (System/7031). Every error return in
    // the old body also abandoned the half-built client, its buffers, its critical section, its
    // thread parameters and any thread handle, and left any already-created thread looking up an id
    // that would never appear.
    //
    // So: build everything that can fail while none of it is reachable; create both threads
    // SUSPENDED, because creating a thread is not the same as letting it run; publish the client
    // under the server lock; and only then resume. One failure path, reached only while the client
    // is unpublished and both threads are suspended - which is what makes releasing everything here
    // safe without touching refcounts or the disconnect machinery.
    //
    // The server lock now covers the publish instead of the whole construction. Nothing under
    // construction is reachable until the insert, and the old shape held a global lock across two
    // mallocs, two CmqCreate calls and two CreateThread calls.
    struct THREAD_PARAM *readerParam = NULL;
    struct THREAD_PARAM *writerParam = NULL;
    PPIPE_CLIENT client;
    DWORD status;

    // The two pipes are this function's from the moment it is called. Every return that does not
    // publish the client closes them, because the accept loop does not.
    if (!Server->AcceptConnections)
    {
        CloseHandle(WritePipe);
        CloseHandle(ReadPipe);
        return ERROR_SHUTDOWN_IN_PROGRESS;
    }

    client = malloc(sizeof(PIPE_CLIENT));
    if (!client)
    {
        LogError("no memory");
        CloseHandle(WritePipe);
        CloseHandle(ReadPipe);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    ZeroMemory(client, sizeof(PIPE_CLIENT));
    client->Id = ClientId;
    client->WritePipe = WritePipe;
    client->ReadPipe = ReadPipe;
    client->Disconnecting = FALSE;
    InitializeCriticalSection(&client->Lock);

    client->ReadBuffer = CmqCreate(Server->InternalBufferSize);
    client->WriteBuffer = CmqCreate(Server->InternalBufferSize);
    readerParam = malloc(sizeof(struct THREAD_PARAM));
    writerParam = malloc(sizeof(struct THREAD_PARAM));
    if (!client->ReadBuffer || !client->WriteBuffer || !readerParam || !writerParam)
    {
        status = ERROR_NOT_ENOUGH_MEMORY;
        goto fail;
    }

    readerParam->Server = Server;
    readerParam->ClientId = ClientId;
    writerParam->Server = Server;
    writerParam->ClientId = ClientId;

    // SUSPENDED: the lookup these threads begin with must not race the insert below.
    client->ReaderThread = CreateThread(NULL, 0, QpsReaderThread, readerParam, CREATE_SUSPENDED, NULL);
    client->WriterThread = CreateThread(NULL, 0, QpsWriterThread, writerParam, CREATE_SUSPENDED, NULL);
    if (!client->ReaderThread || !client->WriterThread)
    {
        status = ERROR_NO_SYSTEM_RESOURCES;
        goto fail;
    }

    // ONE LOAD of the callback pointer; the local copy is what is tested and called from here on.
    // The test and the call run outside Server->Lock, so a second load could return a pointer
    // that another thread has cleared since the test.
    const QPS_CLIENT_CONNECTED connectCallback = Server->ConnectCallback;

    // THE HOST'S REFERENCE EXISTS BEFORE THE CLIENT CAN BE FOUND. A worker thread that runs to
    // its end as soon as it is resumed gives back only its own reference, so the client stays
    // valid for the rest of this function and until the host calls QpsDisconnectClient.
    if (connectCallback)
        client->RefCount = 1;

    // PUBLISH. After this the client is findable, so the threads may run - and from here on the
    // client belongs to the server: it is torn down by QpsDisconnectClient/QpsReleaseClient, never
    // by this function.
    EnterCriticalSection(&Server->Lock);
    InsertTailList(&Server->Clients, &client->ListEntry);
    Server->NumberClients++;
    LogInfo("[%lld] (%p) connected (%lld total)", client->Id, client, Server->NumberClients);
    LeaveCriticalSection(&Server->Lock);

    // CHECKED, because a PUBLISHED client whose pumps never run is a silent hang - worse to
    // diagnose than a crash, and the one new failure mode this ordering introduces. Near-impossible
    // (the handles are ours, created moments ago), so it is reported at ERROR and the client is
    // disconnected through the normal path rather than left half-alive.
    if (ResumeThread(client->ReaderThread) == (DWORD)-1 ||
        ResumeThread(client->WriterThread) == (DWORD)-1)
    {
        win_perror("ResumeThread");
        LogError("[%lld] worker threads could not be resumed; disconnecting", ClientId);
        QpsDisconnectClientInternal(Server, ClientId, FALSE, FALSE);
        // The host is never told about this client, so its reference is given back here.
        if (connectCallback)
            QpsReleaseClient(Server, client);
        return ERROR_NO_SYSTEM_RESOURCES;
    }

    if (connectCallback)
    {
        // The reference taken before the publish is the host's from here on. The host (the
        // application that registered the callback) calls QpsDisconnectClient when it is done
        // with the client; that gives the reference back and lets the client's data be freed.
        // The host may do so from inside the callback, so the client is not touched after it.
        connectCallback(Server, ClientId, Server->UserContext);
    }

    return ERROR_SUCCESS;

fail:
    // UNPUBLISHED AND SUSPENDED, so nothing else can be looking at any of this: the client was
    // never inserted, and neither thread has executed an instruction. Release in reverse order of
    // construction. TerminateThread is safe for exactly this case and no other - a thread that has
    // never run holds no lock and owns nothing but its parameter, which is freed here.
    if (client->WriterThread)
    {
        TerminateThread(client->WriterThread, 0);
        CloseHandle(client->WriterThread);
    }
    if (client->ReaderThread)
    {
        TerminateThread(client->ReaderThread, 0);
        CloseHandle(client->ReaderThread);
    }
    if (writerParam)
        free(writerParam);
    if (readerParam)
        free(readerParam);
    if (client->WriteBuffer)
        CmqDestroy(client->WriteBuffer);
    if (client->ReadBuffer)
        CmqDestroy(client->ReadBuffer);
    DeleteCriticalSection(&client->Lock);
    free(client);
    // THE PIPES, WHICH NOBODY ELSE WILL CLOSE: the accept loop creates them and hands them in, and
    // on failure its caller goes on to the next client without touching them. On success they
    // belong to the client and QpsDisconnectClientInternal closes them, so
    // this function owns them in both outcomes or a handle pair leaks per failure.
    if (WritePipe)
        CloseHandle(WritePipe);
    if (ReadPipe)
        CloseHandle(ReadPipe);
    LogWarning("[%lld] connect failed (0x%x); nothing was published", ClientId, status);
    return status;
}

// Public API. Decreases the client's refcount.
// DO NOT USE HERE. It will mess up the refcount. Use QpsDisconnectClientInternal directly.
void QpsDisconnectClient(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId
    )
{
    PPIPE_CLIENT client;

    LogDebug("[%lld]", ClientId);
    QpsDisconnectClientInternal(Server, ClientId, FALSE, FALSE);
    // We need to decrease the refcount without increasing it.
    client = QpsGetClientRaw(Server, ClientId, FALSE);
    // NOTHING TO RELEASE IF THE CLIENT IS ALREADY GONE: QpsDisconnectClientInternal above may have
    // taken the last reference, and QpsReleaseClient WRITES through this pointer
    // (InterlockedDecrement on RefCount, offset 0x78). Checked here because that is what every
    // other caller of a lookup in this file does.
    if (client)
        QpsReleaseClient(Server, client);
}

static void QpsDisconnectClientInternal(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    IN  BOOL WriterExiting,
    IN  BOOL ReaderExiting
    )
{
    PPIPE_CLIENT client = QpsGetClient(Server, ClientId);

    if (!client)
    {
        // INFO, NOT A WARNING: this is a redundant disconnect, and nothing is wrong. At service stop
        // QpsDestroy disconnects every client from the main thread; a client's own per-client thread
        // then gets 109 from QpsRead and asks to disconnect it again, and the lookup answers NULL.
        // Client ids come from InterlockedIncrement64 and are never reused, so NULL can only mean
        // "already gone". When the other thread wins the same race, the Disconnecting branch below
        // returns silently, so the level used to depend only on which thread won. MEASURED
        // 2026-11-11 (acceptance of build 4.3.41.1270, win10-reinstall, qubesdb-daemon, one clock):
        // main thread disconnects client 9, 15 ms later the client's thread fails QpsRead with 109
        // and asks again -> this line -> QPSDESTROYED. Until 2026-10-26 the same sequence crashed the
        // daemon (QDBSTOPUAF); this return is that fix's designed answer. Owner, 2026-11-11:
        // "demote, too".
        LogInfo("[%lld] not connected", ClientId);
        return;
    }

    // Test and set in one step: of two threads that disconnect the same client, exactly one goes
    // on to the teardown below and the other returns here.
    if (InterlockedExchange((LONG *)&client->Disconnecting, TRUE))
    {
        QpsReleaseClient(Server, client);
        return;
    }

    LogInfo("[%lld] (%p) disconnecting, WriterExiting %d, ReaderExiting %d", ClientId, client, WriterExiting, ReaderExiting);

    if (!WriterExiting)
    {
        // wait for the writer thread to exit
        if (WaitForSingleObject(client->WriterThread, Server->WriteTimeout) != WAIT_OBJECT_0)
        {
            LogWarning("[%lld] writer thread didn't terminate in time, canceling write", ClientId);
            // The write belongs to the writer thread, so it is cancelled by handle and not by
            // calling thread. Nothing to cancel is not an error: the writer is between two writes.
            if (!CancelIoEx(client->WritePipe, NULL) && GetLastError() != ERROR_NOT_FOUND) // this will abort a blocking operation
                win_perror("CancelIo(write)");
        }

        // wait for the writer thread cleanup
        if (WaitForSingleObject(client->WriterThread, 100) != WAIT_OBJECT_0)
        {
            LogWarning("[%lld] writer thread didn't terminate in time, killing it", ClientId);
            // this may leak memory or do other nasty things but should never happen
            TerminateThread(client->WriterThread, 0);
        }
    }
    LogDebug("[%lld] (%p) closing write handles", ClientId, client);
    CloseHandle(client->WriterThread);
    client->WriterThread = NULL;
    CloseHandle(client->WritePipe);
    client->WritePipe = NULL;

    if (!ReaderExiting)
    {
        // wait for the reader thread to exit
        LogVerbose("[%lld] (%p) canceling read", ClientId, client);
        // The read belongs to the reader thread, so it is cancelled by handle and not by calling
        // thread. Nothing to cancel is not an error: the reader is between two reads. It starts
        // no new one once it has seen the disconnect; one that looked just before the flag was
        // set still starts a read after this cancel, and the wait and the kill below end it.
        if (!CancelIoEx(client->ReadPipe, NULL) && GetLastError() != ERROR_NOT_FOUND) // this will abort a blocking operation
            win_perror("CancelIo(read)");

        if (WaitForSingleObject(client->ReaderThread, 100) != WAIT_OBJECT_0)
        {
            LogWarning("[%lld] reader thread didn't terminate in time, killing it", ClientId);
            // this may leak memory or do other nasty things but should never happen
            TerminateThread(client->ReaderThread, 0);
        }
    }
    LogDebug("[%lld] (%p) closing read handles", ClientId, client);
    CloseHandle(client->ReaderThread);
    client->ReaderThread = NULL;
    CloseHandle(client->ReadPipe);
    client->ReadPipe = NULL;

    // rest of the client's data will be destroyed by QpsReleaseClient when refcount drops to 0
    QpsReleaseClient(Server, client);

    // PER-CALL MECHANICS ARE DEBUG. The pipe server takes a client per qrexec call and a
    // campaign makes hundreds: measured on acceptance run 39476792836, 2026-10-20, one brief
    // cell logged 58 of this line, and the guest session read 2535 INFO against 52 WARN and 2
    // ERROR. Owner 2026-10-20: "it is NOT normal to have thousands of lines of log during the
    // brief normal run. it is ok for debug purposes but not on a product session." A client
    // disconnecting in the ordinary course is mechanics, not an event; at LOG_LEVEL_DEBUG it
    // comes back. A disconnect that is NOT ordinary is reported by its own error path.
    LogDebug("[%lld] disconnected (%lld total)", ClientId, Server->NumberClients);

    // Same single-load rule as the connect site above. THIS one is currently safe in the shipped
    // binary only by ACCIDENT: nothing sits between the test and the call, so the optimiser kept
    // one load. A correctness property that holds because the optimiser happened to do the right
    // thing is not a property - inserting any statement here would silently reintroduce `call 0`.
    const QPS_CLIENT_DISCONNECTED disconnectCallback = Server->DisconnectCallback;
    if (disconnectCallback)
        disconnectCallback(Server, ClientId, Server->UserContext);
}

// Returns only on error. At that point the server state is undefined, call QpsDestroy().
DWORD QpsMainLoop(
    PIPE_SERVER Server
    )
{
    BOOL connected;
    HANDLE writePipe, readPipe;
    DWORD status;
    WCHAR pipeName[256];

    // THE ONE PUBLIC ENTRY THAT DOES NOT GO THROUGH THE CLIENT LOOKUP, so it carries the guard
    // itself. Everything else that takes a server and a client id reaches the list through
    // QpsGetClientRaw and is covered there; this function reads Server->PipeName and the callbacks
    // directly, so a late or NULL handle would fault here and nowhere else. Named rather than left
    // out, because "every entry point is covered" is the property the fix rests on and a single
    // uncovered one makes that sentence false.
    if (!Server || Server->Destroyed)
    {
        LogWarning("called with a %s server; nothing to accept on", Server ? "destroyed" : "NULL");
        return ERROR_INVALID_HANDLE;
    }
    ULONG pid;
    LONGLONG clientId;
    DWORD cbPipeName;
    DWORD written;

    while (TRUE)
    {
        writePipe = CreateNamedPipe(Server->PipeName,
                                    PIPE_ACCESS_OUTBOUND,
                                    PIPE_TYPE_BYTE | PIPE_WAIT,
                                    PIPE_UNLIMITED_INSTANCES,
                                    Server->PipeBufferSize,
                                    Server->PipeBufferSize,
                                    0,
                                    Server->SecurityAttributes);

        // Without this instance there is nothing to accept on, and a connect on an invalid handle
        // fails every time it is tried.
        if (writePipe == INVALID_HANDLE_VALUE)
            return win_perror("CreateNamedPipe(outbound)");

        // wait for connection
        do
        {
            LogVerbose("waiting for outbound connection, pipe %s", Server->PipeName);
            // A client that has opened this instance and closed it again already has connected
            // too (ERROR_NO_DATA). It is dropped below, by the first step that fails for it, and
            // the loop goes on; waiting here for the same instance again would never end.
            connected = ConnectNamedPipe(writePipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED || GetLastError() == ERROR_NO_DATA);
            if (!connected)
                Sleep(10);
        } while (!connected);

        LogVerbose("outbound pipe connected");
        // prepare the read pipe
        if (!GetNamedPipeClientProcessId(writePipe, &pid))
        {
            // An error on one client ends that client only; the loop goes on to the next one.
            win_perror("GetNamedPipeClientProcessId");
            CloseHandle(writePipe);
            continue;
        }

        clientId = QpsAllocateClientId(Server);
        // create the second pipe with unique name
        StringCbPrintf(pipeName, sizeof(pipeName), L"%s-%lu-%lld", Server->PipeName, pid, clientId);
        readPipe = CreateNamedPipe(pipeName,
                                   PIPE_ACCESS_INBOUND,
                                   PIPE_TYPE_BYTE | PIPE_WAIT,
                                   PIPE_UNLIMITED_INSTANCES,
                                   Server->PipeBufferSize,
                                   Server->PipeBufferSize,
                                   0,
                                   Server->SecurityAttributes);

        if (readPipe == INVALID_HANDLE_VALUE)
        {
            win_perror("CreateNamedPipe(inbound)");
            CloseHandle(writePipe);
            continue;
        }

        // send the name to the client
        cbPipeName = (DWORD) (wcslen(pipeName) + 1) * sizeof(WCHAR);
        if (!WriteFile(writePipe, &cbPipeName, sizeof(cbPipeName), &written, NULL))
        {
            win_perror("writing size of inbound pipe name");
            CloseHandle(readPipe);
            CloseHandle(writePipe);
            continue;
        }

        if (!WriteFile(writePipe, pipeName, cbPipeName, &written, NULL))
        {
            win_perror("writing name of inbound pipe");
            CloseHandle(readPipe);
            CloseHandle(writePipe);
            continue;
        }

        // FIXME: this blocks forever if the client never connects here
        // readPipe needs to be open in async mode
        do
        {
            LogVerbose("waiting for inbound connection, pipe %s", pipeName);
            // A client that has written its request and closed already (ERROR_NO_DATA) is as
            // connected as one that is still there: what it wrote stays in the pipe for the
            // reader thread. Waiting here for the same instance again would never end.
            connected = ConnectNamedPipe(readPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED || GetLastError() == ERROR_NO_DATA);
            if (!connected)
                Sleep(10);
        } while (!connected);
        LogVerbose("inbound pipe connected");

        // initialize the client
        status = QpsConnectClient(Server, clientId, writePipe, readPipe);
        // A failure to set one client up has released that client's pipes and ends that client
        // only. The loop itself ends when the server is being destroyed.
        if (status == ERROR_SHUTDOWN_IN_PROGRESS)
            return status;
    }
}

DWORD QpsRead(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    OUT void *Data,
    IN  DWORD DataSize
    )
{
    UINT64 size;
    DWORD received = 0;
    BOOL disconnecting;
    PPIPE_CLIENT client = QpsGetClient(Server, ClientId);

    LogVerbose("[%lld] size %lu", ClientId, DataSize);
    if (!client)
        return ERROR_NOT_CONNECTED;

    // Take what the read buffer holds, piece by piece, until the requested amount has arrived.
    // The reader thread refills the buffer as it empties, so a request may be larger than the
    // buffer.
    while (received < DataSize)
    {
        // The flag is sampled BEFORE the buffer is looked at. A reader thread that finds the peer
        // gone has added everything it read before it sets the flag, so a flag already set here
        // means the look below sees all this client delivered. A flag that is set after the look
        // is acted on in the next pass, after another look.
        disconnecting = client->Disconnecting;

        // Never zero inside this loop, and it must not be: zero asks CmqGetData for everything.
        size = DataSize - received;
        EnterCriticalSection(&client->Lock);
        CmqGetData(client->ReadBuffer, (BYTE *)Data + received, &size, CMQ_ALLOW_UNDERFLOW);
        LeaveCriticalSection(&client->Lock);
        received += (DWORD)size;

        if (received < DataSize)
        {
            // If there's not enough data and the client is disconnecting,
            // that means we'll never have enough data: abort.
            if (disconnecting)
            {
                // HOW MUCH WAS PENDING decides what this is. Nothing pending = the consumer was
                // between messages and the peer is gone: the ordinary end of a session. Some but
                // not all of the requested bytes = a TRUNCATED message, i.e. a request lost in
                // flight - which the old single warning could not be told apart from the clean
                // case. That one is now an ERROR naming both counts, so this path gets LOUDER for
                // the case that matters. The ERROR_BROKEN_PIPE return is unchanged either way, so
                // no caller's control flow moves.
                QpsReleaseClient(Server, client);
                if (received == 0)
                    LogDebug("[%lld] peer gone, nothing pending", ClientId);
                else
                    // The two counts are what this call took and what it was asked for.
                    LogError("[%lld] peer gone mid-message: %llu of %lu bytes", ClientId, (UINT64)received, DataSize);
                return ERROR_BROKEN_PIPE;
            }

            Sleep(1); // don't congest the lock
        }
    }

    QpsReleaseClient(Server, client);
    return ERROR_SUCCESS;
}

DWORD QpsWrite(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    IN  const void *Data,
    IN  DWORD DataSize
    )
{
    PPIPE_CLIENT client = QpsGetClient(Server, ClientId);
    BOOL ret;

    LogVerbose("[%lld] size %lu", ClientId, DataSize);
    if (!client)
        return ERROR_NOT_CONNECTED;

    if (client->Disconnecting)
    {
        // pipe(s) broken, we won't be able to send anything. In a request/no-reply protocol a send
        // to a peer that has already gone is an ordinary race, not a fault of this server's. The
        // ERROR_BROKEN_PIPE return is unchanged, so a caller whose DATA MATTERED still decides and
        // can be as loud as it likes - only this library's duplicate line goes quiet.
        QpsReleaseClient(Server, client);
        LogDebug("[%lld] write to a peer that is already gone", ClientId);
        return ERROR_BROKEN_PIPE;
    }

    // add data to the write queue
    // it will be flushed to the client pipe by the background writer thread
    EnterCriticalSection(&client->Lock);
    ret = CmqAddData(client->WriteBuffer, Data, DataSize);
    LeaveCriticalSection(&client->Lock);

    if (!ret)
    {
        QpsReleaseClient(Server, client);
        LogError("[%lld] write buffer full", ClientId);
        return ERROR_BUFFER_OVERFLOW;
    }

    QpsReleaseClient(Server, client);
    return ERROR_SUCCESS;
}

DWORD QpsGetReadBufferSize(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId
    )
{
    DWORD queuedData;
    PPIPE_CLIENT client = QpsGetClient(Server, ClientId);

    LogVerbose("[%lld]", ClientId);
    if (!client)
        return 0;

    EnterCriticalSection(&client->Lock);
    queuedData = (DWORD)CmqGetUsedSize(client->ReadBuffer);
    LeaveCriticalSection(&client->Lock);
    QpsReleaseClient(Server, client);
    return queuedData;
}

DWORD QpsSetClientData(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    IN  PVOID UserData
    )
{
    PPIPE_CLIENT client = QpsGetClient(Server, ClientId);

    LogVerbose("[%lld]", ClientId);
    if (!client)
        return ERROR_NOT_CONNECTED;

    EnterCriticalSection(&client->Lock);
    client->UserData = UserData;
    LeaveCriticalSection(&client->Lock);
    QpsReleaseClient(Server, client);
    return ERROR_SUCCESS;
}

PVOID QpsGetClientData(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId
    )
{
    PPIPE_CLIENT client = QpsGetClient(Server, ClientId);
    PVOID data;

    LogVerbose("[%lld]", ClientId);
    if (!client)
        return NULL;

    EnterCriticalSection(&client->Lock);
    data = client->UserData;
    LeaveCriticalSection(&client->Lock);
    QpsReleaseClient(Server, client);
    return data;
}

DWORD QpsConnect(
    IN  PWCHAR PipeName,
    OUT HANDLE *ReadPipe,
    OUT HANDLE *WritePipe
    )
{
    DWORD status;
    WCHAR writePipeName[256];
    DWORD cbWritePipeName;
    DWORD read;

    // Try to open the read pipe; wait for it, if necessary.
    do
    {
        LogDebug("opening read pipe: %s", PipeName);
        *ReadPipe = CreateFile(PipeName,
                              GENERIC_READ, // this is an inbound pipe
                              0,
                              NULL,
                              OPEN_EXISTING,
                              0,
                              NULL);

        // Exit if an error other than ERROR_PIPE_BUSY occurs.
        status = GetLastError();
        if (*ReadPipe == INVALID_HANDLE_VALUE)
        {
            if (ERROR_PIPE_BUSY != status)
            {
                LogDebug("open read pipe failed, code: %d", (int)status);
                return status; // win_perror("open read pipe");
            }

            // Wait until the pipe is available.
            if (!WaitNamedPipe(PipeName, NMPWAIT_WAIT_FOREVER))
            {
                status = GetLastError();
                LogDebug("WaitNamedPipe(read) failed, status: %s", (int)status);
                return status; // win_perror("WaitNamedPipe(read)");
            }
        }
    } while (*ReadPipe == INVALID_HANDLE_VALUE);

    // Read the second pipe name from the server.
    if (!ReadFile(*ReadPipe, &cbWritePipeName, sizeof(cbWritePipeName), &read, NULL))
    {
        CloseHandle(*ReadPipe);
        return win_perror("reading size of write pipe name");
    }

    if (cbWritePipeName > sizeof(writePipeName) - 2 || cbWritePipeName % 2 != 0)
    {
        LogError("invalid pipe name size from server (%u)", cbWritePipeName);
        return ERROR_INTERNAL_ERROR;
    }

    if (!ReadFile(*ReadPipe, writePipeName, cbWritePipeName, &read, NULL))
    {
        CloseHandle(*ReadPipe);
        return win_perror("reading write pipe name");
    }
    writePipeName[cbWritePipeName/2] = L'0';

    // Open the write pipe. The server creates it before it sends its name, so a pipe that is not
    // found will not appear later: the server has given this client up or has gone away. The
    // open is made once and its failure is the answer.
    LogDebug("opening write pipe: %s", writePipeName);
    *WritePipe = CreateFile(writePipeName,
                            GENERIC_WRITE, // this is an outbound pipe
                            0,
                            NULL,
                            OPEN_EXISTING,
                            0,
                            NULL);

    status = GetLastError();
    if (*WritePipe == INVALID_HANDLE_VALUE)
        return win_perror2(status, "open write pipe");

    // The server gets 10 ms to see this connection before the caller's first write.
    Sleep(10);

    return ERROR_SUCCESS;
}
