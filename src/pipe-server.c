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
#include <sddl.h>
#include <aclapi.h>
#include <bcrypt.h>

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
    // The client's identity (QpsEnableClientTokens). Written once, by the reader thread under Lock, before the bytes
    // of the first read are queued; read under Lock by QpsGetClientToken. ERROR_IO_PENDING until that read.
    DWORD TokenStatus;
    BOOL TokenIsLocalSystem;
    HANDLE Token;           // primary token of a client that is not LocalSystem; NULL otherwise
} PIPE_CLIENT, *PPIPE_CLIENT;

typedef struct _PIPE_SERVER
{
    WCHAR PipeName[256];
    DWORD PipeBufferSize;
    DWORD InternalBufferSize;
    DWORD WriteTimeout;
    PSECURITY_ATTRIBUTES SecurityAttributes;    // the caller's: the per-client pipes
    // The MAIN pipe's own descriptor (fix B, PUBLICPIPECREATEINSTANCE), built by QpsCreate when the caller passed
    // SecurityAttributes, and with it the first-instance flag (QpsMainLoopEx). lpSecurityDescriptor NULL: the server
    // has none of its own, and its main pipe takes the caller's SecurityAttributes (NULL) as before. Retained with
    // the server object, which QpsDestroy never frees.
    SECURITY_ATTRIBUTES MainPipeAttributes;
    LONGLONG NumberClients;
    LONGLONG NextClientId;
    LIST_ENTRY Clients;
    BOOL AcceptConnections;
    // Set by QpsDestroy, which does NOT free this object - see there. Read by QpsGetClientRaw,
    // which every function that takes a client id goes through, so a call that arrives after the
    // destroy is answered with "no such client" instead of searching a list that is gone.
    BOOL Destroyed;
    // Set by QpsEnableClientTokens before the main loop; read-only afterwards.
    BOOL CaptureClientTokens;
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
    PSECURITY_DESCRIPTOR mainPipeDescriptor = NULL;

    LogVerbose("pipe name '%s'", PipeName);
    // WHO MAY SERVE THE MAIN PIPE (fix B step 1, PUBLICPIPECREATEINSTANCE). A caller that passes a descriptor (the qrexec
    // agent: exec.c's, which gives Everyone FILE_CREATE_PIPE_INSTANCE) keeps it for the per-client pipes, and the main
    // pipe gets this one: SYSTEM full control, Everyone FILE_GENERIC_READ - no FILE_WRITE_DATA and no
    // FILE_CREATE_PIPE_INSTANCE, so no other process can add an instance and take a caller (CreateNamedPipe: "the
    // user must have FILE_CREATE_PIPE_INSTANCE access to the named pipe object"). The main pipe is PIPE_ACCESS_OUTBOUND
    // and QpsConnect opens it GENERIC_READ only, so no client loses its connect. Owner SYSTEM, which QpsConnect's
    // owner check accepts (the agent runs as LocalSystem). A caller that passes none (the qubesdb daemon) keeps the
    // default descriptor, which already gives Everyone read only, and none of this or of QpsMainLoopEx's first-instance
    // flag applies to it.
    if (SecurityAttributes &&
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;WD)", SDDL_REVISION_1,
                                                              &mainPipeDescriptor, NULL))
    {
        *Server = NULL;
        return win_perror("ConvertStringSecurityDescriptorToSecurityDescriptor(main pipe)");
    }

    *Server = malloc(sizeof(struct _PIPE_SERVER));
    if (*Server == NULL)
    {
        LocalFree(mainPipeDescriptor);
        goto cleanup;
    }

    ZeroMemory(*Server, sizeof(struct _PIPE_SERVER));

    StringCbCopyW((*Server)->PipeName, sizeof((*Server)->PipeName), PipeName);
    (*Server)->PipeBufferSize = PipeBufferSize;
    (*Server)->InternalBufferSize = InternalBufferSize;
    (*Server)->WriteTimeout = WriteTimeout;
    (*Server)->SecurityAttributes = SecurityAttributes;
    (*Server)->MainPipeAttributes.nLength = sizeof((*Server)->MainPipeAttributes);
    (*Server)->MainPipeAttributes.bInheritHandle = FALSE;
    (*Server)->MainPipeAttributes.lpSecurityDescriptor = mainPipeDescriptor;

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
            // The reference is taken under the list lock. The last release unlinks and frees the client
            // under this same lock (QpsReleaseClient), so that cannot happen between the find and the
            // count (AUDIT-qrexec #28).
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
        if (Client->Token)
            CloseHandle(Client->Token);

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

// THE CLIENT'S IDENTITY, FROM THE PIPE ITS BYTES CAME IN ON (fix A, ADR-qrexec 7.2). Called by the reader thread right
// after the first read from a client's inbound pipe completes: ImpersonateNamedPipeClient takes "the security
// context of the last message read from the pipe", and before any read it fails ERROR_CANNOT_IMPERSONATE ("Unable to
// impersonate using a named pipe until data has been read from that pipe", System Error Codes 1300-1699). With the
// static tracking QpsConnect asks for, that context is the snapshot taken when the client opened the pipe. The reader
// is the only thread doing I/O on that synchronous handle, so the request is not queued behind a blocking read.
// Nothing else runs on this thread between the impersonation and the revert: no log line, no file I/O. A client
// below impersonation level is refused (ERROR_BAD_IMPERSONATION_LEVEL), never taken for LocalSystem. A LocalSystem
// client is only a flag: no token is kept for it, so no SYSTEM token is ever held for a handle value to name.
static DWORD QpsCaptureClientToken(
    IN  HANDLE Pipe,
    OUT BOOL *IsLocalSystem,
    OUT HANDLE *Primary
    )
{
    HANDLE impersonation = NULL;
    SECURITY_IMPERSONATION_LEVEL level = SecurityAnonymous;
    union
    {
        TOKEN_USER User;
        BYTE Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    } tokenUser;
    DWORD status = ERROR_SUCCESS, size;

    *IsLocalSystem = FALSE;
    *Primary = NULL;

    if (!ImpersonateNamedPipeClient(Pipe))
        return GetLastError();
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &impersonation))
    {
        status = GetLastError();
        impersonation = NULL;
    }
    // A thread that cannot stop being its client must not run one more instruction for this server.
    if (!RevertToSelf())
        ExitProcess(GetLastError());
    if (status != ERROR_SUCCESS)
        return status;

    if (!GetTokenInformation(impersonation, TokenImpersonationLevel, &level, sizeof(level), &size))
    {
        status = GetLastError();
        goto cleanup;
    }
    if (level < SecurityImpersonation)
    {
        status = ERROR_BAD_IMPERSONATION_LEVEL;
        goto cleanup;
    }
    if (!GetTokenInformation(impersonation, TokenUser, &tokenUser, sizeof(tokenUser), &size))
    {
        status = GetLastError();
        goto cleanup;
    }
    if (IsWellKnownSid(tokenUser.User.User.Sid, WinLocalSystemSid))
    {
        *IsLocalSystem = TRUE;
        goto cleanup;
    }
    if (!DuplicateTokenEx(impersonation, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, Primary))
    {
        status = GetLastError();
        *Primary = NULL;
    }

cleanup:
    CloseHandle(impersonation);
    return status;
}

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

        // Only as many bytes as the read buffer has room for are taken from the pipe (AUDIT-qrexec
        // #20). The rest stay in the pipe, where they hold back the peer's next write until they
        // are read, so nothing is thrown away for arriving faster than the host reads. While the
        // buffer is full this thread looks again every 10 ms for QpsRead to have made room, for as
        // long as the host takes: a client is dropped by a disconnect, not by a clock.
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

        // The first read decides who the client is (QpsCaptureClientToken), and that is recorded BEFORE its bytes are
        // queued below, so a host whose QpsRead returned data never finds the identity undecided. Only this thread
        // writes these fields. A failed capture leaves the client with no identity; the host refuses it.
        if (server->CaptureClientTokens && client->TokenStatus == ERROR_IO_PENDING)
        {
            BOOL isLocalSystem = FALSE;
            HANDLE token = NULL;
            DWORD tokenStatus = QpsCaptureClientToken(pipe, &isLocalSystem, &token);

            EnterCriticalSection(&client->Lock);
            client->TokenIsLocalSystem = isLocalSystem;
            client->Token = token;
            client->TokenStatus = tokenStatus;
            LeaveCriticalSection(&client->Lock);
            if (tokenStatus != ERROR_SUCCESS)
                LogDebug("[%lld] no identity from the first read (%lu)", client->Id, tokenStatus);
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

    // Both early returns own the pipes too (see the fail path): the handshake that called this goes on without them.
    if (!Server->AcceptConnections)
    {
        CloseHandle(WritePipe);
        CloseHandle(ReadPipe);
        return ERROR_SHUTDOWN_IN_PROGRESS;
    }

    client = malloc(sizeof(PIPE_CLIENT));
    if (!client)
    {
        CloseHandle(WritePipe);
        CloseHandle(ReadPipe);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    ZeroMemory(client, sizeof(PIPE_CLIENT));
    client->Id = ClientId;
    client->WritePipe = WritePipe;
    client->ReadPipe = ReadPipe;
    client->Disconnecting = FALSE;
    // Decided at the first read when the server takes identities; never decided, and so refused, when it does not.
    client->TokenStatus = Server->CaptureClientTokens ? ERROR_IO_PENDING : ERROR_NOT_SUPPORTED;
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

    // SINGLE LOAD, THEN USE THE LOCAL COPY - the field must not be re-read between the guard and the
    // call, which run OUTSIDE Server->Lock. MEASURED in the shipped windows-utils.dll of package
    // 4.3.39+agent.1f7216b11d1e, at 0x180005c30, when an InterlockedIncrement sat between the test
    // and the call:
    //     cmp  QWORD PTR [rsi+0x270],rbx   ; rbx is 0 (xor ebx,ebx at 0x180005b45) - the NULL test
    //     je   skip
    //     lock inc DWORD PTR [rdi+0x78]    ; the InterlockedIncrement
    //     mov  rax,QWORD PTR [rsi+0x270]   ; RELOAD of the same field
    //     call rax                         ; called without re-testing
    // A field cleared between the test and the reload turns that into `call 0` - exactly c0000005
    // "execute of 0000000000000000", p0=8 p1=0. Today only QpsCreate writes the field; the single
    // load keeps the test and the call on one value whatever is added later.
    const QPS_CLIENT_CONNECTED connectCallback = Server->ConnectCallback;

    // THE HOST'S REFERENCE EXISTS BEFORE THE CLIENT CAN BE FOUND (AUDIT-qrexec #9). Taken after the
    // resume, as it was, a reader whose first read failed could give back the last reference and
    // free the client while this thread still used it. Now a worker thread that runs to its end as
    // soon as it is resumed gives back only its own reference, so the client stays valid for the
    // rest of this function and until the host calls QpsDisconnectClient.
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
        // The host is never told about this client, so its reference is given back here. It kept
        // the client valid through the disconnect above, whose own lookup gives back its own.
        if (connectCallback)
            QpsReleaseClient(Server, client);
        return ERROR_NO_SYSTEM_RESOURCES;
    }

    if (connectCallback)
    {
        // The reference taken before the publish is the host's from here on. The host (the
        // application that registered the callback) calls QpsDisconnectClient when it is done with
        // the client; that gives the reference back and lets the client's data be freed. The host
        // may do so from inside the callback, so the client is not touched after it - nor for the
        // call: the id is this function's own argument.
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
    // THE PIPES, WHICH NOBODY ELSE WILL CLOSE: the client's handshake (QpsHandshakeThread) creates
    // them and hands them in, and on failure only logs. On success they belong to the client and QpsDisconnectClientInternal closes them, so
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

    // Test and set in one step (AUDIT-qrexec #27): of two threads that disconnect the same client -
    // the reader on its end-of-file and the host, say - exactly one goes on to the teardown below
    // and the other returns here. Tested and then set, both could pass the test and both run it:
    // four handles closed twice and the disconnect callback delivered twice.
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
            // The write belongs to the writer thread, so it is cancelled by handle and not by calling
            // thread: CancelIo cancels only the caller's own I/O, which here is none (AUDIT-qrexec #11).
            // Nothing to cancel is not an error: the writer is between two writes.
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
        // thread (AUDIT-qrexec #11). Nothing to cancel is not an error: the reader is between two
        // reads. A reader that starts a read after this cancel is still ended by the wait and the
        // kill below, which stay.
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

// ONE CLIENT'S HANDSHAKE, OFF THE ACCEPT THREAD (GWeck post 241 item D, 2026-11-25). The accept loop used to run it
// inline: create the client's unique inbound pipe, send its name, then wait in a blocking ConnectNamedPipe for the
// client to open it - upstream's own FIXME, "this blocks forever if the client never connects here". A client that
// connected to the public pipe and then never opened its inbound one (killed, crashed, stopped) parked the accept loop
// for ever: the daemon stayed alive and every later client waited in WaitNamedPipe(NMPWAIT_WAIT_FOREVER) - qubesdb
// unanswered for the whole boot, which is the shape of an update stuck at "last phase: init" behind
// Get-QubesVmClass. And any failed step of that inline handshake RETURNED from QpsMainLoop, ending the server
// (qubesdb-daemon exits when its pipe thread does) because of one client.
// Now each handshake runs here. The client's process exit releases it, with no clock: a one-shot thread-pool wait
// on the process opens the inbound pipe itself, which completes the ConnectNamedPipe below whether it is already
// waiting or not yet called (then it reports ERROR_PIPE_CONNECTED or ERROR_NO_DATA). The client counts as gone only
// when THAT open succeeded: a client that opened its inbound pipe itself holds the one instance, the release's open
// then fails (ERROR_PIPE_BUSY), and the client is served - what it wrote before it exited is still read, as before.
// A client that left during the handshake is one warning line; any other failed step is one error line.
typedef struct _QPS_HANDSHAKE
{
    PIPE_SERVER Server;
    HANDLE WritePipe;
    LONGLONG ClientId;
    volatile LONG ClientGone;
    WCHAR PipeName[256];
} QPS_HANDSHAKE;

static VOID CALLBACK QpsHandshakeClientExited(PVOID context, BOOLEAN timedOut)
{
    QPS_HANDSHAKE* hs = (QPS_HANDSHAKE*)context;
    HANDLE pipe;
    UNREFERENCED_PARAMETER(timedOut);
    // At anonymous level (fix B, the review of wf_212a17bd-b58): this is a SYSTEM open, and nothing on the other end
    // is to act as SYSTEM through it. The pipe is this server's own single instance (QpsHandshakeThread).
    pipe = CreateFile(hs->PipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, NULL);
    if (pipe != INVALID_HANDLE_VALUE)
    {
        InterlockedExchange(&hs->ClientGone, 1);
        CloseHandle(pipe);
    }
}

static DWORD WINAPI QpsHandshakeThread(PVOID param)
{
    QPS_HANDSHAKE* hs = (QPS_HANDSHAKE*)param;
    HANDLE readPipe = INVALID_HANDLE_VALUE, process = NULL, wait = NULL;
    DWORD status = ERROR_SUCCESS, cbPipeName, written;
    const WCHAR* step = L"";
    ULONG pid = 0;
    ULONG nonce[4];
    BOOL connected, left = FALSE;

    if (!GetNamedPipeClientProcessId(hs->WritePipe, &pid))
    {
        status = GetLastError();
        step = L"GetNamedPipeClientProcessId";
        goto fail;
    }
    hs->ClientId = QpsAllocateClientId(hs->Server);
    // THIS CLIENT'S PIPE IS THIS SERVER'S ALONE (fix B steps 2 and 3, PUBLICPIPECREATEINSTANCE). Its name ends in 128
    // random bits, so no process can work it out from the pid and the client counter and create it first; it is
    // created with FILE_FLAG_FIRST_PIPE_INSTANCE, so a name that does exist already fails here ("creation of the next
    // instance fails with ERROR_ACCESS_DENIED") and only this client is dropped, with one error line; and with one
    // instance at most, so nobody - SYSTEM included - adds a second one beside it and reads or rewrites the request.
    // The two land together: the flag alone on the old predictable name would refuse a client whose pid and number
    // repeat after a server restart while a stale handle keeps that name. The caller's descriptor (its Everyone ACE)
    // is unchanged, so every client that opens with GENERIC_WRITE still connects.
    status = (DWORD)BCryptGenRandom(NULL, (PUCHAR)nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS((NTSTATUS)status))
    {
        step = L"BCryptGenRandom(pipe name)";
        goto fail;
    }
    StringCbPrintf(hs->PipeName, sizeof(hs->PipeName), L"%s-%lu-%lld-%08lx%08lx%08lx%08lx", hs->Server->PipeName, pid,
                   hs->ClientId, nonce[0], nonce[1], nonce[2], nonce[3]);
    readPipe = CreateNamedPipe(hs->PipeName,
                               PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                               PIPE_TYPE_BYTE | PIPE_WAIT,
                               1,
                               hs->Server->PipeBufferSize,
                               hs->Server->PipeBufferSize,
                               0,
                               hs->Server->SecurityAttributes);
    if (readPipe == INVALID_HANDLE_VALUE)
    {
        status = GetLastError();
        step = L"CreateNamedPipe(inbound)";
        goto fail;
    }
    // Before the name is sent: from here the client's exit always releases the wait below.
    process = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!process)
    {
        status = GetLastError();
        step = L"OpenProcess(pipe client)";
        // ERROR_INVALID_PARAMETER: no process with that id - the client has already exited.
        left = status == ERROR_INVALID_PARAMETER;
        goto fail_logged;
    }
    if (!RegisterWaitForSingleObject(&wait, process, QpsHandshakeClientExited, hs, INFINITE, WT_EXECUTEONLYONCE))
    {
        wait = NULL;
        status = GetLastError();
        step = L"RegisterWaitForSingleObject(pipe client)";
        goto fail;
    }

    cbPipeName = (DWORD)(wcslen(hs->PipeName) + 1) * sizeof(WCHAR);
    if (!WriteFile(hs->WritePipe, &cbPipeName, sizeof(cbPipeName), &written, NULL) ||
        !WriteFile(hs->WritePipe, hs->PipeName, cbPipeName, &written, NULL))
    {
        status = GetLastError();
        step = L"writing the inbound pipe name";
        goto fail;
    }

    LogVerbose("[%lld] waiting for inbound connection, pipe %s", hs->ClientId, hs->PipeName);
    connected = ConnectNamedPipe(readPipe, NULL);
    status = connected ? ERROR_SUCCESS : GetLastError();
    // ERROR_NO_DATA: something opened it and closed it again before this call - the exit release, or a client that
    // wrote and exited at once. Either way something came; ClientGone says which.
    if (!connected && status != ERROR_PIPE_CONNECTED && status != ERROR_NO_DATA)
    {
        step = L"ConnectNamedPipe(inbound)";
        goto fail;
    }
    UnregisterWaitEx(wait, INVALID_HANDLE_VALUE);   // a running release finishes first; none starts after this
    wait = NULL;
    if (InterlockedCompareExchange(&hs->ClientGone, 0, 0))
    {
        status = ERROR_BROKEN_PIPE;
        step = L"exited before it opened its inbound pipe";
        goto fail;
    }
    CloseHandle(process);
    LogVerbose("[%lld] inbound pipe connected", hs->ClientId);
    // Owns both pipes from here, in success and in failure (its own fail path closes them).
    status = QpsConnectClient(hs->Server, hs->ClientId, hs->WritePipe, readPipe);
    if (status != ERROR_SUCCESS && status != ERROR_SHUTDOWN_IN_PROGRESS)
        LogError("[%lld] client pid %lu could not be connected (0x%x); dropped, the server goes on",
                 hs->ClientId, pid, status);
    free(hs);
    return status;

fail:
    // The pipe errors a client's leaving produces on the steps above.
    left = status == ERROR_BROKEN_PIPE || status == ERROR_NO_DATA || status == ERROR_PIPE_NOT_CONNECTED;
fail_logged:
    if (wait)
        UnregisterWaitEx(wait, INVALID_HANDLE_VALUE);
    if (process)
        CloseHandle(process);
    if (readPipe != INVALID_HANDLE_VALUE)
        CloseHandle(readPipe);
    CloseHandle(hs->WritePipe);
    // One line per dropped client: its leaving is the client's own business (a warning); anything else is ours.
    if (left)
        LogWarning("[%lld] client pid %lu left during the handshake (%s: %lu); dropped, the server goes on",
                   hs->ClientId, pid, step, status);
    else
        LogError("[%lld] handshake with client pid %lu failed (%s: %lu); dropped, the server goes on",
                 hs->ClientId, pid, step, status);
    free(hs);
    return status;
}

// The first client in a boot that a pipe server drops for want of memory or a thread is also written to the
// Application log (ADR-qrexec 3, point 2), which the death reporter sends to dom0 as an ACTION notice: the qube is
// out of memory and refused a call made inside it. Every later one in that boot is its error line alone. Both
// servers of this loop write it: the qrexec agent's trigger pipe and the qubesdb daemon's pipe.
static void QpsReportDropped(PIPE_SERVER Server, const WCHAR *why)
{
    WCHAR detail[320];

    StringCchPrintfW(detail, RTL_NUMBER_OF(detail), L"pipe %s: %s", Server->PipeName, why);
    LogAppEventFirstInBoot(LOG_APPEVENT_PIPE_CLIENT_DROPPED,
        L"A call made inside the qube was refused: the qube is out of memory. Its pipe server had no memory or no "
        L"thread for the caller and dropped it; the server goes on.", detail);
}

// Hands a connected instance to its own handshake (QpsHandshakeThread), which owns it from then on, so one client
// never holds the accept loop. A client whose handshake cannot be started - no memory for its record, or no thread
// for it - is dropped alone, with one error line (and, the first in a boot, QpsReportDropped's record), and the loop
// goes on (ADR-qrexec section 3, decision 2): its instance is closed here, and no other instance is touched.
static void QpsStartHandshake(PIPE_SERVER Server, HANDLE ConnectedPipe)
{
    QPS_HANDSHAKE* hs = calloc(1, sizeof(*hs));
    HANDLE thread;
    DWORD status;

    if (!hs)
    {
        CloseHandle(ConnectedPipe);
        LogError("no memory for a client's handshake; dropped, the server goes on");
        QpsReportDropped(Server, L"no memory for the client's handshake");
        return;
    }
    hs->Server = Server;
    hs->WritePipe = ConnectedPipe;
    thread = CreateThread(NULL, 0, QpsHandshakeThread, hs, 0, NULL);
    if (!thread)
    {
        status = GetLastError();
        CloseHandle(ConnectedPipe);
        free(hs);
        LogError("no thread for a client's handshake (CreateThread: %lu); dropped, the server goes on", status);
        QpsReportDropped(Server, L"no thread for the client's handshake");
        return;
    }
    CloseHandle(thread);
}

// Returns only on error. At that point the server state is undefined, call QpsDestroy().
DWORD QpsMainLoop(
    PIPE_SERVER Server
    )
{
    return QpsMainLoopEx(Server, NULL);
}

// As QpsMainLoop. ListeningEvent, when given, is set once, right after the first instance of the pipe
// has been created. A caller that starts a client of its own after starting this loop waits on it, so
// that client's open cannot arrive before the pipe's first instance exists. From then on, while the
// loop runs, the name always has an instance: the loop creates the next one before it hands a
// connected one to its handshake (PIPEZEROINSTANCE). (AUDIT-qrexec #16/#6: the qrexec agent opens its
// trigger pipe after the hello, then starts advertise-tools, whose qrexec-client-vm opens that pipe.)
// The loop returns only when it cannot create an instance; a client whose handshake cannot be started
// is dropped alone (QpsStartHandshake). If the loop returns before the first instance exists, the
// event is not set; the caller's wait also watches the thread running the loop.
DWORD QpsMainLoopEx(
    PIPE_SERVER Server,
    HANDLE ListeningEvent OPTIONAL
    )
{
    BOOL connected;
    HANDLE writePipe;
    DWORD status;

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
    // The instance a client connected to on the previous pass, not yet handed to its handshake.
    HANDLE connectedPipe = INVALID_HANDLE_VALUE;

    // ONCE THE FIRST INSTANCE EXISTS, THE NAME ALWAYS HAS ONE (PIPEZEROINSTANCE). Each pass creates the next
    // instance FIRST and only then hands the client connected on the previous pass to its handshake, which
    // may close that client's instance at once (a client that left fails there, QpsHandshakeThread). Created
    // after the hand-off, as it was since fbe86fd, the name could have no instance for that moment: a client's
    // open then failed at once with "not found" - QpsConnect waits only on ERROR_PIPE_BUSY - and the name was
    // free for another process to take. An instance that is connected and not yet handed on answers
    // ERROR_PIPE_BUSY, so a client waits there, as before.
    //
    // A SERVER WITH A MAIN-PIPE DESCRIPTOR OF ITS OWN (QpsCreate, fix B steps 1 and 5: the qrexec agent) creates its
    // first instance with FILE_FLAG_FIRST_PIPE_INSTANCE. A name that already exists when this loop starts - created by
    // another process before the server, to take its callers - then fails that create with ERROR_ACCESS_DENIED and the
    // loop returns, where it could add an instance beside the other one's and share the callers with it. An instance
    // from an earlier run of this server lives on while a client still holds it ("An instance of a named pipe is always
    // deleted when the last handle to the instance of the named pipe is closed", CreateNamedPipe); whether such an
    // instance also fails this create is not documented and not measured - if it does, a restarted server fails the
    // same way until that client has closed (qrexec-client-vm closes when its read of the main pipe breaks). Later
    // passes create without the flag, which would refuse them. A server without its own descriptor (the
    // qubesdb daemon) creates as before: its clients hold their pipes for a connection's life, and its restart is not
    // to depend on all of them having gone (the review of wf_212a17bd-b58).
    PSECURITY_ATTRIBUTES mainPipeAttributes =
        Server->MainPipeAttributes.lpSecurityDescriptor ? &Server->MainPipeAttributes : Server->SecurityAttributes;
    DWORD firstInstance = Server->MainPipeAttributes.lpSecurityDescriptor ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0;
    while (TRUE)
    {
        writePipe = CreateNamedPipe(Server->PipeName,
                                    PIPE_ACCESS_OUTBOUND | firstInstance,
                                    PIPE_TYPE_BYTE | PIPE_WAIT,
                                    PIPE_UNLIMITED_INSTANCES,
                                    Server->PipeBufferSize,
                                    Server->PipeBufferSize,
                                    0,
                                    mainPipeAttributes);
        // The one pipe this loop cannot go on without (ADR-qrexec section 3, decision 2). A client connected
        // on the previous pass is still handed to its handshake first, which does not need this loop - as at
        // fbe86fd, where it had been handed on before this create.
        if (writePipe == INVALID_HANDLE_VALUE)
        {
            // One line either way; the first names its flag, so error 5 there reads as a name that existed already.
            status = firstInstance ? win_perror("CreateNamedPipe(outbound, first instance)")
                                   : win_perror("CreateNamedPipe(outbound)");
            if (connectedPipe != INVALID_HANDLE_VALUE)
                QpsStartHandshake(Server, connectedPipe);
            return status;
        }
        firstInstance = 0;

        // The pipe's first instance exists here, so a client's open finds it even before the connect
        // below. Told once.
        if (ListeningEvent)
        {
            SetEvent(ListeningEvent);
            ListeningEvent = NULL;
        }

        if (connectedPipe != INVALID_HANDLE_VALUE)
        {
            // The rest of this client's handshake is its own thread's. If it cannot be started, that client
            // alone is dropped and the loop goes on with the instance just created as its listener.
            QpsStartHandshake(Server, connectedPipe);
            connectedPipe = INVALID_HANDLE_VALUE;
        }

        // wait for connection
        do
        {
            LogVerbose("waiting for outbound connection, pipe %s", Server->PipeName);
            connected = ConnectNamedPipe(writePipe, NULL);
            // ERROR_NO_DATA: a client opened this instance and closed it again before the call. It counts as connected
            // (ADR-qrexec section 3, decision 3) - its handshake then fails alone, one error line - where retrying the
            // call unchanged answered ERROR_NO_DATA for good and this loop spun, accepting no one.
            if (!connected && (GetLastError() == ERROR_PIPE_CONNECTED || GetLastError() == ERROR_NO_DATA))
                connected = TRUE;
            if (!connected)
                Sleep(10);
        } while (!connected);

        LogVerbose("outbound pipe connected");
        // Handed on at the top of the next pass, after the instance that replaces it as the listener exists.
        connectedPipe = writePipe;
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

    // Take what the read buffer holds, piece by piece, until the requested amount has arrived
    // (AUDIT-qrexec #2). What is taken makes room for the reader thread to add more, so a request
    // may be larger than the buffer: the qrexec agent's buffer is 4096 bytes and it accepts a
    // command line of up to 65536.
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

void QpsEnableClientTokens(
    IN  PIPE_SERVER Server
    )
{
    if (Server)
        Server->CaptureClientTokens = TRUE;
}

DWORD QpsGetClientToken(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    OUT BOOL *IsLocalSystem,
    OUT HANDLE *Token
    )
{
    PPIPE_CLIENT client;
    DWORD status;

    *IsLocalSystem = FALSE;
    *Token = NULL;
    if (!Server->CaptureClientTokens)
        return ERROR_NOT_SUPPORTED;
    client = QpsGetClient(Server, ClientId);
    if (!client)
        return ERROR_NOT_CONNECTED;

    EnterCriticalSection(&client->Lock);
    status = client->TokenStatus;
    if (status == ERROR_SUCCESS)
    {
        // A new handle, so the client's own is still closed with the client and the caller's lives as long as it needs.
        if (client->Token &&
            !DuplicateHandle(GetCurrentProcess(), client->Token, GetCurrentProcess(), Token, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            status = GetLastError();
            *Token = NULL;
        }
        else
            *IsLocalSystem = client->TokenIsLocalSystem;
    }
    LeaveCriticalSection(&client->Lock);
    QpsReleaseClient(Server, client);
    return status;
}

// THE SERVER ON THE OTHER END OF A CLIENT'S MAIN-PIPE HANDLE IS LOCALSYSTEM OR AN ADMINISTRATOR (fix B step 4,
// PUBLICPIPECREATEINSTANCE). Every server of this file runs as LocalSystem: the qrexec agent creates its main pipe owned
// by SYSTEM (QpsCreate), the qubesdb daemon with the default descriptor, whose owner is its token's default owner.
// A process that is neither, and holds no SeRestorePrivilege, cannot give an object either owner, so a name it took
// first is refused here, before this client reads the name it sends or hands it anything. An administrator's process
// passes only when the pipe it created is owned by Administrators, which its token's default owner decides; that was
// not measured, for an elevated token or a filtered one. GENERIC_READ
// carries READ_CONTROL, which reading the owner needs (GetSecurityInfo). One error line on a refusal, with the owner.
static DWORD QpsServerIsTrusted(
    IN  HANDLE Pipe,
    IN  PWCHAR PipeName
    )
{
    PSID owner = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    WCHAR *ownerText = NULL;
    DWORD status;

    status = GetSecurityInfo(Pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL, &descriptor);
    if (status != ERROR_SUCCESS)
        return win_perror2(status, "reading the owner of the server's pipe");
    if (owner && (IsWellKnownSid(owner, WinLocalSystemSid) || IsWellKnownSid(owner, WinBuiltinAdministratorsSid)))
        status = ERROR_SUCCESS;
    else
    {
        if (owner && !ConvertSidToStringSidW(owner, &ownerText))
            ownerText = NULL;
        LogError("pipe %s is owned by %s, neither LocalSystem nor Administrators: not connected", PipeName,
                 ownerText ? ownerText : L"(no owner)");
        status = ERROR_ACCESS_DENIED;
    }
    LocalFree(ownerText);
    LocalFree(descriptor);
    return status;
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
    size_t cchPipeName;

    // Try to open the read pipe; wait for it, if necessary.
    // AT IDENTIFICATION LEVEL (fix B step 4): this pipe's server only reads which process opened it
    // (GetNamedPipeClientProcessId) and never acts as its client. A process that took this name first learns who
    // called, and gets no token it could act with. CreateFile: SECURITY_IDENTIFICATION "Impersonate a client at the
    // identification level". The client's identity is taken from the per-client pipe below, not from this one.
    do
    {
        LogDebug("opening read pipe: %s", PipeName);
        *ReadPipe = CreateFile(PipeName,
                              GENERIC_READ, // this is an inbound pipe
                              0,
                              NULL,
                              OPEN_EXISTING,
                              SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
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

    // A FAILED CONNECT LEAVES NOTHING OPEN AND BOTH HANDLES INVALID_HANDLE_VALUE (fix B step 4, below at `fail`). The
    // qubesdb client's qdb_open closes read_pipe on a failed connect when it is not INVALID_HANDLE_VALUE
    // (qubes-core-qubesdb client/qdb-client.c, qdb_open's error label), so a handle closed here and left set would be
    // closed twice there, and its value may by then name another handle of that process. The two read failures below
    // closed it and left it set; the invalid-size return left it open.

    // Nothing is read from a server that is not LocalSystem's or an administrator's, and nothing is sent to it.
    status = QpsServerIsTrusted(*ReadPipe, PipeName);
    if (status != ERROR_SUCCESS)
        goto fail;

    // Read the second pipe name from the server.
    if (!ReadFile(*ReadPipe, &cbWritePipeName, sizeof(cbWritePipeName), &read, NULL))
    {
        status = win_perror("reading size of write pipe name");
        goto fail;
    }

    if (cbWritePipeName > sizeof(writePipeName) - 2 || cbWritePipeName % 2 != 0)
    {
        LogError("invalid pipe name size from server (%u)", cbWritePipeName);
        status = ERROR_INTERNAL_ERROR;
        goto fail;
    }

    if (!ReadFile(*ReadPipe, writePipeName, cbWritePipeName, &read, NULL))
    {
        status = win_perror("reading write pipe name");
        goto fail;
    }
    writePipeName[cbWritePipeName/2] = L'\0';

    // ONLY A PIPE OF THIS SERVER'S IS OPENED (fix B step 4): the name must be this one's own followed by '-' and contain
    // no further backslash, as every per-client name the server makes does (QpsHandshakeThread). Any other path -
    // another pipe, or a file - is not opened with this client's GENERIC_WRITE and token. Pipe names are not case
    // sensitive (CreateNamedPipe), so neither is the comparison.
    cchPipeName = wcslen(PipeName);
    if (_wcsnicmp(writePipeName, PipeName, cchPipeName) != 0 || writePipeName[cchPipeName] != L'-' ||
        wcschr(writePipeName + cchPipeName, L'\\'))
    {
        LogError("the server of %s named a pipe that is not one of its own: not opened", PipeName);
        status = ERROR_INVALID_DATA;
        goto fail;
    }

    // Open the write pipe once (AUDIT-qrexec #22). The server creates it before it sends its name,
    // so a pipe that is not found will not appear later: the server has given this client up or
    // has gone away. The open is made once and its failure is the answer.
    // WHAT THIS CLIENT HANDS THE SERVER (fix A, ADR-qrexec 7.2). A server that takes its clients' identities
    // (QpsEnableClientTokens) runs the client's program on the token it gets from this pipe, so the quality of
    // service is stated, not left to whatever the system uses when SECURITY_SQOS_PRESENT is absent (CreateFile's
    // page does not say). CreateFile: SECURITY_IMPERSONATION "Impersonate a client at the impersonation level";
    // SECURITY_CONTEXT_TRACKING omitted, so "the security tracking mode is static" - "a snapshot of the client's
    // security context" (SECURITY_QUALITY_OF_SERVICE), taken at this open, so the identity is the opener's and not
    // whichever thread wrote last; SECURITY_EFFECTIVE_ONLY omitted, so "all aspects of the client's security context
    // are available", and the program gets the caller's whole token, its disabled privileges and groups included.
    LogDebug("opening write pipe: %s", writePipeName);
    *WritePipe = CreateFile(writePipeName,
                            GENERIC_WRITE, // this is an outbound pipe
                            0,
                            NULL,
                            OPEN_EXISTING,
                            SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                            NULL);

    status = GetLastError();
    if (*WritePipe == INVALID_HANDLE_VALUE)
    {
        status = win_perror2(status, "open write pipe");
        goto fail;
    }

    // The server gets 10 ms to see this connection before the caller's first write.
    Sleep(10);

    return ERROR_SUCCESS;

fail:
    CloseHandle(*ReadPipe);
    *ReadPipe = INVALID_HANDLE_VALUE;
    *WritePipe = INVALID_HANDLE_VALUE;      // never opened here: every path to this label is before the open or its failure
    SetLastError(status);   // qrexec-client-vm reports a failed connect with win_perror, which reads it
    return status;
}
