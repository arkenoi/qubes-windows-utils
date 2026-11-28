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

#pragma once
#include <windows.h>

/*
This is a generic implementation of a named pipe server.
It's multithreaded with blocking pipes (two per client).

Initial pipe created is outbound (server->client). When a client
connects, the inbound pipe is created with the same name and
"-clientpid" appended (clientpid is the decimal PID of the client).

Each connected client has a background reader thread that tries
to read data in a loop and adds it to an internal memory buffer.

When you read from a client, the function just gets the data
from the read buffer. If insufficient data is present, it waits
until more data arrives.

Writing to a client is non-blocking, a background thread is started
to complete the operation in case the client blocks. The client
is expected to read written data in a certain amount of time,
otherwise it's disconnected.

The usual mode of operation is as follows:
- Create the server object, register at least a QPS_CLIENT_CONNECTED
  callback function.
- Call QpsMainLoop() in a separate thread.
- When a client connects in the QPS_CLIENT_CONNECTED callback,
  start a new thread to handle the communication. Callbacks are
  blocking and should return ASAP.
- A single client thread usually flows according to the desired
  communication protocol state machine.
- Make sure to call QpsDisconnectClient after you're done with the client.
*/

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WINDOWSUTILS_EXPORTS
#    define WINDOWSUTILS_API __declspec(dllexport)
#else
#    define WINDOWSUTILS_API __declspec(dllimport)
#endif

struct _PIPE_SERVER;

// Control structure.
typedef struct _PIPE_SERVER *PIPE_SERVER;

/*
Callback invoked after a client has connected.
This is a good place to start a thread for the usual processing/state machine.
This is a blocking call, hence the need for a separate processing thread.
The server takes care of locking its data.
*/
typedef void(*QPS_CLIENT_CONNECTED)(struct _PIPE_SERVER *Server, LONGLONG Id, PVOID Context);

/*
Callback invoked after a client has disconnected.
All client's data is deallocated/invalid at this time.
*/
typedef void(*QPS_CLIENT_DISCONNECTED)(struct _PIPE_SERVER *Server, LONGLONG Id, PVOID Context);

/*
Callback invoked when data has been read from a client.
Probably not very useful since you can't expect the reads having predictable sizes.
Read data is enqueued in FIFO manner in an internal buffer.
Use QpsRead() for structured, buffered reads.
*/
typedef void(*QPS_DATA_RECEIVED)(struct _PIPE_SERVER *Server, LONGLONG Id, PVOID Data, DWORD DataSize, PVOID Context);

// All functions return an error code unless specified otherwise.

// Create the server.
// WHO MAY SERVE ITS PIPES (fix B, PUBLICPIPECREATEINSTANCE). Each client's own pipe is named
// "<PipeName>-<pid>-<id>-<32 random hex digits>", is created with FILE_FLAG_FIRST_PIPE_INSTANCE and has one instance at
// most; it takes SecurityAttributes. A server created WITH SecurityAttributes (the qrexec agent) gives its main pipe a
// descriptor of its own - owner SYSTEM, SYSTEM full control, Everyone FILE_GENERIC_READ. If that name already exists
// when the main loop starts, the loop serves it only if it is owned by LocalSystem or Administrators AND its DACL lets no
// other SID add an instance or change the DACL or owner; otherwise QpsMainLoopEx returns an error at once, ListeningEvent unset. One
// created with NULL (the qubesdb daemon) keeps the default descriptor on its main pipe, and no check.
WINDOWSUTILS_API
DWORD QpsCreate(
    IN  PWCHAR PipeName, // The main pipe's name (the server writes, clients read). Each client's own pipe (it writes, the server reads) is this name with "-<pid>-<id>-<32 hex digits>" appended.
    IN  DWORD PipeBufferSize, // Pipe read/write buffer size. Shouldn't be too big.
    IN  DWORD ReadBufferSize, // Read buffer (per client). The server enqueues all received data here until it's read by QpsRead().
    IN  DWORD WriteTimeout, // If a client doesn't read written data in this amount of milliseconds, it's disconnected.
    IN  QPS_CLIENT_CONNECTED ConnectCallback, // "Client connected" callback.
    IN  QPS_CLIENT_DISCONNECTED DisconnectCallback OPTIONAL, // "Client disconnected" callback.
    IN  QPS_DATA_RECEIVED ReadCallback OPTIONAL, // "Data received" callback.
    IN  PVOID Context OPTIONAL, // Opaque parameter that will be passed to callbacks.
    IN  PSECURITY_ATTRIBUTES SecurityAttributes OPTIONAL, // Must be valid for the whole lifetime of the server.
    OUT PIPE_SERVER *Server // Server object.
    );

// Destroy the server, disconnect all clients, deallocate memory.
WINDOWSUTILS_API
void QpsDestroy(
    PIPE_SERVER Server // The server to destroy.
    );

// Main loop of the server. Call to start accepting clients.
// Returns only on error. At that point the server state is undefined, call ServerDestroy.
WINDOWSUTILS_API
DWORD QpsMainLoop(
    PIPE_SERVER Server
    );

// As QpsMainLoop, and sets ListeningEvent (when not NULL) once, right after the pipe's first instance
// exists, so that a caller can start a client of its own only after that first instance exists. The
// event is not set if the loop returns before that point: wait on the loop's thread as well.
WINDOWSUTILS_API
DWORD QpsMainLoopEx(
    PIPE_SERVER Server,
    HANDLE ListeningEvent OPTIONAL
    );

// Blocking read from a client.
// Returns immediately if the internal read queue has enough data.
WINDOWSUTILS_API
DWORD QpsRead(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    OUT void *Data,
    IN  DWORD DataSize
    );

// Nonblocking write to a client.
// Uses a background thread to write.
WINDOWSUTILS_API
DWORD QpsWrite(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    IN  const void *Data,
    IN  DWORD DataSize
    );

// Get the number of bytes available in a client's read buffer.
WINDOWSUTILS_API
DWORD QpsGetReadBufferSize(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId
    );

// Cancel all IO, disconnect the client, deallocate client's data.
// Make sure to call when you're done with the client.
WINDOWSUTILS_API
void QpsDisconnectClient(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId
    );

// Assign arbitrary data to the client.
WINDOWSUTILS_API
DWORD QpsSetClientData(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    IN  PVOID UserData
    );

// Get user data assigned to the client.
WINDOWSUTILS_API
PVOID QpsGetClientData(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId
    );

// Take each client's identity (ADR-qrexec 7.2, CLIENTVMRUNSASSYSTEM fix A). Call once, after QpsCreate and before
// the main loop; a server that never calls it takes no identity, and QpsGetClientToken answers it ERROR_NOT_SUPPORTED.
// The identity is that of whoever opened the client's per-client inbound pipe - the pipe its bytes arrive on - and
// it is taken right after the first read from that pipe completes, before those bytes are handed to QpsRead: the
// pipe gives a server its client's security context only once data has been read from it (ERROR_CANNOT_IMPERSONATE).
// So the client must still hold its end at that read; qrexec-client-vm does, until the server disconnects it.
// A NULL Server is ignored.
WINDOWSUTILS_API
void QpsEnableClientTokens(
    IN  PIPE_SERVER Server
    );

// The identity taken for a client (QpsEnableClientTokens). ERROR_SUCCESS: *IsLocalSystem says whether the client is
// LocalSystem; when it is not, *Token is a new handle to a primary token of the client's own, for the caller to
// close. No token is kept for a LocalSystem client, so none is handed out for one. Any other result means the
// client has no identity the server can use - it connected below impersonation level, or the server could not
// impersonate it at its first read - and the caller refuses it; *Token is NULL and *IsLocalSystem FALSE.
// Valid once QpsRead has returned data for the client: the identity is decided before any of its bytes are queued.
WINDOWSUTILS_API
DWORD QpsGetClientToken(
    IN  PIPE_SERVER Server,
    IN  LONGLONG ClientId,
    OUT BOOL *IsLocalSystem,
    OUT HANDLE *Token
    );

// Client API: connect to a server. The per-client pipe is opened with SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION:
// impersonation level, static tracking (the opener's identity, taken at the open), not effective-only (the whole token).
// Before that (fix B): the main pipe is opened at identification level; a main pipe whose owner is neither LocalSystem
// nor Administrators, or - for \\.\pipe\qrexec_trigger only - whose DACL lets another SID add an instance or change
// the DACL or owner, is refused (ERROR_ACCESS_DENIED), and so is a per-client pipe with such an owner; a per-client name that is not "<PipeName>-..." with no further
// backslash is refused (ERROR_INVALID_DATA). On any failure nothing is left open and both handles are
// INVALID_HANDLE_VALUE, and the result is also the thread's last error.
WINDOWSUTILS_API
DWORD QpsConnect(
    IN  PWCHAR PipeName,
    OUT HANDLE *ReadPipe,
    OUT HANDLE *WritePipe
    );

#ifdef __cplusplus
}
#endif
