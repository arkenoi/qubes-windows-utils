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

#include "vchan-common.h"
#include "log.h"

#include <strsafe.h>

static void VchanLogger(IN int logLevel, IN const char* function, IN const wchar_t* format, IN va_list args)
{
    wchar_t buf[1024];

    StringCbVPrintfW(buf, sizeof(buf), format, args);
    _LogFormat(logLevel, /*raw=*/FALSE, function, buf);
}

libvchan_t *VchanInitServer(IN int domain, IN int port, IN size_t bufferSize, IN DWORD timeout)
{
    libvchan_t *vchan;
    ULONGLONG start = GetTickCount64();
    ULONGLONG ticks = start;

    LogDebug("domain %d, port %d, buffer %lu, timeout %lu", domain, port, bufferSize, timeout);

    libvchan_register_logger(VchanLogger, LogGetLevel());
    vchan = libvchan_server_init(domain, port, bufferSize, bufferSize);

    while (vchan == NULL && GetLastError() == ERROR_NOT_SUPPORTED && (ticks - start) < timeout)
    {
        Sleep(1000);
        LogDebug("server init failed: 0x%x, retrying", GetLastError());
        ticks = GetTickCount64();
        vchan = libvchan_server_init(domain, port, bufferSize, bufferSize);
    }

    return vchan;
}

libvchan_t *VchanInitClient(IN int domain, IN int port, IN DWORD timeout)
{
    libvchan_t *vchan;
    ULONGLONG start = GetTickCount64();
    ULONGLONG ticks = start;

    LogDebug("domain %d, port %d, timeout %lu", domain, port, timeout);

    libvchan_register_logger(VchanLogger, LogGetLevel());
    vchan = libvchan_client_init(domain, port);

    while (vchan == NULL && GetLastError() == ERROR_NOT_SUPPORTED && (ticks - start) < timeout)
    {
        Sleep(1000);
        LogDebug("client init failed: 0x%x, retrying", GetLastError());
        ticks = GetTickCount64();
        vchan = libvchan_client_init(domain, port);
    }

    return vchan;
}

int VchanGetReadBufferSize(IN libvchan_t *vchan)
{
    return libvchan_data_ready(vchan);
}

int VchanGetWriteBufferSize(IN libvchan_t *vchan)
{
    return libvchan_buffer_space(vchan);
}

// Set by VchanBeginTeardown, tested by the wait in VchanSendBuffer below. One-way and process-wide:
// the setter is the thread tearing the component down and the reader is a sender parked in that wait,
// never the same thread, so the write is interlocked and the read is volatile.
static volatile LONG g_VchanTearingDown = 0;

void VchanBeginTeardown(void)
{
    InterlockedExchange(&g_VchanTearingDown, 1);
}

// Longest the wait below sleeps before it re-reads its exit conditions. It is NOT a deadline and
// nothing here gives up when it expires: the wait still ends only when room appears, when the peer
// closes, or when this component tears down. The slice exists because a peer that dies without
// firing the channel never fires it again, so the per-slice re-check is what notices that; a wake
// that fails to arrive costs one slice. Same value and same reasoning as
// agent/gui-agent/vchan.c's VCHAN_RESERVE_WAIT_SLICE_MS, which is where this idiom is proven.
#define VCHAN_SEND_WAIT_SLICE_MS 100

BOOL VchanSendBuffer(IN libvchan_t *vchan, IN const void *data, IN size_t size, IN const WCHAR *what)
{
    int writeSize;
    HANDLE vchanEvent = NULL;
    BOOL consumedWake = FALSE;

    LogVerbose("(%p, %s): %d bytes (free: %d)", vchan, what, size, VchanGetWriteBufferSize(vchan));
    //hex_dump(what, data, size);

    if (VchanGetWriteBufferSize(vchan) < size)
    {
        // wait for space
        LogWarning("(%p, %s): vchan buffer full, blocking write", vchan, what);

        // Fetched once, here rather than per iteration: it does not change for the life of the
        // vchan, and a NULL is an anomaly to report once, not every millisecond.
        vchanEvent = libvchan_fd_for_select(vchan);
        if (!vchanEvent)
            LogWarning("no vchan event to wait on, polling for room instead");
        // A `for (;;)` AND NOT A `while (room < size)`: that condition is ITSELF a ring read, so it
        // would run before the teardown test on every iteration and the test could not be described as
        // coming first. Here nothing touches the ring until the flag has been read.
        for (;;)
        {
            // WHAT THIS IS: LIVENESS. It is NOT what makes the close safe. Safety is the CALLER's lock:
            // a component whose teardown closes under the same lock its senders hold (qrexec-agent's
            // ServiceCleanup, agent/gui-agent/main.c) cannot have a close running concurrently with a
            // sender parked here, because that sender holds the lock. What it CANNOT do without this
            // flag is finish - so the teardown blocks on that lock forever, and ordering the close
            // under the lock would merely trade a use-after-unmap for a service that never stops.
            // The check below cannot serve instead: open() reads ring->cli_live / ring->srv_live and
            // nobody writes 0 on our own side of a close we are about to perform. A teardown we asked
            // for is not a fault, so INFO, not a warning.
            if (g_VchanTearingDown)
            {
                LogInfo("QGAGOINGDOWN this component is tearing down while %Iu bytes waited for room - not sent", size);
                if (consumedWake)
                    SetEvent(vchanEvent);
                return FALSE;
            }

            if (VchanGetWriteBufferSize(vchan) >= size)
                break;

            // ONLY THE PEER FREES ROOM, SO A WAIT WITH NO PEER NEVER ENDS, and this loop had no
            // escape at all. qrexec-wrapper added one for itself in VchanWaitForSendSpace, whose
            // docstring says this function "never checks that the peer is still there", but its
            // other guard is g_VchanClosing - a WRAPPER-LOCAL flag, absent from all of winutils -
            // so agent/gui-agent/vchan.c and qrexec-agent.c inherited a spin with no exit of any
            // kind, under the lock each of them holds across the send (g_DaemonCriticalSection,
            // g_VchanCs), which stops the whole component and not just the send. Same check as the
            // wrapper's, in the one place every caller shares.
            // WHAT THIS DOES NOT CATCH, stated so nobody reads more into it: open() is ring->cli_live
            // or ring->srv_live (pvdrivers libxenvchan io.c:526-529), and only an orderly
            // libxenvchan_close writes 0, so a peer that was KILLED or wedged still reads CONNECTED.
            // That is the 31/34 "peer still MARKED live" RINGPEER measured, and closing it needs the
            // evtchn cross-check that upstream leaves #if 0 (core-vchan-xen io.c:152).
            if (!libvchan_is_open(vchan))
            {
                LogWarning("the peer closed the vchan while %Iu bytes waited for room - not sent", size);
                if (consumedWake)
                    SetEvent(vchanEvent);
                return FALSE;
            }

            // WAIT ON THE CHANNEL, DO NOT SPIN. This was Sleep(1): a 1 kHz timer-resolution spin,
            // run by a thread that is HOLDING the component's lock, for as long as the peer takes to
            // drain. That is self-inflicted guest load in precisely the window the stall is recorded
            // in, and findings records self-inflicted load as a confounder in its own right.
            // libvchan already has the trigger and no wake can be lost: VchanGetWriteBufferSize
            // above is libvchan_buffer_space, which calls request_notify(VCHAN_NOTIFY_READ) BEFORE
            // it reads the space (pvdrivers libxenvchan io.c:256-257), so the arming precedes the
            // observation and the peer's next consume fires this event.
            // THE RE-SIGNAL IS NOT OPTIONAL. This is the SAME auto-reset event the callers' own main
            // loops wait on for INCOMING data - qrexec-wrapper.c:1803 and :2109, qrexec-agent.c:1369
            // all pass libvchan_fd_for_select on this vchan - so a wake consumed here is a wake
            // those loops never see, and a message would sit unread in the ring until some unrelated
            // event woke them. Handing it back on every exit costs a spurious wake, which is already
            // routine for them (the peer's read-notify produces them). agent/gui-agent/vchan.c
            // carries this same consumedWake dance for the same reason.
            // WHAT THIS DOES NOT CHANGE, said plainly: the caller's lock is still held across the
            // whole wait, so a peer that stops draining still stops the component. This removes the
            // spin, not that. Releasing the lock needs a reservation the ring protocol does not have.
            if (vchanEvent)
            {
                if (WaitForSingleObject(vchanEvent, VCHAN_SEND_WAIT_SLICE_MS) == WAIT_OBJECT_0)
                    consumedWake = TRUE;
            }
            else
            {
                // No event for this vchan at all (warned once before the loop): poll rather than
                // busy-loop with no delay. This is the pre-2026-11-09 behaviour, kept only as the
                // fallback it always should have been.
                Sleep(1);
            }
        }

        if (consumedWake)
            SetEvent(vchanEvent);
    }

    if ((writeSize = libvchan_send(vchan, data, size)) < 0)
    {
        LogError("(%p, %s): failed to send (buffer %p, size %d)", vchan, what, data, size);
        return FALSE;
    }

    if (writeSize != size)
    {
        // shouldn't happen
        LogError("(%p, %s): size mismatch or error: requested %d, sent %d", vchan, what, size, writeSize);
        return FALSE;
    }

    return TRUE;
}

BOOL VchanReceiveBuffer(IN libvchan_t *vchan, OUT void *data, IN size_t size, IN const WCHAR *what)
{
    int readSize;

    LogVerbose("(%p, %s): %d bytes (available: %d)", vchan, what, size, VchanGetReadBufferSize(vchan));
    if (VchanGetReadBufferSize(vchan) < size)
    {
        // WAITING FOR DATA IS THE ORDINARY STATE OF A BLOCKING READ, NOT AN ANOMALY. This warned
        // every time the ring held fewer bytes than the caller asked for - which is immediately
        // followed by a libvchan_recv that blocks and then succeeds, so nothing is wrong and
        // nothing is lost. Measured 2026-10-08 on win11r-logvol: 6 of these on a FULLY IDLE clean
        // cycle, and the count scales with every protocol message received, so under GUI load it is
        // unbounded. Owner the same day, for our own components: "no warnings on normal operation.
        // warning means something is not quite normal, yet workable."
        // DEBUG, not INFO, because the shipped LogLevel is 3 and this is per-read flow detail. The
        // breadcrumb value for the open wedge class is not lost: the agent's own
        // "CaptureThread: main loop slow ... (wedge at N)" WARNING is kept, and a read that fails
        // or returns short is still an ERROR two lines below.
        LogDebug("(%p, %s): no data yet, the read will block", vchan, what);
    }

    if ((readSize = libvchan_recv(vchan, data, size)) < 0)
    {
        LogError("(%p, %s): failed to read (size %d)", vchan, what, size);
        return FALSE;
    }

    if (readSize != size)
    {
        // shouldn't happen
        LogError("(%p, %s): size mismatch or error: requested %d, got %d", vchan, what, size, readSize);
        return FALSE;
    }

    //hex_dump(what, data, size);
    return TRUE;
}
