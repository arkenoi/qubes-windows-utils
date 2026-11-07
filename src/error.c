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

#include <strsafe.h>

#include "error.h"
#include "log.h"

// Unhandled exception filter that logs the exception.
// Should work for most exceptions except stack overflows.
static LONG WINAPI ErrUEF(EXCEPTION_POINTERS *ep)
{
    DWORD i;
    WCHAR detail[512];
    WCHAR one[96];

    // ONE WRITE, EVERY FACT. This used to log the exception on its own line and then one line per
    // exception parameter, and the parameters are where an access violation keeps the two facts
    // that identify it: ExceptionInformation[0] is read/write/execute and [1] is the address that
    // was touched. The head line records only where the FAULTING INSTRUCTION was.
    //
    // MEASURED, 2026-10-26, acceptance cell WIN10-reinstall of campaign rel-40243956400-r2: the
    // qubesdb-daemon log ends, with a trailing newline and nothing after it, on
    //   [20261026.092153.535-3488:4624-E] ErrUEF: Unhandled exception c0000005 at 00007FF8CCD3FAAD, flags: 0
    // The two "Parameter N:" lines that this filter asks for next are absent from the capture - the
    // process did not survive to write them - so the one fact needed to say WHICH pointer was bad
    // was emitted by the code and still lost. A filter that needs a second call to be useful is a
    // filter that reports nothing about the crashes that kill hardest.
    //
    // The head of the line is kept byte-identical, parameters appended, because that prefix is what
    // the acceptance sweep's signature and this project's records already quote.
    //
    // DELIBERATELY NOT DONE HERE: naming the module the faulting instruction belongs to.
    // GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) takes the loader lock, and a crash
    // that happened while holding that lock would turn this filter into a hang during process exit.
    detail[0] = 0;
    for (i = 0; i < ep->ExceptionRecord->NumberParameters && i < EXCEPTION_MAXIMUM_PARAMETERS; i++)
    {
        StringCchPrintfW(one, ARRAYSIZE(one), L" p%u=%p", i, (PVOID)ep->ExceptionRecord->ExceptionInformation[i]);
        StringCchCatW(detail, ARRAYSIZE(detail), one);
    }

    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2)
    {
        ULONG_PTR kind = ep->ExceptionRecord->ExceptionInformation[0];
        StringCchPrintfW(one, ARRAYSIZE(one), L" (%s of %p)",
            kind == 0 ? L"read" : (kind == 1 ? L"write" : (kind == 8 ? L"execute" : L"access")),
            (PVOID)ep->ExceptionRecord->ExceptionInformation[1]);
        StringCchCatW(detail, ARRAYSIZE(detail), one);
    }

    LogError("Unhandled exception %08x at %p, flags: %x%s",
        ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress, ep->ExceptionRecord->ExceptionFlags, detail);

    // TODO: stack trace

#ifdef _DEBUG
    DebugBreak();
#endif

    return EXCEPTION_EXECUTE_HANDLER; // terminate
}

DWORD ErrRegisterUEF(void)
{
    static BOOL registered = FALSE;

    if (registered)
        return ERROR_SUCCESS;

    registered = TRUE;
    SetUnhandledExceptionFilter(ErrUEF);
    LogDebug("done");
    return ERROR_SUCCESS;
}
