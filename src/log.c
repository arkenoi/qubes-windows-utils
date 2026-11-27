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
#include <PathCch.h>
#include <stdlib.h>
#include <strsafe.h>

#include "utf8-conv.h"
#include "log.h"
#include "config.h"
#include "error.h"
#include "exec.h"
#include "qubes-io.h"

static BOOL g_LoggerInitialized = FALSE;
static BOOL g_SafeFlush = FALSE;
static HANDLE g_LogfileHandle = INVALID_HANDLE_VALUE;
static WCHAR g_LogName[CFG_MODULE_MAX] = { 0 };
static int g_LogLevel = -1; // uninitialized
static CRITICAL_SECTION g_Lock = { 0 };

#define BUFFER_SIZE (LOG_MAX_MESSAGE_LENGTH * sizeof(WCHAR))

#if (UNLEN > LOG_MAX_MESSAGE_LENGTH)
#error "UNLEN > LOG_MAX_MESSAGE_LENGTH"
#endif

static WCHAR g_Buffer[BUFFER_SIZE];
static char g_BufferUtf8[CONVERT_MAX_BUFFER_LENGTH];
static char g_PrefixBufferUtf8[CONVERT_MAX_BUFFER_LENGTH];
// The log's own path, kept so LogFlush can reopen it: an append-only handle cannot be flushed.
static WCHAR *g_LogFilePath = NULL;
// A raw ROW is many LogDebugRaw calls and must still reach the file in ONE write, or another
// process sharing the file lands a line inside the row. Accumulated here and flushed on the
// fragment that ends the line (and by LogUnlock, so an unterminated row cannot sit here).
static char g_RawBufUtf8[CONVERT_MAX_BUFFER_LENGTH + 1024];
static size_t g_RawLen = 0;
// Set when the shared open failed and this process took a per-process name. Reported as a LOG line
// once the logger is up: stderr is not somewhere a service's children can be read from.
static BOOL g_LogDegraded = FALSE;
static DWORD g_LogDegradedError = 0;
// One line, one WriteFile: prefix, message and newline are composed here before the single write.
static char g_LineBufUtf8[CONVERT_MAX_BUFFER_LENGTH + 1024];

static WCHAR g_LogLevelChar[] = {
    L'?',
    L'E',
    L'W',
    L'I',
    L'D',
    L'V'
};

void LogLock()
{
    EnterCriticalSection(&g_Lock);
}

// Flush a raw row that has not been ended by a newline fragment. Called with the lock held.
static void _RawFlushUnlocked(void)
{
    DWORD written = 0;

    if (g_RawLen == 0 || g_LogfileHandle == INVALID_HANDLE_VALUE)
    {
        g_RawLen = 0;
        return;
    }

    if (!WriteFile(g_LogfileHandle, g_RawBufUtf8, (DWORD) g_RawLen, &written, NULL) || written != (DWORD) g_RawLen)
        fwprintf(stderr, L"_RawFlush: WriteFile(raw row) failed: error %d\n", GetLastError());

    g_RawLen = 0;
}

void LogUnlock()
{
    // A raw row ends at the unlock even if its last fragment carried no newline: holding bytes here
    // past the row would attribute them to whatever is logged next.
    _RawFlushUnlocked();
    LeaveCriticalSection(&g_Lock);
}

static DWORD GetCurrentModuleVersion(OUT DWORD *versionMajor, OUT DWORD *versionMinor)
{
    BYTE *versionBuffer = NULL;

    DWORD status = ERROR_OUTOFMEMORY;
    WCHAR* currentModulePath = malloc(MAX_PATH_LONG_WSIZE);
    if (!currentModulePath)
        goto cleanup;

    if (GetModuleFileName(NULL, currentModulePath, MAX_PATH_LONG) == 0)
    {
        status = GetLastError();
        goto cleanup;
    }

    DWORD cbVersion = GetFileVersionInfoSize(currentModulePath, NULL);
    if (cbVersion == 0)
        goto cleanup;

    versionBuffer = malloc(cbVersion);
    if (!versionBuffer)
    {
        status = ERROR_OUTOFMEMORY;
        goto cleanup;
    }

    if (!GetFileVersionInfo(currentModulePath, 0, cbVersion, versionBuffer))
    {
        status = GetLastError();
        goto cleanup;
    }

    VS_FIXEDFILEINFO* fileInfo = NULL;
    UINT cbFileInfo = 0;
    if (!VerQueryValue(versionBuffer, L"\\", &fileInfo, &cbFileInfo))
    {
        status = GetLastError();
        goto cleanup;
    }

    *versionMajor = fileInfo->dwFileVersionMS;
    *versionMinor = fileInfo->dwFileVersionLS;
    status = ERROR_SUCCESS;

cleanup:
    free(currentModulePath);
    free(versionBuffer);
    return status;
}

static void PurgeOldLogs(IN const WCHAR *logDir)
{
    // Read log retention time from registry (in seconds).
    LARGE_INTEGER logRetentionTime = { 0 };
    if (ERROR_SUCCESS != CfgReadDword(g_LogName, LOG_CONFIG_RETENTION_VALUE, &logRetentionTime.LowPart, NULL))
        logRetentionTime.QuadPart = LOG_DEFAULT_RETENTION_TIME;

    logRetentionTime.QuadPart *= 10000000ULL; // convert to 100ns units

    FILETIME ft;
    ULARGE_INTEGER* thresholdTime = (ULARGE_INTEGER*)&ft;

    GetSystemTimeAsFileTime(&ft);
    (*thresholdTime).QuadPart -= logRetentionTime.QuadPart;

    HANDLE findHandle = INVALID_HANDLE_VALUE;
    WCHAR* filePath = NULL;
    WCHAR* searchMask = malloc(MAX_PATH_LONG_WSIZE);
    if (!searchMask)
        goto end;

    filePath = malloc(MAX_PATH_LONG_WSIZE);
    if (!filePath)
        goto end;

    if (FAILED(StringCchPrintf(searchMask, MAX_PATH_LONG, L"%s\\%s*.*", logDir, g_LogName)))
        goto end;

    WIN32_FIND_DATA findData;
    findHandle = FindFirstFile(searchMask, &findData);
    if (findHandle == INVALID_HANDLE_VALUE)
        goto end;

    do
    {
        if ((*(ULARGE_INTEGER *) &findData.ftCreationTime).QuadPart < thresholdTime->QuadPart)
        {
            // File is too old, delete.
            if (FAILED(PathCchCombineEx(filePath, MAX_PATH_LONG, logDir, findData.cFileName, PATHCCH_ALLOW_LONG_PATHS)))
                goto end;
            DeleteFile(filePath);
        }
    } while (FindNextFile(findHandle, &findData));

end:
    free(filePath);
    free(searchMask);
    if (findHandle != INVALID_HANDLE_VALUE)
        FindClose(findHandle);
}

static WCHAR *LogGetName(void)
{
    DWORD status;

    if (g_LogName[0] == 0)
    {
        status = CfgGetModuleName(g_LogName, RTL_NUMBER_OF(g_LogName));
        if (ERROR_SUCCESS != status)
            return NULL;
    }
    return g_LogName;
}

// Read verbosity level from registry config.
// This should not call LogXXX to avoid infinite loop.
static void LogReadLevel(void)
{
    DWORD status;
    DWORD logLevel;
    status = CfgReadDword(LogGetName(), LOG_CONFIG_LEVEL_VALUE, &logLevel, NULL);

    if (status != ERROR_SUCCESS)
        g_LogLevel = LOG_LEVEL_DEFAULT;
    else
        g_LogLevel = logLevel;
}

// Explicitly set verbosity level.
void LogSetLevel(IN int level)
{
    if (level < LOG_LEVEL_MIN || level > LOG_LEVEL_MAX)
    {
        LogWarning("Ignoring invalid log level %d", level);
        return;
    }
    g_LogLevel = level;
    LogInfo("Verbosity level set to %d (%c)", g_LogLevel, g_LogLevelChar[g_LogLevel]);
}

int LogGetLevel(void)
{
    if (g_LogLevel < 0)
        LogReadLevel();

    return g_LogLevel;
}

void LogInit(IN const WCHAR *logDir OPTIONAL, IN const WCHAR *logName)
{
    SYSTEMTIME st;
    DWORD len = 0;
    // ONE FILE PER MODULE PER DAY, not one per process. The date stays because PurgeOldLogs
    // deletes by ftCreationTime: a dateless name would eventually have it delete the LIVE log.
    WCHAR *format = L"%s\\%s-%04d%02d%02d.log";
    WCHAR systemPath[MAX_PATH]; // this should be fine unless for some reason Windows dir is in a weird location
    DWORD versionMajor = 0, versionMinor = 0;
    HANDLE token;
    DWORD sessionId;
    WCHAR* logPath = NULL;

    if (g_LogLevel < 0)
        g_LogLevel = LOG_LEVEL_DEFAULT;

    StringCchCopy(g_LogName, RTL_NUMBER_OF(g_LogName), logName);
    GetLocalTime(&st);

    // if logDir is NULL, use default log location
    if (!logDir)
    {
        // Prepare default log path (%SYSTEMDRIVE%\QubesLogs)

        if (!GetSystemDirectory(systemPath, RTL_NUMBER_OF(systemPath)))
        {
            LogStart(NULL);
            LogWarning("GetSystemDirectory"); // this will just write to stderr before logfile is initialized
            goto fallback;
        }

        if (FAILED(StringCchCopy(systemPath + 3, RTL_NUMBER_OF(systemPath) - 3, LOG_DEFAULT_DIR L"\0")))
        {
            LogStart(NULL);
            LogWarning("StringCchCopy failed");
            goto fallback;
        }
        logDir = systemPath;
    }

    if (!CreateDirectory(logDir, NULL))
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
        {
            LogStart(NULL);
            win_perror("CreateDirectory");
            LogWarning("failed to create %s", logDir);
            goto fallback;
        }
    }

    PurgeOldLogs(logDir);

    logPath = malloc(MAX_PATH_LONG_WSIZE);
    if (!logPath)
    {
        LogStart(NULL);
        LogWarning("Out of memory");
        goto fallback;
    }

    if (FAILED(StringCchPrintf(logPath, MAX_PATH_LONG, format,
        logDir, g_LogName, st.wYear, st.wMonth, st.wDay
        )))
    {
        LogStart(NULL);
        LogWarning("StringCchPrintf(full path) failed");
        goto fallback;
    }

    LogStart(logPath);

    // NOW the logger is up, so the degradation can be said where it will be counted.
    if (g_LogDegraded)
    {
        LogError("QWTLOGFALLBACK the shared log could not be opened (error %lu) - this process is "
            L"logging to %s instead, so this module has a file per process until that is fixed",
            g_LogDegradedError, g_LogFilePath ? g_LogFilePath : L"(unknown)");
        g_LogDegraded = FALSE;
    }

fallback:
    free(logPath);
    // THE STARTUP BANNER IS DEBUG, NOT AN EVENT. qrexec-wrapper is spawned once per qrexec
    // call: measured on acceptance run 39225775322, one brief cell logged 155 invocations, and
    // these six lines times 155 is ~1085 of that module's 1250 lines - 87% of it a process
    // announcing its own birth. Across the whole guest the session read 2535 INFO against 52
    // WARN and 2 ERROR. A product session's log should carry what HAPPENED; who started, as
    // whom, on which build is diagnostic. At LOG_LEVEL_DEBUG every line below comes back, which
    // is where it is wanted. Owner 2026-10-20: "ok for debug purposes but not on a product
    // session".
    LogDebug("Log started, module name: %s", g_LogName);

    // system uptime (useful for performance testing)
    UINT64 uptime_ms = GetTickCount64();
    LogDebug("System uptime: %.3f seconds", uptime_ms / 1000.0f);

    // reuse systemPath
    len = ARRAYSIZE(systemPath); //UNLEN
    if (!GetUserName(systemPath, &len))
    {
        win_perror("GetUserName");
        LogDebug("Running as user: <UNKNOWN>, process ID: %d", GetCurrentProcessId());
    }
    else
    {
        LogDebug("Running as user: %s, process ID: %d", systemPath, GetCurrentProcessId());
    }

    // version
    if (ERROR_SUCCESS == GetCurrentModuleVersion(&versionMajor, &versionMinor))
    {
        LogDebug("Module version: %d.%d.%d.%d",
                (versionMajor >> 0x10) & 0xffff,
                (versionMajor >> 0x00) & 0xffff,
                (versionMinor >> 0x10) & 0xffff,
                (versionMinor >> 0x00) & 0xffff);
    }

    // session
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    GetTokenInformation(token, TokenSessionId, &sessionId, sizeof(sessionId), &len);
    CloseHandle(token);
    LogDebug("Session: %lu", sessionId);
    LogDebug("Command line: %s", GetOriginalCommandLine());

    // ONE BIRTH LINE AT INFO, BECAUSE A LOG THAT CANNOT SAY WHICH BUILD WROTE IT CANNOT BE GRADED.
    //
    // The six lines above are DEBUG and belong there - owner 2026-10-20, "it is NOT normal to have
    // thousands of lines of log during the brief normal run", measured at ~1085 of qrexec-wrapper's
    // 1250 lines in one brief cell. That demotion also took away the only thing that bills a log
    // line to a BUILD. tools/log-sweep.py reads three facts out of that banner - the module name,
    // the boot (from System uptime) and the version - and with the banner at DEBUG it reads none of
    // them. MEASURED, acceptance run 39868919766: every cell reported boots=0 agent_instances=0
    // over thousands of lines, four cells returned status=CLEAN having attributed nothing at all,
    // and win10-upgrade FAILED on five ERROR lines belonging to its 4.3.35.795 entry fixture - the
    // only banner-bearing log in the capture, because that image predates the demotion. The four
    // campaigns before it read boots=3..6 agent_instances=3..5 in the same cells.
    //
    // So state the facts ONCE per process instead of six times: 155 qrexec-wrapper invocations in a
    // cell write 155 lines here where the INFO banner wrote 930. This is the marker
    // tools/sweep-gate.sh:747 already names as patches/windows-utils-single-birth-line and greps for
    // at :778, and that tools/tests/sweep-life-selftest.sh already builds fixtures from - the
    // producer was simply never written, so the gate's own count of birth lines per capture went
    // "2484, then 327, then ZERO".
    //
    // versionMajor/versionMinor stay 0 when GetCurrentModuleVersion failed, so an unversioned image
    // declares ver=0.0.0.0 rather than claiming a version it could not read.
    LogInfo("QWTBIRTH module=%s ver=%d.%d.%d.%d pid=%lu session=%lu uptime=%.3f",
            g_LogName,
            (versionMajor >> 0x10) & 0xffff,
            (versionMajor >> 0x00) & 0xffff,
            (versionMinor >> 0x10) & 0xffff,
            (versionMinor >> 0x00) & 0xffff,
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)sessionId,
            uptime_ms / 1000.0f);
}

// Use the log directory from registry config.
// If logName is NULL, use current executable as name.
DWORD LogInitDefault(IN const WCHAR *logName OPTIONAL)
{
    if (!logName)
    {
        logName = LogGetName();
        if (logName == NULL)
        {
            // log to stderr only
            LogStart(NULL);
            g_LogLevel = LOG_LEVEL_DEFAULT;
            LogInfo("Verbosity level set to %d", g_LogLevel);
            return ERROR_INVALID_NAME;
        }
    }
    else
        StringCchCopy(g_LogName, RTL_NUMBER_OF(g_LogName), logName);

    LogReadLevel(); // needs log name

    DWORD status;
    WCHAR* logPath = malloc(MAX_PATH_LONG_WSIZE);
    if (!logPath)
    {
        // failed, use default location
        LogInit(NULL, logName);
        status = ERROR_OUTOFMEMORY;
        goto end;
    }

    status = CfgReadString(logName, LOG_CONFIG_PATH_VALUE, logPath, MAX_PATH_LONG, NULL);
    if (ERROR_SUCCESS != status)
    {
        LogInit(NULL, logName);
    }
    else
    {
        LogInit(logPath, logName);
    }

end:
    LogDebug("Verbosity level set to %d, safe flush: %d", g_LogLevel, g_SafeFlush);
    return status;
}

// create the log file
// if logfile_path is NULL, use stderr
void LogStart(IN const WCHAR *logfilePath OPTIONAL)
{
    BYTE utf8Bom[3] = { 0xEF, 0xBB, 0xBF };
    DWORD len, status = ERROR_SUCCESS;
    BOOL weCreatedTheLog = FALSE;
    // SAFE FLUSH IS DECIDED BEFORE THE OPEN, because the OPEN implements it now:
    // FlushFileBuffers wants GENERIC_WRITE, which an append-only handle does not have, so leaving
    // durability to it would make safe flush a silent no-op. Write-through does it at the source.
    DWORD logFlags = FILE_ATTRIBUTE_NORMAL;

    if (!g_LoggerInitialized)
    {
        InitializeCriticalSection(&g_Lock);

        if (logfilePath)
        {
            // FILE_APPEND_DATA WITHOUT FILE_WRITE_DATA is what makes a single WriteFile atomic
            // against the other writers; FILE_SHARE_WRITE lets them open it at all. Each line is
            // written in ONE call, so two processes interleave lines but never bytes within one.
            DWORD safeFlushCfg = 0;
            if (CfgReadDword(g_LogName, LOG_CONFIG_FLUSH_VALUE, &safeFlushCfg, NULL) != ERROR_SUCCESS)
                safeFlushCfg = 0;
            if (safeFlushCfg != 0)
                logFlags |= FILE_FLAG_WRITE_THROUGH;

            g_LogfileHandle = CreateFile(
                logfilePath,
                FILE_APPEND_DATA | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, // fixme: security attrs
                CREATE_NEW,
                logFlags,
                NULL);

            // THE BOM BELONGS TO WHOEVER CREATES THE FILE: OPEN_ALWAYS plus a length check lets two
            // simultaneous starters both read zero and both write one, and only one CREATE_NEW can
            // win. WHAT THIS DOES NOT GUARANTEE is the BOM's POSITION - this handle is append-only,
            // so the 3-byte write below is an append like any other and a loser that got in through
            // OPEN_EXISTING first could precede it. Harmless and deliberately not chased: every
            // consumer tolerates a BOM anywhere (log-sweep.py's five line regexes all anchor
            // "^\ufeff?", restart-gui-agent.ps1 the same, and the collector only special-cases a BOM
            // at offset 0 and otherwise decodes it as a U+FEFF character).
            if (g_LogfileHandle != INVALID_HANDLE_VALUE)
            {
                weCreatedTheLog = TRUE;
            }
            else if (GetLastError() == ERROR_FILE_EXISTS || GetLastError() == ERROR_ALREADY_EXISTS)
            {
                // Somebody else owns the BOM; we only append after it. DECLARED, not handled: a
                // delete between the failed CREATE_NEW and this open drops THIS process to stderr
                // for its lifetime - only the age-based purge deletes here, so it needs a
                // retention near zero, and the next process recreates the file.
                g_LogfileHandle = CreateFile(
                    logfilePath,
                    FILE_APPEND_DATA | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, // fixme: security attrs
                    OPEN_EXISTING,
                    logFlags,
                    NULL);
            }

            // A FAILED SHARED OPEN MUST NOT COST THIS PROCESS ITS WHOLE LOG. Sharing failures are
            // newly reachable exactly because the file is shared now - another process can hold it
            // in a way we did not expect, a reader can hold it without FILE_SHARE_WRITE, the ACL
            // can differ - and the old code sent every failure that was not ERROR_FILE_EXISTS to
            // stderr, where this process then logged nothing at all for its lifetime. Fall back to
            // a PER-PROCESS name instead: a few extra files in a rare case beat a blind process.
            if (g_LogfileHandle == INVALID_HANDLE_VALUE)
            {
                DWORD sharedError = GetLastError();
                WCHAR *ownPath = malloc(MAX_PATH_LONG_WSIZE);

                if (ownPath && SUCCEEDED(StringCchPrintf(ownPath, MAX_PATH_LONG, L"%s.%d.log",
                                                         logfilePath, GetCurrentProcessId())))
                {
                    g_LogfileHandle = CreateFile(
                        ownPath,
                        FILE_APPEND_DATA | FILE_READ_ATTRIBUTES,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, // fixme: security attrs
                        OPEN_ALWAYS,
                        logFlags,
                        NULL);
                }

                if (g_LogfileHandle == INVALID_HANDLE_VALUE)
                {
                    status = GetLastError();
                    fwprintf(stderr, L"LogStart: CreateFile(%s) failed: error %d, and the per-process "
                                     L"fallback failed too: error %d\n", logfilePath, sharedError, status);
                    free(ownPath);
                    goto fallback;
                }

                // The reason belongs in the file, and it cannot be written yet: the logger is
                // not initialised until the end of this function. Remembered and emitted by
                // LogInit, so the sweep can COUNT it - a shared open that fails systematically
                // reinstates per-process files for that module, and stderr is not readable for a
                // service's children (CREATE_NO_WINDOW) or for an agent started with
                // CreateProcessAsUser.
                g_LogDegraded = TRUE;
                g_LogDegradedError = sharedError;
                fwprintf(stderr, L"LogStart: the shared log %s could not be opened (error %d) - "
                                 L"logging to %s instead\n", logfilePath, sharedError, ownPath);
                free(g_LogFilePath);
                g_LogFilePath = ownPath;
                weCreatedTheLog = TRUE;   // our own file: the BOM is ours to write
            }
            else
            {
                free(g_LogFilePath);
                g_LogFilePath = _wcsdup(logfilePath);
            }

            if (weCreatedTheLog) // fresh file - write BOM
            {
                if (!WriteFile(g_LogfileHandle, utf8Bom, 3, &len, NULL))
                {
                    status = GetLastError();
                    fwprintf(stderr, L"LogStart: WriteFile(%s) failed: error %d\n", logfilePath, GetLastError());
                    goto fallback;
                }
            }
        }
    }
fallback:
    if (status != ERROR_SUCCESS && g_LogfileHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_LogfileHandle);
        g_LogfileHandle = INVALID_HANDLE_VALUE;
    }

    if (g_LogfileHandle != INVALID_HANDLE_VALUE)
    {
        DWORD safeFlush;
        if (CfgReadDword(g_LogName, LOG_CONFIG_FLUSH_VALUE, &safeFlush, NULL) == ERROR_SUCCESS)
        {
            g_SafeFlush = (safeFlush != 0);
        }
        else
        {
            g_SafeFlush = FALSE;
        }
    }

    g_LoggerInitialized = TRUE;
}

void LogFlush(void)
{
    // ITS CALLERS ARE THE ONES BEFORE ExitProcess (gui-agent lifecycle.c, at a session end), so this
    // has to really flush. FlushFileBuffers documents a GENERIC_WRITE requirement that the
    // append-only handle does not meet, so when it refuses, reopen the same file with write access
    // and flush THAT: the cache is per file, so our appended lines go out with it. Per-line writes
    // stay cached, so nothing in the hot path got slower to buy this.
    static BOOL flushFailureReported = FALSE;

    if (!g_LoggerInitialized || g_LogfileHandle == INVALID_HANDLE_VALUE)
        return;

    if (FlushFileBuffers(g_LogfileHandle))
        return;

    if (g_LogFilePath)
    {
        HANDLE h = CreateFile(
            g_LogFilePath,
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (h != INVALID_HANDLE_VALUE)
        {
            BOOL flushed = FlushFileBuffers(h);
            CloseHandle(h);
            if (flushed)
                return;
        }
    }

    // Both routes refused: the lines this call was meant to make durable may be lost on an abrupt
    // end, and that is said once rather than never.
    if (!flushFailureReported)
    {
        flushFailureReported = TRUE;
        fwprintf(stderr, L"LogFlush: could not flush the log (error %d) - lines before an abrupt "
                         L"process end may be lost\n", GetLastError());
    }
}

static void _LogFormatUnlocked(IN int level, IN BOOL raw, IN const char *functionName, IN const WCHAR *format, va_list args)
{
    size_t bufferSize = 0;
    DWORD written = 0;
    SYSTEMTIME st;
    WCHAR prefixBuffer[256];
    int prefixLen = 0;
    BOOL addNewline = FALSE;
    size_t prefixBufferSize = 0;
    BOOL echoToStderr = level <= LOG_LEVEL_WARNING;

// pid:tid, NOT tid alone: the pid was carried by the file NAME and nothing else, and a shared file
// whose lines do not name their process is unreadable.
#define PREFIX_FORMAT TEXT("[%04d%02d%02d.%02d%02d%02d.%03d-%d:%d-%c] ")
#define PREFIX_FORMAT_FUNCNAME TEXT("%S: ")
    if (!raw)
    {
        ZeroMemory(prefixBuffer, sizeof(prefixBuffer));
        GetLocalTime(&st); // or system time (UTC)?
        prefixLen = swprintf_s(prefixBuffer, RTL_NUMBER_OF(prefixBuffer),
            functionName ? PREFIX_FORMAT PREFIX_FORMAT_FUNCNAME : PREFIX_FORMAT,
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            GetCurrentProcessId(), GetCurrentThreadId(), g_LogLevelChar[level], functionName);
    }

    // format buffer
    bufferSize = vswprintf_s(g_Buffer, LOG_MAX_MESSAGE_LENGTH, format, args) * sizeof(WCHAR);

    if (!raw)
    {
        if (ERROR_SUCCESS != ConvertUTF16ToUTF8(prefixBuffer, g_PrefixBufferUtf8, &prefixBufferSize))
        {
            fwprintf(stderr, L"_LogFormat: ConvertUTF16ToUTF8(prefix) failed: error %d\n", GetLastError());
            goto cleanup;
        }
    }

    if (ERROR_SUCCESS != ConvertUTF16ToUTF8(g_Buffer, g_BufferUtf8, &bufferSize))
    {
        fwprintf(stderr, L"_LogFormat: ConvertUTF16ToUTF8(buffer) failed: error %d\n", GetLastError());
        goto cleanup;
    }

    if (bufferSize == 0)
        addNewline = !raw; // an empty message still ends its own line; reading [-1] was undefined
    else if (g_BufferUtf8[bufferSize - 1] != '\n')
        addNewline = TRUE;

    if (g_LogfileHandle != INVALID_HANDLE_VALUE)
    {
        size_t lineSize = 0;

        // A RAW ROW IS ONE WRITE TOO. Raw output is emitted a FRAGMENT at a time - the window table
        // is 4 to ~40 LogDebugRaw calls for one visual row - so writing each fragment would let
        // another process sharing this file land a line inside the row. Fragments accumulate and go
        // out when one ends the line, or at LogUnlock, or if the buffer would overflow.
        if (raw)
        {
            if (g_RawLen + bufferSize > sizeof(g_RawBufUtf8))
            {
                fwprintf(stderr, L"_LogFormat: raw row exceeds %zu bytes - flushing it early, so it "
                                 L"can be interleaved\n", sizeof(g_RawBufUtf8));
                _RawFlushUnlocked();
            }

            if (bufferSize <= sizeof(g_RawBufUtf8))
            {
                memcpy(g_RawBufUtf8 + g_RawLen, g_BufferUtf8, bufferSize);
                g_RawLen += bufferSize;
                if (g_RawLen > 0 && g_RawBufUtf8[g_RawLen - 1] == '\n')
                    _RawFlushUnlocked();
            }
            else if (!WriteFile(g_LogfileHandle, g_BufferUtf8, (DWORD) bufferSize, &written, NULL))
            {
                fwprintf(stderr, L"_LogFormat: WriteFile(raw) failed: error %d\n", GetLastError());
            }
            goto echo_raw;
        }

        // THE ONE WRITE. A single WriteFile to an append-only handle is atomic against the other
        // processes sharing this file; three calls would let one shred a line mid-way. Same bytes.
        if (prefixBufferSize + bufferSize + 1 <= sizeof(g_LineBufUtf8))
        {
            if (!raw && prefixBufferSize > 0)
            {
                memcpy(g_LineBufUtf8, g_PrefixBufferUtf8, prefixBufferSize);
                lineSize = prefixBufferSize;
            }

            memcpy(g_LineBufUtf8 + lineSize, g_BufferUtf8, bufferSize);
            lineSize += bufferSize;

            if (addNewline && !raw)
                g_LineBufUtf8[lineSize++] = '\n';

            if (!WriteFile(g_LogfileHandle, g_LineBufUtf8, (DWORD) lineSize, &written, NULL) || written != (DWORD) lineSize)
            {
                fwprintf(stderr, L"_LogFormat: WriteFile(line) failed: error %d\n", GetLastError());
                goto cleanup;
            }
        }
        else
        {
            // Too long to compose: written piecewise and SAID, since truncating would be worse.
            fwprintf(stderr, L"_LogFormat: line of %zu bytes exceeds the one-write buffer; writing piecewise\n",
                prefixBufferSize + bufferSize + 1);

            if (!raw)
            {
                if (!WriteFile(g_LogfileHandle, g_PrefixBufferUtf8, (DWORD) prefixBufferSize, &written, NULL) || written != (DWORD) prefixBufferSize)
                {
                    fwprintf(stderr, L"_LogFormat: WriteFile(prefix) failed: error %d\n", GetLastError());
                    goto cleanup;
                }
            }

            // bufferSize is at most INT_MAX*2
            if (!WriteFile(g_LogfileHandle, g_BufferUtf8, (DWORD) bufferSize, &written, NULL) || written != (DWORD) bufferSize)
            {
                fwprintf(stderr, L"_LogFormat: WriteFile failed: error %d\n", GetLastError());
                goto cleanup;
            }

            if (addNewline && !raw)
            {
                if (!WriteFile(g_LogfileHandle, "\n", 1, &written, NULL) || written != 1)
                {
                    fwprintf(stderr, L"_LogFormat: WriteFile failed: error %d\n", GetLastError());
                    goto cleanup;
                }
            }
        }

echo_raw:
        if (echoToStderr)
        {
            if (!raw)
                fwprintf(stderr, L"%s", prefixBuffer);

            fwprintf(stderr, L"%s", g_Buffer);
            if (addNewline && !raw)
            {
                fwprintf(stderr, L"\n");
            }

#if defined(DEBUG) || defined(_DEBUG)
            OutputDebugString(g_Buffer);
            if (addNewline && !raw)
            {
                OutputDebugStringA("\n");
            }
#endif
        }
    }
    else // use stderr
    {
        if (!raw)
            fwprintf(stderr, L"%s", prefixBuffer);
        fwprintf(stderr, L"%s", g_Buffer);
        if (addNewline && !raw)
        {
            fwprintf(stderr, L"\n");
        }
    }

cleanup:

#ifdef LOG_SAFE_FLUSH
    LogFlush();
#endif
    return;
}

void _LogFormat(IN int level, IN BOOL raw, IN const char* functionName, IN const WCHAR* format, ...)
{
    DWORD lastError = GetLastError(); // preserve last error

    ErrRegisterUEF();

    // If we're initializing ad-hoc on a first log call, first read the log level
    // so we can tell if the log file should be created now.
    if (g_LogLevel < 0)
        LogReadLevel();

    if (level > g_LogLevel)
        goto end;

    if (!g_LoggerInitialized)
        LogInitDefault(NULL);

    if (!raw)
        EnterCriticalSection(&g_Lock);

    va_list args;
    va_start(args, format);
    _LogFormatUnlocked(level, raw, functionName, format, args);
    va_end(args);

    if (!raw)
        LeaveCriticalSection(&g_Lock);

end:
    SetLastError(lastError);
}

// Like _win_perror, but takes explicit error code. For cases when previous call doesn't set LastError.
DWORD _win_perror2(IN const char *functionName, IN DWORD errorCode, IN const WCHAR *prefix)
{
    SetLastError(errorCode);
    return _win_perror(functionName, prefix);
}

// Helper function to report errors. Similar to win_perror, but uses GetLastError() instead of errno.
DWORD _win_perror(IN const char *functionName, IN const WCHAR *prefix)
{
    size_t charCount;
    WCHAR *message = NULL;
    WCHAR buffer[2048];
    HRESULT ret;
    DWORD errorCode;

    errorCode = GetLastError();

    ZeroMemory(buffer, sizeof(buffer));
    charCount = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (WCHAR *) &message,
        0,
        NULL);

    if (!charCount)
    {
        if (FAILED(StringCchPrintf(buffer, RTL_NUMBER_OF(buffer), L" failed with error 0x%x\n", errorCode)))
            goto cleanup;
    }
    else
    {
        ret = StringCchPrintf(
            buffer,
            RTL_NUMBER_OF(buffer),
            L" failed with error 0x%x: %s%s",
            errorCode,
            message,
            ((charCount >= 1) && (0x0a == message[charCount - 1])) ? L"" : L"\n");
        LocalFree(message);

        if (FAILED(ret))
            goto cleanup;
    }

    _LogFormat(LOG_LEVEL_ERROR, FALSE, functionName, L"%s%s", prefix, buffer);
cleanup:
    SetLastError(errorCode); // preserve
    return errorCode;
}

// disabled if LOG_NO_HEX_DUMP is defined
void _hex_dump(IN const WCHAR *desc, IN const void *addr, IN int len)
{
    int i;
    WCHAR buff[17];
    BYTE *pc = (BYTE *) addr;

    if (len == 0)
        return;

    LogLock();
    // Output description if given.
    if (desc != NULL)
        LogDebugRaw("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++)
    {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0)
        {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                LogDebugRaw("  %s\n", buff);

            // Output the offset.
            LogDebugRaw("%04x:", i);
        }

        // Now the hex code for the specific character.
        if (i % 8 == 0 && i % 16 != 0)
            LogDebugRaw("  %02x", pc[i]);
        else
            LogDebugRaw(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = TEXT('.');
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = TEXT('\0');
    }

    // Pad out last line if not exactly 16 characters.
    if (i % 16 <= 8 && i % 16 != 0)
        LogDebugRaw(" ");
    while ((i % 16) != 0)
    {
        LogDebugRaw("   ");
        i++;
    }

    // And print the final ASCII bit.
    LogDebugRaw("  %s\n", buff);
    LogUnlock();
}
