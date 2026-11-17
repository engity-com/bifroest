// Native diagnostic only: no Go, WebUI, extra runtime DLL or startup sleep.
// Reference sequence: https://learn.microsoft.com/windows/console/creating-a-pseudoconsole-session
// The relay variant additionally models our suspended start, owned job and
// standard-handle isolation. Both drain concurrently through native pipe EOF.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef struct {
    HANDLE pipe;
    char bytes[16384];
    DWORD count;
    DWORD error;
} Output;

static unsigned __stdcall read_output(void *argument) {
    Output *output = (Output *)argument;
    char chunk[512];
    DWORD count;
    for (;;) {
        if (!ReadFile(output->pipe, chunk, sizeof(chunk), &count, NULL)) {
            DWORD error = GetLastError();
            output->error = error == ERROR_BROKEN_PIPE ? ERROR_SUCCESS : error;
            return 0;
        }
        if (count > sizeof(output->bytes) - 1 - output->count) {
            output->error = ERROR_INSUFFICIENT_BUFFER;
            return 1;
        }
        memcpy(output->bytes + output->count, chunk, count);
        output->count += count;
        output->bytes[output->count] = 0;
    }
}

static DWORD WINAPI watchdog(void *argument) {
    if (WaitForSingleObject((HANDLE)argument, 20000) != WAIT_OBJECT_0) {
        const char message[] = "native ConPTY diagnostic exceeded the unchanged 20-second case limit\n";
        DWORD count;
        WriteFile(GetStdHandle(STD_ERROR_HANDLE), message, sizeof(message) - 1, &count, NULL);
        TerminateProcess(GetCurrentProcess(), 1);
    }
    return 0;
}

static LPWSTR current_sid(void) {
    HANDLE token = NULL;
    DWORD size = 0;
    TOKEN_USER *user = NULL;
    LPWSTR sid = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return NULL;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (size != 0) user = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), 0, size);
    if (user != NULL && GetTokenInformation(token, TokenUser, user, size, &size)) {
        if (!ConvertSidToStringSidW(user->User.Sid, &sid)) sid = NULL;
    }
    if (user != NULL) HeapFree(GetProcessHeap(), 0, user);
    CloseHandle(token);
    return sid;
}

static int child(DWORD exit_code) {
    DWORD mode, written;
    CONSOLE_SCREEN_BUFFER_INFO info;
    LPWSTR sid;
    WCHAR text[512];
    const WCHAR marker[] = L"native-console-child write-success=true\r\n";
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode)) return 101;
    if (!GetConsoleMode(output, &mode)) return 102;
    if (!GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mode)) return 103;
    if (!GetConsoleScreenBufferInfo(output, &info) ||
        info.srWindow.Right - info.srWindow.Left + 1 != 80 ||
        info.srWindow.Bottom - info.srWindow.Top + 1 != 25) return 104;
    sid = current_sid();
    if (sid == NULL) return 105;
    if (swprintf_s(text, _countof(text), L"%ls\r\nnative-console=80x25\r\n", sid) < 0) {
        LocalFree(sid);
        return 106;
    }
    LocalFree(sid);
    if (!WriteConsoleW(output, text, (DWORD)wcslen(text), &written, NULL) || written != wcslen(text)) return 107;
    if (!WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), marker, (DWORD)(_countof(marker) - 1), &written, NULL) ||
        written != _countof(marker) - 1) return 108;
    // These exits are reached only after both full native writes succeeded.
    ExitProcess(exit_code);
}

static int run_case(BOOL relay, DWORD requested_exit) {
    HANDLE input_read = NULL, input_write = NULL, output_read = NULL, output_write = NULL;
    HANDLE reader = NULL, job = NULL, timer = NULL, done = NULL;
    HANDLE saved[3] = {NULL, NULL, NULL};
    const DWORD standard_ids[3] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    HPCON console = NULL;
    STARTUPINFOEXW startup = {0};
    PROCESS_INFORMATION process = {0};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    SIZE_T attribute_bytes = 0;
    BOOL attributes_ready = FALSE, created = FALSE, restored = TRUE;
    BOOL sid_found = FALSE, sid_converted = FALSE, geometry_found = FALSE, marker_found = FALSE;
    DWORD code = 0xffffffff, failure = 0, path_length;
    const char *stage = "setup";
    WCHAR executable[MAX_PATH], command[MAX_PATH + 64];
    char expected_sid[184];
    LPWSTR sid = NULL;
    Output *output = (Output *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Output));
    unsigned int index;
    if (output == NULL) return 0;
    done = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (done == NULL) goto finish;
    timer = CreateThread(NULL, 0, watchdog, done, 0, NULL);
    if (timer == NULL) goto finish;
    sid = current_sid();
    if (sid == NULL || !WideCharToMultiByte(CP_UTF8, 0, sid, -1, expected_sid, sizeof(expected_sid), NULL, NULL)) goto finish;
    sid_converted = TRUE;
    path_length = GetModuleFileNameW(NULL, executable, _countof(executable));
    if (path_length == 0 || path_length >= _countof(executable)) goto finish;
    if (swprintf_s(command, _countof(command), L"\"%ls\" --child %lu", executable, requested_exit) < 0) goto finish;
    if (!CreatePipe(&input_read, &input_write, NULL, 0) || !CreatePipe(&output_read, &output_write, NULL, 0)) goto finish;
    stage = "CreatePseudoConsole";
    if (FAILED(CreatePseudoConsole((COORD){80, 25}, input_read, output_write, 0, &console))) goto finish;
    output->pipe = output_read;
    reader = (HANDLE)_beginthreadex(NULL, 0, read_output, output, 0, NULL);
    if (reader == NULL) goto finish;
    startup.StartupInfo.cb = sizeof(startup);
    // Use an empty explicit table for the reference, as in Microsoft's native
    // ConPTY tests. Do not let redirected parent pipes become child stdio.
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    if (relay) {
        startup.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
        startup.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
        startup.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
    }
    stage = "process attributes";
    InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_bytes);
    startup.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attribute_bytes);
    if (startup.lpAttributeList == NULL || !InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attribute_bytes)) goto finish;
    attributes_ready = TRUE;
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, console, sizeof(console), NULL, NULL)) goto finish;
    if (relay) {
        stage = "owned job";
        job = CreateJobObjectW(NULL, NULL);
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (job == NULL || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) goto finish;
        for (index = 0; index < 3; index++) saved[index] = GetStdHandle(standard_ids[index]);
        for (index = 0; index < 3; index++) {
            if (!SetStdHandle(standard_ids[index], NULL)) break;
        }
        if (index != 3) {
            for (index = 0; index < 3; index++) SetStdHandle(standard_ids[index], saved[index]);
            goto finish;
        }
    }
    stage = "CreateProcess";
    created = CreateProcessW(executable, command, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | (relay ? CREATE_SUSPENDED : 0), NULL, NULL, &startup.StartupInfo, &process);
    failure = created ? ERROR_SUCCESS : GetLastError();
    if (relay) {
        for (index = 0; index < 3; index++) {
            if (!SetStdHandle(standard_ids[index], saved[index])) restored = FALSE;
        }
    }
    if (!created || !restored) goto finish;
    if (relay) {
        stage = "AssignProcessToJobObject/ResumeThread";
        if (!AssignProcessToJobObject(job, process.hProcess) || ResumeThread(process.hThread) == (DWORD)-1) goto finish;
    }
    CloseHandle(input_read); input_read = NULL;
    CloseHandle(output_write); output_write = NULL;
    stage = "root wait";
    if (WaitForSingleObject(process.hProcess, INFINITE) != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &code)) goto finish;
    stage = "drain";

finish:
    if (code == 0xffffffff && failure == 0) failure = GetLastError();
    if (created && code == 0xffffffff) {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, INFINITE);
    }
    if (input_read != NULL) CloseHandle(input_read);
    if (output_write != NULL) CloseHandle(output_write);
    // The reader stays active while Close emits its final frame. There is no
    // sleep, warm-up, cancellation of the output read, or optimistic EOF.
    if (console != NULL) ClosePseudoConsole(console);
    if (reader != NULL) {
        WaitForSingleObject(reader, INFINITE);
        CloseHandle(reader);
    }
    if (input_write != NULL) CloseHandle(input_write);
    if (output_read != NULL) CloseHandle(output_read);
    if (process.hThread != NULL) CloseHandle(process.hThread);
    if (process.hProcess != NULL) CloseHandle(process.hProcess);
    if (job != NULL) CloseHandle(job);
    if (attributes_ready) DeleteProcThreadAttributeList(startup.lpAttributeList);
    if (startup.lpAttributeList != NULL) HeapFree(GetProcessHeap(), 0, startup.lpAttributeList);
    if (sid != NULL) {
        if (sid_converted) sid_found = strstr(output->bytes, expected_sid) != NULL;
        LocalFree(sid);
    }
    geometry_found = strstr(output->bytes, "native-console=80x25") != NULL;
    marker_found = strstr(output->bytes, "native-console-child write-success=true") != NULL;
    if (done != NULL) SetEvent(done);
    if (timer != NULL) { WaitForSingleObject(timer, INFINITE); CloseHandle(timer); }
    if (done != NULL) CloseHandle(done);
    printf("{\"mode\":\"%s\",\"requestedExit\":%lu,\"childExit\":%lu,\"bytes\":%lu,\"readError\":%lu,\"sid\":%s,\"geometry\":%s,\"writeMarker\":%s,\"stage\":\"%s\",\"nativeError\":%lu}\n",
        relay ? "relay" : "reference", requested_exit, code, output->count, output->error,
        sid_found ? "true" : "false", geometry_found ? "true" : "false", marker_found ? "true" : "false", stage, failure);
    {
        int success = created && restored && code == requested_exit && output->error == 0 && sid_found && geometry_found && marker_found;
        HeapFree(GetProcessHeap(), 0, output);
        return success;
    }
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 3 && wcscmp(argv[1], L"--child") == 0 && (wcscmp(argv[2], L"0") == 0 || wcscmp(argv[2], L"7") == 0)) {
        return child(wcscmp(argv[2], L"7") == 0 ? 7 : 0);
    }
    if (argc == 2 && (wcscmp(argv[1], L"reference") == 0 || wcscmp(argv[1], L"relay") == 0)) {
        BOOL relay = wcscmp(argv[1], L"relay") == 0;
        int zero = run_case(relay, 0);
        int seven = run_case(relay, 7);
        return zero && seven ? 0 : 1;
    }
    return 2;
}
