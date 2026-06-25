#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <iostream>
#include <string>
#include <krabs.hpp>

// ── Global Service Variables ──
SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
krabs::kernel_trace* g_pTrace = nullptr;

// ── 1. Your Existing IPC Logic ──
std::wstring EscapeJSON(const std::wstring& s) {
    std::wstring result;
    for (wchar_t c : s) {
        if (c == L'\"') result += L"\\\"";
        else if (c == L'\\') result += L"\\\\";
        else result += c;
    }
    return result;
}

void SendAlertToEngine(uint32_t pid, const std::wstring& exe, const std::wstring& cmd) {
    HANDLE hPipe = CreateFileW(
        L"\\\\.\\pipe\\HeuristicSensorPipe",
        GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL
    );

    if (hPipe != INVALID_HANDLE_VALUE) {
        std::wstring payload = L"{\"pid\": " + std::to_wstring(pid) + 
                               L", \"exe\": \"" + EscapeJSON(exe) + 
                               L"\", \"cmd\": \"" + EscapeJSON(cmd) + L"\"}";
        DWORD bytesWritten;
        WriteFile(hPipe, payload.c_str(), payload.length() * sizeof(wchar_t), &bytesWritten, NULL);
        CloseHandle(hPipe);
    }
}

void ProcessStartCallback(const EVENT_RECORD& record, const krabs::trace_context& ctx) {
    if (record.EventHeader.EventDescriptor.Opcode == 1) {
        krabs::schema schema(record, ctx.schema_locator);
        krabs::parser parser(schema);
        try {
            uint32_t processId = parser.parse<uint32_t>(L"ProcessId");
            std::string imageFileName = parser.parse<std::string>(L"ImageFileName");
            std::wstring wImageFileName(imageFileName.begin(), imageFileName.end());
            std::wstring commandLine = L"";
            try { commandLine = parser.parse<std::wstring>(L"CommandLine"); } catch (...) {}
            
            SendAlertToEngine(processId, wImageFileName, commandLine);
        } catch (...) {}
    }
}

// ── 2. The Shutdown Handler (Called by Windows when the PC turns off) ──
VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    if (CtrlCode == SERVICE_CONTROL_STOP || CtrlCode == SERVICE_CONTROL_SHUTDOWN) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

        // Stop the ETW trace, which will unblock ServiceMain
        if (g_pTrace) {
            g_pTrace->stop();
        }
    }
}

// ── 3. The Real Entry Point (Runs as SYSTEM in Session 0) ──
VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerW(L"HeuristicSensor", ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    // Tell Windows the service is starting up
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    try {
        krabs::kernel_trace trace;
        g_pTrace = &trace; // Store pointer globally so CtrlHandler can stop it
        
        krabs::kernel::process_provider processProvider;
        processProvider.add_on_event_callback(ProcessStartCallback);
        trace.enable(processProvider);
        
        // This blocks forever until the PC shuts down or you stop the service!
        trace.start(); 
    } 
    catch (...) {}

    // Tell Windows the service has safely stopped
    g_pTrace = nullptr;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// ── 4. The SCM Bootstrapper ──
int wmain(int argc, wchar_t *argv[]) {
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        { const_cast<LPWSTR>(L"HeuristicSensor"), (LPSERVICE_MAIN_FUNCTIONW) ServiceMain },
        { NULL, NULL }
    };
    
    // Hand over control to the Windows Service Control Manager
    StartServiceCtrlDispatcherW(ServiceTable);
    return 0;
}