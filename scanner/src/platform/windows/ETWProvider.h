#pragma once
#include <cstdint>     // Fixes the C2061 uint64_t syntax error
#include <windows.h>
#include <evntprov.h>

namespace Platform::ETW {

    class ScannerProvider {
    public:
        // Initialize ETW (call once at app startup)
        static bool Initialize();
        static void Shutdown();

        // Emit events from heuristic engine
        static void LogScanStart(const wchar_t* filePath, uint64_t fileSize);
        static void LogScanResult(
            const wchar_t* filePath,
            int score,               // 0-100
            const wchar_t* verdict,  // CLEAN, SUSPICIOUS, MALICIOUS
            const wchar_t* indicators// comma-separated
        );
        static void LogFileOperation(
            const wchar_t* filePath,
            const wchar_t* operation, // "CREATE", "WRITE", "DELETE", "EXECUTE"
            bool isHighRisk
        );
        static void LogRegistryAccess(
            const wchar_t* regKey,
            const wchar_t* operation, // "READ", "WRITE"
            bool isSuspicious
        );
    };
}