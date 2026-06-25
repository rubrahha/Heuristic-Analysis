#include "ETWProvider.h"
#include <iostream>
#include <TraceLoggingProvider.h>

// Modern C++ ETW: No manifest files required!
TRACELOGGING_DEFINE_PROVIDER(
    g_hScannerProvider,
    "HeuristicScanner-Provider",
    // Unique GUID from your original code
    (0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0)
);

namespace Platform::ETW {

    bool ScannerProvider::Initialize() {
        HRESULT hr = TraceLoggingRegister(g_hScannerProvider);
        if (SUCCEEDED(hr)) {
            std::wcerr << L"✓ ETW Provider Registered (TraceLogging)\n";
            return true;
        }
        std::wcerr << L"✗ ETW Register Failed: " << hr << L"\n";
        return false;
    }

    void ScannerProvider::Shutdown() {
        TraceLoggingUnregister(g_hScannerProvider);
    }

    void ScannerProvider::LogScanStart(const wchar_t* filePath, uint64_t fileSize) {
        TraceLoggingWrite(
            g_hScannerProvider,
            "ScanStart",
            TraceLoggingValue(filePath, "FilePath"),
            TraceLoggingValue(fileSize, "FileSize")
        );
    }

    void ScannerProvider::LogScanResult(
        const wchar_t* filePath,
        int score,
        const wchar_t* verdict,
        const wchar_t* indicators) {

        TraceLoggingWrite(
            g_hScannerProvider,
            "ScanResult",
            TraceLoggingValue(filePath, "FilePath"),
            TraceLoggingValue(score, "Score"),
            TraceLoggingValue(verdict, "Verdict"),
            TraceLoggingValue(indicators, "Indicators")
        );
    }

    void ScannerProvider::LogFileOperation(
        const wchar_t* filePath,
        const wchar_t* operation,
        bool isHighRisk) {

        TraceLoggingWrite(
            g_hScannerProvider,
            "FileOperation",
            TraceLoggingValue(filePath, "FilePath"),
            TraceLoggingValue(operation, "Operation"),
            TraceLoggingValue(isHighRisk, "IsHighRisk")
        );
    }

    void ScannerProvider::LogRegistryAccess(
        const wchar_t* regKey,
        const wchar_t* operation,
        bool isSuspicious) {

        TraceLoggingWrite(
            g_hScannerProvider,
            "RegistryAccess",
            TraceLoggingValue(regKey, "RegistryKey"),
            TraceLoggingValue(operation, "Operation"),
            TraceLoggingValue(isSuspicious, "IsSuspicious")
        );
    }
}