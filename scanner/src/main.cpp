/**
 * HeuristicScanner v2.0 (Enterprise C++20 Standard)
 *
 * --file "path"   single file → SCORE:N  VERDICT:X  >> indicators
 * --dir  "path"   folder scan → JSON lines on stdout, one result per line
 * --server        IPC server  → reads paths from stdin, streams JSON to stdout
 * (no args)       interactive console menu
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <iostream>
#include <string>
#include <string_view>
#include <array>
#include <filesystem>
#include <algorithm>

#include "heuristics/HeuristicEngine.h"
#include "platform/windows/FileSystem.h"
#include "core/ScanTarget.h"
#include "core/ScanResult.h"
#include "utils/StringUtils.h"
#include "platform/windows/ETWProvider.h"

namespace fs = std::filesystem;

static Heuristics::HeuristicEngine g_engine;

// ── Enterprise Standard: Zero-Allocation Compile-Time Arrays ─────────────

constexpr std::array<std::wstring_view, 13> kScanExts = {
    L".exe", L".dll", L".scr", L".sys", L".ocx", L".drv", L".cpl",
    L".bat", L".cmd", L".ps1", L".vbs", L".js", L".hta"
};

// Directories to completely skip during recursive scan to prevent access violations
constexpr std::array<std::wstring_view, 13> kSkipDirs = {
    L"\\windows\\winsxs\\", L"\\windows\\servicing\\", L"\\windows\\softwaredistribution\\",
    L"\\windows\\assembly\\", L"\\windows\\microsoft.net\\", L"\\system volume information\\",
    L"\\$recycle.bin\\", L"\\$windows.~bt\\", L"\\$windows.~ws\\",
    L"\\windows\\installer\\", L"\\perflogs\\", L"\\windows\\logs\\", L"\\windows\\debug\\"
};

constexpr std::array<std::wstring_view, 6> kHighRiskPaths = {
    L"\\temp\\", L"\\tmp\\", L"\\appdata\\roaming\\",
    L"\\appdata\\local\\temp\\", L"\\users\\public\\", L"\\programdata\\"
};

// ── Helpers ───────────────────────────────────────────────────────────────

[[nodiscard]] static bool ShouldSkipDir(std::wstring_view lowPath) noexcept {
    for (const auto& skipDir : kSkipDirs) {
        if (lowPath.find(skipDir) != std::wstring_view::npos) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] static std::wstring TrimQuotes(std::wstring_view s) {
    if (s.length() >= 2 && s.front() == L'"' && s.back() == L'"') {
        return std::wstring(s.substr(1, s.length() - 2));
    }
    return std::wstring(s);
}

// ── Core Logic ────────────────────────────────────────────────────────────

static void Enrich(Core::ScanTarget& t) {
    t.fileSize = Platform::GetFileSize(t.filePath);
    t.isExecutable = Platform::IsExecutable(t.filePath);

    try {
        auto [c, w] = Platform::GetFileTimes(t.filePath);
        t.creationTime = c;
        t.lastWriteTime = w;
    }
    catch (...) { /* Swallow access errors */ }

    std::wstring lowPath = Utils::ToLower(t.filePath.wstring());

    for (const auto& riskPath : kHighRiskPaths) {
        if (lowPath.find(riskPath) != std::wstring::npos) {
            t.isInHighRiskLocation = true;
            break;
        }
    }
}

// ── ETW Helper ────────────────────────────────────────────────────────────
static std::wstring FormatETWIndicators(const std::vector<std::string>& indicators) {
    if (indicators.empty()) return L"None";
    std::wstring res;
    for (size_t i = 0; i < indicators.size(); ++i) {
        res += Utils::StrToWstr(indicators[i]);
        if (i < indicators.size() - 1) res += L" | ";
    }
    return res;
}


static void ScanFile(const fs::path& path) {
    auto t = Core::ScanTarget::FromFile(path);
    Enrich(t);

    // ETW: Log Scan Start
    Platform::ETW::ScannerProvider::LogScanStart(t.filePath.wstring().c_str(), t.fileSize);

    auto r = g_engine.Analyze(t);

    // ETW: Log Scan Result
    Platform::ETW::ScannerProvider::LogScanResult(
        t.filePath.wstring().c_str(),
        r.riskScore,
        Utils::StrToWstr(r.verdict).c_str(),     // Safely convert to wide string
        FormatETWIndicators(r.indicators).c_str() // Use our new helper
    );

    std::cout << "SCORE:" << r.riskScore << "\n"
        << "VERDICT:" << r.verdict << "\n";

    for (const auto& ind : r.indicators) {
        std::cout << ">> " << ind << "\n";
    }
}

// ── Streaming JSONL Directory Scan ────────────────────────────────────────

static void ScanDir(const fs::path& dirPath) {
    std::error_code ec;
    auto opts = fs::directory_options::skip_permission_denied
        | fs::directory_options::follow_directory_symlink;

    uint64_t filesSeen = 0;

    try {
        for (auto it = fs::recursive_directory_iterator(dirPath, opts, ec);
            it != fs::recursive_directory_iterator(); )
        {
            if (ec) { ec.clear(); it.increment(ec); continue; }

            try {
                const auto& entry = *it;

                if (entry.is_directory(ec) && !ec) {
                    std::wstring lowPath = Utils::ToLower(entry.path().wstring());
                    if (ShouldSkipDir(lowPath)) {
                        it.disable_recursion_pending();
                        it.increment(ec);
                        continue;
                    }
                }

                if (!entry.is_regular_file(ec) || ec) {
                    it.increment(ec);
                    continue;
                }

                std::wstring ext = Utils::ToLower(entry.path().extension().wstring());
                bool isTargetExt = std::find(kScanExts.begin(), kScanExts.end(), ext) != kScanExts.end();

                if (!isTargetExt) {
                    it.increment(ec);
                    continue;
                }

                auto t = Core::ScanTarget::FromFile(entry.path());
                Enrich(t);

                // ETW: Log Scan Start
                Platform::ETW::ScannerProvider::LogScanStart(t.filePath.wstring().c_str(), t.fileSize);

                auto r = g_engine.Analyze(t);

                // ETW: Log Scan Result
                Platform::ETW::ScannerProvider::LogScanResult(
                    t.filePath.wstring().c_str(),
                    r.riskScore,
                    Utils::StrToWstr(r.verdict).c_str(),     // Safely convert to wide string
                    FormatETWIndicators(r.indicators).c_str() // Use our new helper
                );
                

                // Emit result immediately as UTF-8 JSON
                std::cout << r.ToJson() << "\n";
                std::cout.flush(); // Critical for streaming to Python UI

                filesSeen++;

            }
            catch (...) { /* Swallow per-file errors to keep the stream alive */ }

            it.increment(ec);
        }
    }
    catch (...) { /* Swallow catastrophic directory failures */ }

    // Signal done with a sentinel line
    std::cout << "{\"done\":true,\"total\":" << filesSeen << "}\n";
    std::cout.flush();
}

// ── Persistent IPC Server Mode ────────────────────────────────────────────

static void RunIpcServer() {
    std::string line;

    // Continuously read file paths pushed by Python over standard input
    while (std::getline(std::cin, line)) {
        // Trim whitespace and newlines
        line.erase(line.find_last_not_of(" \n\r\t") + 1);
        if (line.empty()) continue;

        // THE FIX: Use our memory-safe architecture for UTF-8 conversion
        std::wstring wPath = Utils::StrToWstr(line);
        fs::path targetPath(wPath);

        // If Defender locked the file or it doesn't exist, instantly return a JSON error
        if (!fs::exists(targetPath)) {
            std::cout << "{\"path\":\"" << Core::ScanResult::EscapeJsonString(line)
                << "\",\"score\":0,\"verdict\":\"ERROR\",\"indicators\":[\"Access Denied / Locked\"]}"
                << std::endl; // std::endl flushes the pipe!
            continue;
        }

        try {
            auto t = Core::ScanTarget::FromFile(targetPath);
            Enrich(t);

            // ETW: Log Scan Start
            Platform::ETW::ScannerProvider::LogScanStart(t.filePath.wstring().c_str(), t.fileSize);

            auto r = g_engine.Analyze(t);

            // ETW: Log Scan Result
            Platform::ETW::ScannerProvider::LogScanResult(
                t.filePath.wstring().c_str(),
                r.riskScore,
                Utils::StrToWstr(r.verdict).c_str(),     // Safely convert to wide string
                FormatETWIndicators(r.indicators).c_str() // Use our new helper
            );

            // Print the JSON and flush the buffer back to Python immediately
            std::cout << r.ToJson() << std::endl;
        }
        catch (...) {
            // Catch-all to prevent C++ from silently crashing the IPC pipe
            std::cout << "{\"path\":\"" << Core::ScanResult::EscapeJsonString(line)
                << "\",\"score\":0,\"verdict\":\"ERROR\",\"indicators\":[\"C++ Exception Thrown\"]}"
                << std::endl;
        }
    }
}

// ── Interactive Console ───────────────────────────────────────────────────

static void RunInteractive() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"\n  HeuristicScanner v2.0  |  11 Rules  |  AI-Ready Output\n\n";
    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    while (true) {
        std::wcout << L"  [1] Scan file\n  [2] Scan folder\n  [3] Exit\n  > ";
        int c = 0;
        std::wcin >> c;
        std::wcin.ignore(1024, L'\n');

        if (c == 3) break;

        std::wcout << L"  Path: ";
        std::wstring path;
        std::getline(std::wcin, path);

        if (path.empty()) continue;

        path = TrimQuotes(path);
        fs::path targetPath(path);

        if (c == 1 && fs::exists(targetPath))       ScanFile(targetPath);
        if (c == 2 && fs::is_directory(targetPath)) ScanDir(targetPath);

        std::wcout << L"\n";
    }
}

// ── Entry Point ───────────────────────────────────────────────────────────

int wmain(int argc, wchar_t* argv[]) {
    // Ensure all stdout is UTF-8 encoded for the Python JSON parser
    SetConsoleOutputCP(CP_UTF8);

    // ETW: Initialize Provider
    Platform::ETW::ScannerProvider::Initialize();

    g_engine.RegisterDefaultRules();

    if (argc >= 2) {
        std::wstring mode = argv[1];

        if (mode == L"--server") {
            RunIpcServer(); // THE FIX: Cleanly route to our IPC server function
            
            // ETW: Shutdown Provider
            Platform::ETW::ScannerProvider::Shutdown();
            return 0;
        }

        if (argc >= 3) {
            std::wstring path = TrimQuotes(argv[2]);
            fs::path targetPath(path);

            if (mode == L"--file") {
                ScanFile(targetPath);

                // ETW: Shutdown Provider
                Platform::ETW::ScannerProvider::Shutdown();
                return 0;
            }
            if (mode == L"--dir") {
                ScanDir(targetPath);

                // ETW: Shutdown Provider
                Platform::ETW::ScannerProvider::Shutdown();
                return 0;
            }
        }
    }

    RunInteractive();

    // ETW: Shutdown Provider
    Platform::ETW::ScannerProvider::Shutdown();
    return 0;
}