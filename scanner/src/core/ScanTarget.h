#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <string>
#include <filesystem>
#include <windows.h>
#include <span>
#include "../platform/windows/FileSystem.h" // Required for MemoryMappedFile

namespace Core {

    // Represents the "Trust Status" populated by TrustAnalyzer
    struct TrustContext {
        bool isSignatureValid = false;
        bool isSigned = false;
        std::string signerName;

        // File Type flags
        bool isInstaller = false;
        bool isGameEngine = false;
        bool isElectron = false;
        bool isMinGW = false;
        bool isDotNet = false;
        bool is64bit = false;
        bool isDriver = false;

        // Trust modifier (Negative numbers reduce the final threat score)
        int trustModifier = 0;
    };

    // Represents the File or Registry Key being scanned
    class ScanTarget {
    public:
        std::filesystem::path filePath;
        std::wstring          registryKey;

        bool isRegistryKey = false;
        bool isInHighRiskLocation = false;
        bool isExecutable = false;

        uint64_t fileSize = 0;
        FILETIME creationTime = { 0, 0 };
        FILETIME lastWriteTime = { 0, 0 };
        FILETIME scanStartTime = { 0, 0 }; // CRITICAL: Required by AgeRule

        TrustContext trust;

        // Factory method for creating a file target
        static ScanTarget FromFile(const std::filesystem::path& path) {
            ScanTarget t;
            t.filePath = path;
            t.isRegistryKey = false;
            return t;
        }

        // Factory method for creating a registry target
        static ScanTarget FromRegistry(const std::wstring& key) {
            ScanTarget t;
            t.registryKey = key;
            t.isRegistryKey = true;
            return t;
        }

        // ── Memory Mapping API used by HeuristicEngine ────────────────────

        void MapFileToMemory() {
            if (!isRegistryKey) {
                (void)memoryMap_.Open(filePath.wstring());
            }
        }

        void UnmapFileFromMemory() noexcept {
            memoryMap_.Close();
        }

        // Zero-copy span consumed by all Heuristic Rules
        [[nodiscard]] std::span<const uint8_t> GetMappedData() const noexcept {
            return memoryMap_.GetSpan();
        }

    private:
        // The RAII wrapper that handles WinAPI CreateFileMapping / MapViewOfFile
        Platform::MemoryMappedFile memoryMap_;
    };

} // namespace Core