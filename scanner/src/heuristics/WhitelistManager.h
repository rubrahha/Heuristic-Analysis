#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <span>
#include "../core/ScanTarget.h"

namespace Heuristics {

    struct WhitelistResult {
        bool        whitelisted = false;
        std::string reason;
        std::string matchedHash;
    };

    // ---------------------------------------------------------------------------
    // WhitelistManager
    //
    // Fast-paths trusted files to bypass expensive heuristic scanning.
    // Utilizes thread-safe path prefix matching and zero-copy SHA-256 hashing.
    // ---------------------------------------------------------------------------
    class WhitelistManager final {
    public:
        [[nodiscard]] static WhitelistResult Check(const Core::ScanTarget& target);

        static void AddTrustedPath(std::wstring_view pathPrefix);
        static void AddKnownGoodHash(std::string_view sha256hex);

        // Standard Disk I/O Hash (For files not currently mapped)
        [[nodiscard]] static std::string ComputeSHA256(const std::filesystem::path& filePath);

        // Zero-Copy Hash (For files already mapped into RAM by the engine)
        [[nodiscard]] static std::string ComputeSHA256(std::span<const uint8_t> data);

    private:
        [[nodiscard]] static bool IsTrustedPath(std::wstring_view lowerPath);
        [[nodiscard]] static bool IsKnownGoodHash(std::string_view hexHash);

        // Static instances managed internally for thread safety
        static std::vector<std::wstring>& GetTrustedPaths();
        static std::unordered_set<std::string>& GetKnownHashes();

        // Mutex to protect runtime additions to the lists
        static std::mutex& GetMutex();
    };

} // namespace Heuristics