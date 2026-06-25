#include "WhitelistManager.h"
#include "../utils/StringUtils.h"
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")

namespace Heuristics {

    namespace {

        // ── Helpers ───────────────────────────────────────────────────────────────────

        [[nodiscard]] std::wstring ExpandAndLower(std::wstring_view ev) {
            std::wstring expanded = Utils::ExpandEnvVars(ev);
            std::wstring lower = Utils::ToLower(expanded);
            while (!lower.empty() && (lower.back() == L'\\' || lower.back() == L'/')) {
                lower.pop_back();
            }
            return lower;
        }

        [[nodiscard]] std::wstring ShellPathLow(int csidl) {
            wchar_t buf[MAX_PATH] = {};
            if (SUCCEEDED(::SHGetFolderPathW(nullptr, csidl, nullptr, SHGFP_TYPE_CURRENT, buf))) {
                std::wstring lower = Utils::ToLower(std::wstring(buf));
                while (!lower.empty() && (lower.back() == L'\\' || lower.back() == L'/')) {
                    lower.pop_back();
                }
                return lower;
            }
            return {};
        }

        // ── RAII Wrappers for CryptoAPI ───────────────────────────────────────────────
        struct ScopedCryptProv {
            HCRYPTPROV hProv = 0;
            ~ScopedCryptProv() { if (hProv) ::CryptReleaseContext(hProv, 0); }
        };

        struct ScopedCryptHash {
            HCRYPTHASH hHash = 0;
            ~ScopedCryptHash() { if (hHash) ::CryptDestroyHash(hHash); }
        };

        struct ScopedFileHandle {
            HANDLE hFile = INVALID_HANDLE_VALUE;
            ~ScopedFileHandle() { if (hFile != INVALID_HANDLE_VALUE) ::CloseHandle(hFile); }
        };

    } // namespace

    // ── Thread-Safe State Management ─────────────────────────────────────────────

    std::mutex& WhitelistManager::GetMutex() {
        static std::mutex mtx;
        return mtx;
    }

    std::vector<std::wstring>& WhitelistManager::GetTrustedPaths() {
        static std::vector<std::wstring> paths = []() {
            std::vector<std::wstring> v;
            v.reserve(50);

            // Windows Core
            v.push_back(ExpandAndLower(L"%SystemRoot%\\system32"));
            v.push_back(ExpandAndLower(L"%SystemRoot%\\syswow64"));
            v.push_back(ExpandAndLower(L"%SystemRoot%\\sysnative"));
            v.push_back(ExpandAndLower(L"%SystemRoot%\\winsxs"));
            v.push_back(ExpandAndLower(L"%SystemRoot%\\servicing"));
            v.push_back(ExpandAndLower(L"%SystemRoot%\\boot"));

            // .NET
            v.push_back(ExpandAndLower(L"%SystemRoot%\\microsoft.net"));
            v.push_back(ExpandAndLower(L"%SystemRoot%\\assembly"));
            v.push_back(ExpandAndLower(L"%ProgramFiles%\\dotnet"));
            v.push_back(ExpandAndLower(L"%ProgramFiles(x86)%\\dotnet"));

            // Program Files & WindowsApps
            v.push_back(ExpandAndLower(L"%ProgramFiles%"));
            v.push_back(ExpandAndLower(L"%ProgramFiles(x86)%"));
            v.push_back(ExpandAndLower(L"%ProgramFiles%\\windowsapps"));

            // Windows Defender
            v.push_back(ExpandAndLower(L"%ProgramData%\\microsoft\\windows defender"));

            // Common Dev Tools
            v.push_back(L"c:\\mingw");
            v.push_back(L"c:\\mingw32");
            v.push_back(L"c:\\mingw64");
            v.push_back(L"c:\\msys64");
            v.push_back(ExpandAndLower(L"%USERPROFILE%\\.vscode\\extensions"));
            v.push_back(ExpandAndLower(L"%LOCALAPPDATA%\\programs\\python"));
            v.push_back(L"c:\\python3");

            auto addShell = [&](int csidl) {
                std::wstring p = ShellPathLow(csidl);
                if (!p.empty()) v.push_back(std::move(p));
                };

            addShell(CSIDL_SYSTEM);
            addShell(CSIDL_SYSTEMX86);
            addShell(CSIDL_PROGRAM_FILES);
            addShell(CSIDL_PROGRAM_FILESX86);
            addShell(CSIDL_WINDOWS);

            // Clean up empty entries, sort, and deduplicate
            v.erase(std::remove_if(v.begin(), v.end(), [](const std::wstring& s) { return s.empty(); }), v.end());
            std::ranges::sort(v);
            auto ret = std::ranges::unique(v);
            v.erase(ret.begin(), ret.end());

            return v;
            }();
        return paths;
    }

    std::unordered_set<std::string>& WhitelistManager::GetKnownHashes() {
        static std::unordered_set<std::string> hashes = {
            // Built-in known-good hashes go here
        };
        return hashes;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    void WhitelistManager::AddTrustedPath(std::wstring_view pathPrefix) {
        std::wstring low = Utils::ToLower(std::wstring(pathPrefix));
        while (!low.empty() && (low.back() == L'\\' || low.back() == L'/')) {
            low.pop_back();
        }

        std::lock_guard<std::mutex> lock(GetMutex());
        GetTrustedPaths().push_back(std::move(low));
        std::ranges::sort(GetTrustedPaths());
    }

    void WhitelistManager::AddKnownGoodHash(std::string_view sha256hex) {
        std::string low = Utils::ToLower(std::string(sha256hex));
        std::lock_guard<std::mutex> lock(GetMutex());
        GetKnownHashes().insert(std::move(low));
    }

    // ── Checking Logic ────────────────────────────────────────────────────────

    bool WhitelistManager::IsTrustedPath(std::wstring_view lowerPath) {
        std::lock_guard<std::mutex> lock(GetMutex());
        const auto& trustedPaths = GetTrustedPaths();

        for (const auto& prefix : trustedPaths) {
            if (prefix.empty()) continue;

            if (Utils::StartsWithW_i(lowerPath, prefix)) {
                if (lowerPath.size() == prefix.size() ||
                    lowerPath[prefix.size()] == L'\\' ||
                    lowerPath[prefix.size()] == L'/') {
                    return true;
                }
            }
        }
        return false;
    }

    bool WhitelistManager::IsKnownGoodHash(std::string_view hexHash) {
        if (hexHash.size() != 64) return false;

        std::lock_guard<std::mutex> lock(GetMutex());
        const auto& hashes = GetKnownHashes();
        return hashes.find(std::string(hexHash)) != hashes.end();
    }

    // ── Zero-Copy Hashing Overload ────────────────────────────────────────────
    std::string WhitelistManager::ComputeSHA256(std::span<const uint8_t> data) {
        if (data.empty()) return {};

        ScopedCryptProv prov;
        ScopedCryptHash hash;

        if (!::CryptAcquireContextW(&prov.hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return {};
        if (!::CryptCreateHash(prov.hProv, CALG_SHA_256, 0, 0, &hash.hHash)) return {};

        // To prevent locking the UI/Thread on giant files, hash in chunks even from memory
        const size_t chunkSize = 65536;
        for (size_t offset = 0; offset < data.size(); offset += chunkSize) {
            size_t currentChunk = std::min(chunkSize, data.size() - offset);
            if (!::CryptHashData(hash.hHash, data.data() + offset, static_cast<DWORD>(currentChunk), 0)) {
                return {};
            }
        }

        BYTE hashBytes[32];
        DWORD hashLen = 32;
        if (!::CryptGetHashParam(hash.hHash, HP_HASHVAL, hashBytes, &hashLen, 0)) return {};

        std::ostringstream oss;
        for (DWORD i = 0; i < hashLen; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hashBytes[i]);
        }
        return oss.str();
    }

    // Standard Disk I/O Hash
    std::string WhitelistManager::ComputeSHA256(const std::filesystem::path& filePath) {
        ScopedFileHandle file;
        file.hFile = ::CreateFileW(
            filePath.c_str(),
            GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

        if (file.hFile == INVALID_HANDLE_VALUE) return {};

        ScopedCryptProv prov;
        ScopedCryptHash hash;

        if (!::CryptAcquireContextW(&prov.hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return {};
        if (!::CryptCreateHash(prov.hProv, CALG_SHA_256, 0, 0, &hash.hHash)) return {};

        std::vector<BYTE> buf(65536);
        DWORD bytesRead = 0;

        while (::ReadFile(file.hFile, buf.data(), static_cast<DWORD>(buf.size()), &bytesRead, nullptr) && bytesRead > 0) {
            if (!::CryptHashData(hash.hHash, buf.data(), bytesRead, 0)) return {};
        }

        BYTE hashBytes[32];
        DWORD hashLen = 32;
        if (!::CryptGetHashParam(hash.hHash, HP_HASHVAL, hashBytes, &hashLen, 0)) return {};

        std::ostringstream oss;
        for (DWORD i = 0; i < hashLen; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hashBytes[i]);
        }
        return oss.str();
    }

    WhitelistResult WhitelistManager::Check(const Core::ScanTarget& target) {
        WhitelistResult r;
        if (target.isRegistryKey) return r;

        std::wstring lowerPath = Utils::ToLower(target.filePath.wstring());

        // Layer 1: Trusted path (instant, no I/O)
        if (IsTrustedPath(lowerPath)) {
            r.whitelisted = true;
            r.reason = "[WhitelistManager] Trusted system/software path — skipped";
            return r;
        }

        // Layer 2: Known-good hash
        // THE FIX: Use std::unique_lock so we can safely unlock it before heavy hashing
        std::unique_lock<std::mutex> lock(GetMutex());
        if (!GetKnownHashes().empty()) {

            // Unlock before computing the hash to avoid blocking other threads during I/O
            lock.unlock();

            std::string sha256;

            // Check if engine already mapped the file to avoid disk I/O
            std::span<const uint8_t> mappedView = target.GetMappedData();
            if (!mappedView.empty()) {
                sha256 = ComputeSHA256(mappedView);
            }
            else {
                sha256 = ComputeSHA256(target.filePath);
            }

            lock.lock(); // Re-lock for the check against the unordered_set

            if (!sha256.empty() && IsKnownGoodHash(sha256)) {
                r.whitelisted = true;
                r.matchedHash = sha256;
                r.reason = "[WhitelistManager] Known-good SHA-256 hash match — skipped";
                return r;
            }
        }

        return r;
    }

} // namespace Heuristics