#include "Registry.h"
#include "utils/StringUtils.h" // Ensure path matches your project tree
#include <algorithm>
#include <array>
#include <mutex>

namespace Platform {

    namespace {

        // Enterprise Standard: RAII wrapper ensures the registry key is ALWAYS closed
        struct ScopedHKEY {
            HKEY hKey = nullptr;
            ~ScopedHKEY() {
                if (hKey) {
                    ::RegCloseKey(hKey);
                }
            }
        };

        // Enterprise Standard: Compile-time arrays
        constexpr std::array<std::wstring_view, 3> kRunKeys = {
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        };

        const std::array<HKEY, 2> kRoots = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };

        // ── Thread-Safe Registry Cache ──────────────────────────────────────────
        // Reads the Run keys from the registry exactly ONCE and holds them in memory.
        const std::vector<std::wstring>& GetCachedRunKeyData() {
            static std::vector<std::wstring> cachedData;
            static std::once_flag initFlag;

            // std::call_once guarantees thread safety if multiple scanning threads 
            // attempt to access the cache simultaneously on the very first file.
            std::call_once(initFlag, [&]() {
                for (HKEY root : kRoots) {
                    for (const auto& key : kRunKeys) {
                        for (const auto& val : ReadRegistryValues(root, key)) {
                            if (!val.data.empty()) {
                                // Lowercase and cache the data exactly once
                                cachedData.push_back(Utils::ToLower(val.data));
                            }
                        }
                    }
                }
                });

            return cachedData;
        }

    } // namespace


    std::vector<RegValue> ReadRegistryValues(HKEY root, std::wstring_view subKey) {
        std::vector<RegValue> result;
        ScopedHKEY scopedKey;

        // Convert string_view to null-terminated wstring for WinAPI compatibility
        std::wstring safeSubKey(subKey);

        if (::RegOpenKeyExW(root, safeSubKey.c_str(), 0, KEY_READ, &scopedKey.hKey) != ERROR_SUCCESS) {
            return result;
        }

        DWORD index = 0;

        // Static buffers to prevent massive heap allocations inside the loop
        wchar_t nameBuf[16384];
        BYTE dataBuf[16384];

        while (true) {
            DWORD nLen = static_cast<DWORD>(std::size(nameBuf));
            DWORD dLen = static_cast<DWORD>(std::size(dataBuf));
            DWORD type = 0;

            LONG ret = ::RegEnumValueW(
                scopedKey.hKey, index++,
                nameBuf, &nLen,
                nullptr, &type,
                dataBuf, &dLen
            );

            if (ret != ERROR_SUCCESS) {
                break;
            }

            // Only process string types
            if (type == REG_SZ || type == REG_EXPAND_SZ) {

                // Malware safety check: The registry data length is returned in BYTES, not characters.
                // And it may or may not include the null terminator. 
                size_t charCount = dLen / sizeof(wchar_t);

                auto* wcharData = reinterpret_cast<wchar_t*>(dataBuf);
                if (charCount > 0 && wcharData[charCount - 1] == L'\0') {
                    charCount--; // Strip null terminator if present so std::wstring doesn't double-count it
                }

                result.push_back({
                    std::wstring(nameBuf, nLen),
                    std::wstring(wcharData, charCount)
                    });
            }
        }

        return result;
    }

    bool FileIsInRunKey(std::wstring_view filePath) {
        if (filePath.empty()) return false;

        // We only lower-case the target file path once per file scan
        std::wstring lowerTarget = Utils::ToLower(std::wstring(filePath));

        // Fetch the blazing-fast in-memory cache (No disk/registry I/O happens here!)
        const auto& cachedData = GetCachedRunKeyData();

        for (const auto& lowerData : cachedData) {
            // Check if our file path is a substring of the registry data 
            // (Accounts for args like: "C:\malware.exe" /silent)
            if (lowerData.find(lowerTarget) != std::wstring::npos) {
                return true;
            }
        }

        return false;
    }

} // namespace Platform