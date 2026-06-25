#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <string_view>
#include <algorithm>
#include <ranges>

namespace Utils {

    // [[nodiscard]] ensures the caller doesn't accidentally ignore the transformed string
    [[nodiscard]] inline std::string ToLower(std::string s) {
        std::ranges::transform(s, s.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
            });
        return s;
    }

    [[nodiscard]] inline std::wstring ToLower(std::wstring s) {
        std::ranges::transform(s, s.begin(), ::towlower);
        return s;
    }

    // THE GLOBAL FIX: Native WinAPI UTF-8 Conversion
    [[nodiscard]] inline std::string WstrToStr(std::wstring_view ws) {
        if (ws.empty()) return {};

        // 1. Ask Windows exactly how many bytes we need for the UTF-8 string
        int size_needed = ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
        if (size_needed <= 0) return {};

        // 2. Allocate exactly that amount (memory safe)
        std::string result(size_needed, 0);

        // 3. Perform the actual conversion
        ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), result.data(), size_needed, nullptr, nullptr);

        return result;
    }

    [[nodiscard]] inline std::wstring StrToWstr(std::string_view s) {
        if (s.empty()) return {};

        int size_needed = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
        if (size_needed <= 0) return {};

        std::wstring result(size_needed, 0);
        ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), result.data(), size_needed);

        return result;
    }

    // THE STACK OVERFLOW FIX: Dynamic sizing instead of massive fixed buffers
    [[nodiscard]] inline std::wstring ExpandEnvVars(std::wstring_view path) {
        if (path.empty()) return {};

        // WinAPI requires a null-terminated string, so we construct one from the view
        std::wstring null_term_path(path);

        // Calling with nullptr returns the exact buffer size required
        DWORD req_size = ::ExpandEnvironmentStringsW(null_term_path.c_str(), nullptr, 0);
        if (req_size == 0) return null_term_path; // Fallback to original on failure

        // req_size includes the null terminator, which std::wstring handles automatically
        std::wstring result(req_size - 1, L'\0');
        ::ExpandEnvironmentStringsW(null_term_path.c_str(), result.data(), req_size);

        return result;
    }

    // Enterprise Standard: Using string_view avoids expensive string copies during path checks.
    // Note: This implements a Case-Insensitive check, as required by Windows filesystems.
    [[nodiscard]] inline bool StartsWithW_i(std::wstring_view str, std::wstring_view prefix) {
        if (prefix.size() > str.size()) return false;

        return std::ranges::equal(prefix, str.substr(0, prefix.size()),
            [](wchar_t a, wchar_t b) { return ::towlower(a) == ::towlower(b); });
    }

    [[nodiscard]] inline bool StartsWithA_i(std::string_view str, std::string_view prefix) {
        if (prefix.size() > str.size()) return false;

        return std::ranges::equal(prefix, str.substr(0, prefix.size()),
            [](unsigned char a, unsigned char b) { return std::tolower(a) == std::tolower(b); });
    }

} // namespace Utils