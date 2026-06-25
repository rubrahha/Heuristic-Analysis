#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <string_view>
#include <vector>

namespace Platform {

    struct RegValue {
        std::wstring name;
        std::wstring data;
    };

    // [[nodiscard]] forces the caller to actually handle the read registry values
    [[nodiscard]] std::vector<RegValue> ReadRegistryValues(HKEY root, std::wstring_view subKey);

    // Determines if a file is established in an Auto-Start location.
    // Optimized: Performs a live registry query on the FIRST call only, then caches 
    // the results in RAM for lightning-fast O(1) lookups during the rest of the scan.
    [[nodiscard]] bool FileIsInRunKey(std::wstring_view filePath);

} // namespace Platform