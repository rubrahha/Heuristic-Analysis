#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "ScanTarget.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <filesystem> // ADDED

namespace Core {

    struct ScanResult {
        // FIXED: Store just the path, not the uncopyable ScanTarget object
        std::filesystem::path targetPath;

        int         riskScore = 0;
        std::string verdict;

        std::vector<std::string>             indicators;
        std::unordered_map<std::string, int> ruleContributions;

        std::chrono::milliseconds scanDuration{ 0 };

        void Finalize();
        [[nodiscard]] std::string ToJson() const;

        // FIXED: Moved to public so main.cpp can use it for error handling
        [[nodiscard]] static std::string EscapeJsonString(const std::string& input);
    };

} // namespace Core