#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <vector>
#include <memory>
#include <string>
#include <filesystem>
#include "IHeuristicRule.h"
#include "WhitelistManager.h"
#include "TrustAnalyzer.h"
#include "../core/ScanResult.h" // Adjusted path based on your tree

namespace Heuristics {

    class HeuristicEngine final {
    public:
        void RegisterRule(std::unique_ptr<IHeuristicRule> rule);
        void RegisterDefaultRules();

        // [[nodiscard]] forces the caller (e.g., your Python bridge) to handle the result
        [[nodiscard]] Core::ScanResult Analyze(Core::ScanTarget& target);

        static void AddTrustedPath(const std::wstring& p) { WhitelistManager::AddTrustedPath(p); }
        static void AddKnownGoodHash(const std::string& h) { WhitelistManager::AddKnownGoodHash(h); }

        [[nodiscard]] static std::string ComputeFileHash(const std::filesystem::path& p) {
            return WhitelistManager::ComputeSHA256(p);
        }

    private:
        std::vector<std::unique_ptr<IHeuristicRule>> rules_;

        // Enterprise Standard: Centralized thresholds
        static constexpr int SCORE_MAX = 100;
        static constexpr int SCORE_MIN = 0;

        // If a signed file drops the score by this much, we skip heuristic rules entirely
        static constexpr int TRUST_BYPASS_THRESHOLD = -60;
    };

} // namespace Heuristics