#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "IHeuristicRule.h"
#include "../core/ScanTarget.h"
#include <string_view>
#include <vector>
#include <string>

namespace Heuristics {

    // ---------------------------------------------------------------------------
    // PersistenceRule — Auto-Start & Registry Heuristic
    //
    // Evaluates whether a scanned file has established a foothold in the system
    // via Windows Auto-Start Extensibility Points (ASEPs), primarily the Run keys.
    // Also capable of scoring the registry keys themselves if the engine is in
    // Registry-Scan mode.
    // ---------------------------------------------------------------------------

    class PersistenceRule final : public IHeuristicRule {
    public:
        [[nodiscard]] int Evaluate(const Core::ScanTarget& target,
            std::vector<std::string>& indicators) override;

        [[nodiscard]] std::string_view GetName() const noexcept override { return "PersistenceRule"; }
        [[nodiscard]] int GetWeight() const noexcept override { return 15; }

        static constexpr int kMaxScore = 100;

    private:
        // Enterprise Standard: Centralized Scoring Weights
        static constexpr int SCORE_RUN_KEY_TARGET = 35;
        static constexpr int SCORE_RUN_KEY_HIGH_RISK = 50;
        static constexpr int SCORE_RUN_KEY_STANDARD = 25;
    };

} // namespace Heuristics