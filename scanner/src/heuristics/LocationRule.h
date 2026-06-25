#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "IHeuristicRule.h"
#include "../core/ScanTarget.h"

namespace Heuristics {

    // ---------------------------------------------------------------------------
    // LocationRule — Execution Context Heuristic
    //
    // Scores a binary based on its physical location on disk. Malware frequently
    // drops payloads into user-writable directories (Temp, AppData) or persistence
    // locations (Startup) to bypass User Account Control (UAC).
    // ---------------------------------------------------------------------------

    class LocationRule final : public IHeuristicRule {
    public:
        [[nodiscard]] int Evaluate(const Core::ScanTarget& target,
            std::vector<std::string>& indicators) override;

        [[nodiscard]] std::string_view GetName() const noexcept override { return "LocationRule"; }
        [[nodiscard]] int GetWeight() const noexcept override { return 15; }

        static constexpr int kMaxScore = 100;
    };

} // namespace Heuristics