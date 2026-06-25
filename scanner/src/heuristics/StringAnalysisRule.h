// ─── heuristics/StringAnalysisRule.h ─────────────────────────────────────────
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "IHeuristicRule.h"
#include "../core/ScanTarget.h"

namespace Heuristics {

    class StringAnalysisRule final : public IHeuristicRule {
    public:
        [[nodiscard]] int Evaluate(const Core::ScanTarget& target, std::vector<std::string>& indicators) override;

        [[nodiscard]] std::string_view GetName() const noexcept override { return "StringAnalysisRule"; }
        [[nodiscard]] int GetWeight() const noexcept override { return 15; }

        static constexpr int kMaxScore = 100;

    private:
        static constexpr int SCORE_ANTI_VM = 50;
        static constexpr int SCORE_OFFENSIVE_TOOL = 90;
        static constexpr int SCORE_PS_DOWNLOADER = 65;
        static constexpr int SCORE_PERSISTENCE = 40;
        static constexpr int SCORE_RANSOMWARE = 75;
        static constexpr int SCORE_C2_DOMAIN = 55;

        static constexpr uint16_t MAGIC_MZ = 0x5A4D;
    };

} // namespace Heuristics