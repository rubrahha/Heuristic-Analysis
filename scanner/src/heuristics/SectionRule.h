#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "IHeuristicRule.h"
#include "../core/ScanTarget.h"

namespace Heuristics {

    // ---------------------------------------------------------------------------
    // SectionRule — Memory Geometry & Packer Heuristic
    //
    // Analyzes the structural sections of a PE file. Detects W+X memory
    // anomalies (self-modifying code), Virtual Size vs Raw Size discrepancies
    // (memory decompression stubs), and known packer signatures.
    // ---------------------------------------------------------------------------

    class SectionRule final : public IHeuristicRule {
    public:
        [[nodiscard]] int Evaluate(const Core::ScanTarget& target,
            std::vector<std::string>& indicators) override;

        [[nodiscard]] std::string_view GetName() const noexcept override { return "SectionRule"; }
        [[nodiscard]] int GetWeight() const noexcept override { return 20; }

        static constexpr int kMaxScore = 100;

    private:
        // Enterprise Standard: Extracted Scoring Weights
        static constexpr int SCORE_WX_SECTION = 60;
        static constexpr int SCORE_PACKER_NAME = 50;
        static constexpr int SCORE_HIGH_ENTROPY = 55;
        static constexpr int SCORE_VSIZE_ANOMALY = 40;
        static constexpr int SCORE_HIGH_SEC_COUNT = 25;

        static constexpr double ENTROPY_THRESH_NATIVE = 7.2;
        static constexpr double ENTROPY_THRESH_DOTNET = 7.7;

        static constexpr uint32_t VSIZE_MULT_NATIVE = 10;
        static constexpr uint32_t VSIZE_MULT_DOTNET = 50;

        static constexpr uint16_t MAX_NORMAL_SECTIONS = 12;
    };

} // namespace Heuristics