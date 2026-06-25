#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "IHeuristicRule.h"
#include "../core/ScanTarget.h"

namespace Heuristics {

    // ---------------------------------------------------------------------------
    // PEHeaderRule — Structural & Metadata Heuristic
    //
    // Analyzes the DOS and NT headers of a Portable Executable for anomalies
    // often introduced by malware packers, crypters, and custom compilers.
    // Includes ASLR/DEP capability checks, compile-time timestamp validation,
    // and Entry Point (OEP) boundary verification.
    // ---------------------------------------------------------------------------

    class PEHeaderRule final : public IHeuristicRule {
    public:
        [[nodiscard]] int Evaluate(const Core::ScanTarget& target,
            std::vector<std::string>& indicators) override;

        [[nodiscard]] std::string_view GetName() const noexcept override { return "PEHeaderRule"; }
        [[nodiscard]] int GetWeight() const noexcept override { return 15; }

        static constexpr int kMaxScore = 100;

    private:
        // Converts Windows FILETIME (1601 epoch) to Unix Epoch Seconds (1970 epoch)
        [[nodiscard]] static uint64_t FileTimeToUnixEpochSec(const FILETIME& ft) noexcept;

        // Enterprise Standard: Extracted Scoring Weights
        static constexpr int SCORE_ZERO_TS_TRUSTED = 5;
        static constexpr int SCORE_ZERO_TS_UNKNOWN = 20;
        static constexpr int SCORE_FUTURE_TS = 35;
        static constexpr int SCORE_ANCIENT_TS = 25;

        static constexpr int SCORE_DOTNET_NATIVE_DRIVER = 75; // Highly malformed

        static constexpr int SCORE_NO_ASLR_64 = 15;
        static constexpr int SCORE_NO_ASLR_32_RISKY = 8;
        static constexpr int SCORE_NO_DEP = 5;
        static constexpr int SCORE_ABNORMAL_EP = 40;

        // 788918400 = Jan 1, 1995 (Approximate mass adoption of PE32 format)
        static constexpr uint32_t TIMESTAMP_PE_CREATION = 788918400u;
        static constexpr uint64_t ONE_DAY_SECONDS = 86400ULL;
    };

} // namespace Heuristics