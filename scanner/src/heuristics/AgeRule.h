#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include "IHeuristicRule.h"
#include "../core/ScanTarget.h" // Ensure this path matches your project structure

namespace Heuristics {

    // ---------------------------------------------------------------------------
    // AgeRule — Timestamps & Age Heuristic
    //
    // Scores a PE/file target based on temporal anomalies that are
    // disproportionately associated with malware delivery and evasion:
    //
    //   • Very recent creation time in a high-risk location
    //   • Future-dated creation or last-write timestamps (timestomping)
    //   • Identical creation + last-write on a recently-dropped file (dropper pattern)
    //   • Long-lived file modified < 1 hour ago (DLL hijack / in-place patching)
    //
    // Design invariants:
    //   • "Now" must come from ScanTarget::scanStartTime, NOT from a live WinAPI
    //     call, so that the rule is 100% deterministic and unit-testable.
    //   • Independent anomalies ADD to the score; they are not max'd.
    //   • Total score is capped at kMaxScore to prevent a single rule from
    //     dominating the engine's total risk budget.
    // ---------------------------------------------------------------------------

    class AgeRule final : public IHeuristicRule {
    public:
        [[nodiscard]] int Evaluate(const Core::ScanTarget& target,
            std::vector<std::string>& indicators) override;

        [[nodiscard]] std::string_view GetName() const noexcept override { return "AgeRule"; }

        // Weight is intentionally 1: scores already encode risk magnitude.
        [[nodiscard]] int GetWeight() const noexcept override { return 1; }

        // Maximum score this rule can contribute to the engine total.
        static constexpr int kMaxScore = 60;

    private:
        // Converts a FILETIME to a comparable uint64 (100-ns ticks since Jan 1 1601).
        [[nodiscard]] static uint64_t FtToU64(const FILETIME& ft) noexcept;

        // Returns true when both DWORD fields are zero (uninitialised / read failure).
        [[nodiscard]] static bool IsZero(const FILETIME& ft) noexcept;

        // -----------------------------------------------------------------------
        // Scoring weights
        // -----------------------------------------------------------------------
        static constexpr int SCORE_LESS_THAN_1H = 20; // Mutually exclusive age bands
        static constexpr int SCORE_LESS_THAN_24H = 12;
        static constexpr int SCORE_LESS_THAN_7D = 5;
        static constexpr int SCORE_FUTURE_CREATION = 25; // Independent of age band
        static constexpr int SCORE_FUTURE_WRITE = 15; // Independent
        static constexpr int SCORE_IDENTICAL_TIMESTAMPS = 8; // creation == write on new file
        static constexpr int SCORE_OLD_FILE_RECENT_WRITE = 15; // DLL hijack / in-place patch
    };

} // namespace Heuristics