#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "IHeuristicRule.h"
#include "../core/ScanTarget.h"

namespace Heuristics {

    // ---------------------------------------------------------------------------
    // OverlayRule — Appended Data Heuristic
    //
    // Analyzes data appended outside of the declared PE sections (the overlay).
    // Malware heavily uses overlays to hide encrypted payloads, secondary binaries,
    // or configuration files. Legitimate software uses it for Installers, Game 
    // Assets, and Authenticode Digital Signatures.
    // ---------------------------------------------------------------------------

    class OverlayRule final : public IHeuristicRule {
    public:
        [[nodiscard]] int Evaluate(const Core::ScanTarget& target,
            std::vector<std::string>& indicators) override;

        [[nodiscard]] std::string_view GetName() const noexcept override { return "OverlayRule"; }
        [[nodiscard]] int GetWeight() const noexcept override { return 10; }

        static constexpr int kMaxScore = 100;

    private:
        // Enterprise Standard: Centralized Scoring Weights
        static constexpr int SCORE_EMBEDDED_PE_MALWARE = 85;
        static constexpr int SCORE_EMBEDDED_PE_SIGNED = 20;
        static constexpr int SCORE_EMBEDDED_ARCHIVE_DROPPER = 50;
        static constexpr int SCORE_EMBEDDED_ARCHIVE_TRUSTED = 5;
        static constexpr int SCORE_HIGH_ENTROPY_PAYLOAD = 60;
        static constexpr int SCORE_LARGE_UNKNOWN_BLOCK = 15;

        // Thresholds
        static constexpr double THRESHOLD_ENTROPY = 7.0;
        static constexpr size_t MIN_OVERLAY_SIZE = 512; // Ignore tiny padding blocks
        static constexpr size_t LARGE_BLOCK_SIZE = 65536; // 64 KB
    };

} // namespace Heuristics