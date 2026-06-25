#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <span>
#include "IHeuristicRule.h"
#include "../core/ScanTarget.h"

namespace Heuristics {

    // ---------------------------------------------------------------------------
    // FileTypeRule — Metadata & Extension Heuristic
    //
    // Detects anomalies between a file's physical structure and its naming
    // conventions. Key detections:
    //   • Disguised Executables (e.g., a PE file named "document.pdf")
    //   • Social Engineering Naming (e.g., "invoice.pdf.exe")
    //   • Dangerous scripts resting in high-risk delivery locations.
    // ---------------------------------------------------------------------------

    class FileTypeRule final : public IHeuristicRule {
    public:
        [[nodiscard]] int Evaluate(const Core::ScanTarget& target,
            std::vector<std::string>& indicators) override;

        [[nodiscard]] std::string_view GetName() const noexcept override { return "FileTypeRule"; }
        [[nodiscard]] int GetWeight() const noexcept override { return 15; }

        static constexpr int kMaxScore = 100;

    private:
        [[nodiscard]] static bool IsDangerousExt(std::wstring_view ext) noexcept;
        [[nodiscard]] static bool IsBenignExt(std::wstring_view ext) noexcept;

        // Checks for decoy patterns (e.g. .pdf.exe)
        [[nodiscard]] static bool HasDecoyDoubleExt(const std::filesystem::path& path);

        // Scoring Weights
        static constexpr int SCORE_DISGUISED_EXE = 85;
        static constexpr int SCORE_RISKY_SCRIPT = 35;
        static constexpr int SCORE_DOUBLE_EXT = 40;
        static constexpr int SCORE_LONG_NAME = 15;

        // Magic Bytes
        static constexpr uint16_t MAGIC_MZ = 0x5A4D; // "MZ"

        // Character count thresholds
        static constexpr size_t SUSPICIOUS_NAME_LENGTH = 64;
    };

} // namespace Heuristics