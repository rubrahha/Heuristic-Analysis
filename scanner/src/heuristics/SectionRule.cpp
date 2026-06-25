#include "SectionRule.h"
#include "PEParser.h"
#include "EntropyRule.h" // DRY Principle: Reuse centralized math
#include <algorithm>
#include <array>
#include <format>
#include <string_view>
#include <ranges>
#include <span>

namespace Heuristics {

    namespace {
        // Zero-allocation, compile-time array of known packer/protector section names
        constexpr std::array<std::string_view, 11> kPackerNames = {
            "UPX0", "UPX1", "UPX2", ".MPRESS1", ".MPRESS2",
            "ASPack", "PECompact", "Themida", "WinLicense", "Enigma", ".packed"
        };
    }

    int SectionRule::Evaluate(const Core::ScanTarget& target, std::vector<std::string>& indicators) {
        if (target.isRegistryKey) {
            return 0;
        }

        // ── 1. Zero-Copy I/O ──────────────────────────────────────────────────
        std::span<const uint8_t> fileView = target.GetMappedData();
        if (fileView.empty()) {
            return 0;
        }

        auto pe = PE::Parse(fileView);

        if (!pe.valid || pe.sections.empty()) {
            return 0;
        }

        int score = 0;

        for (const auto& sec : pe.sections) {

            // pe.sections guarantees s.name is null-terminated due to our custom strncpy_s
            std::string_view sname(sec.name);

            // ── 2. W+X (Writable & Executable) Memory ─────────────────────────
            // .NET Note: Static W+X in the section table of a .NET file is still highly suspicious.
            if (sec.IsExec() && sec.IsWrite()) {
                indicators.emplace_back(std::format(
                    "[SectionRule] W+X section '{}' — writable executable memory (self-modifying or injected code)",
                    sname));
                score += SCORE_WX_SECTION;
            }

            // ── 3. Known Packer Signatures ────────────────────────────────────
            bool hasPackerName = std::ranges::any_of(kPackerNames, [sname](std::string_view pn) {
                return sname.find(pn) != std::string_view::npos;
                });

            if (hasPackerName) {
                indicators.emplace_back(std::format(
                    "[SectionRule] Packer/Protector section name '{}' detected", sname));
                score += SCORE_PACKER_NAME;
            }

            // ── 4. Localized Section Entropy ──────────────────────────────────
            if (sec.rawPtr > 0 && sec.rawSize > 0 &&
                (sec.rawPtr + sec.rawSize <= fileView.size()) && sec.IsExec()) {

                // Exclude the primary .text section for .NET files (they are naturally high-entropy IL)
                bool is_dotnet_text = pe.is_dotnet && sname.starts_with(".text");

                if (!is_dotnet_text) {
                    std::span<const uint8_t> secData = fileView.subspan(sec.rawPtr, sec.rawSize);
                    double H = EntropyRule::CalculateShannonEntropy(secData);
                    double threshold = pe.is_dotnet ? ENTROPY_THRESH_DOTNET : ENTROPY_THRESH_NATIVE;

                    if (H > threshold) {
                        indicators.emplace_back(std::format(
                            "[SectionRule] High-entropy executable section '{}' ({:.2f}/8.0) — highly indicative of encrypted/packed code",
                            sname, H));
                        score += SCORE_HIGH_ENTROPY;
                    }
                }
            }

            // ── 5. Virtual Size vs Raw Size Anomaly ───────────────────────────
            // Packer hallmark: A tiny raw footprint on disk that expands into a massive virtual buffer in RAM.
            if (sec.rawSize > 0) {
                uint32_t multiplier = pe.is_dotnet ? VSIZE_MULT_DOTNET : VSIZE_MULT_NATIVE;
                if (sec.vsize > (sec.rawSize * multiplier)) {
                    indicators.emplace_back(std::format(
                        "[SectionRule] Section '{}' virtual size expands massively beyond disk size — classic unpacking stub",
                        sname));
                    score += SCORE_VSIZE_ANOMALY;
                }
            }
        }

        // ── 6. Structural Obfuscation (High Section Count) ────────────────────
        if (pe.numSections > MAX_NORMAL_SECTIONS) {
            indicators.emplace_back(std::format(
                "[SectionRule] Unusually high section count ({}) — possible structural obfuscation",
                pe.numSections));
            score += SCORE_HIGH_SEC_COUNT;
        }

        return std::min(score, kMaxScore);
    }

} // namespace Heuristics