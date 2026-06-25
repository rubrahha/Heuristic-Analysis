#include "PEHeaderRule.h"
#include "PEParser.h"
#include <algorithm>
#include <array>
#include <string_view>
#include <ranges>
#include <span>

namespace Heuristics {

    namespace {
        // Zero-allocation, compile-time array of legitimate code section names
        constexpr std::array<std::string_view, 8> kLegitSections = {
            ".text", ".itext", ".init", ".code", "CODE", "TEXT", ".ntext", ".textbss"
        };
    }

    // ---------------------------------------------------------------------------
    // Deterministic Time Conversion
    // Converts 100-nanosecond intervals since Jan 1, 1601 to seconds since 1970
    // ---------------------------------------------------------------------------
    uint64_t PEHeaderRule::FileTimeToUnixEpochSec(const FILETIME& ft) noexcept {
        ULARGE_INTEGER ul{};
        ul.HighPart = ft.dwHighDateTime;
        ul.LowPart = ft.dwLowDateTime;

        // 11644473600ULL is the exact number of seconds between 1601 and 1970
        return (ul.QuadPart / 10'000'000ULL) - 11'644'473'600ULL;
    }

    int PEHeaderRule::Evaluate(const Core::ScanTarget& target, std::vector<std::string>& indicators) {
        if (target.isRegistryKey) {
            return 0;
        }

        // ── 1. Zero-Copy I/O ──────────────────────────────────────────────────
        std::span<const uint8_t> fileView = target.GetMappedData();
        if (fileView.empty()) {
            return 0;
        }

        auto pe = PE::Parse(fileView);
        if (!pe.valid) {
            return 0;
        }

        int score = 0;

        // ── 2. Timestamp Anomaly Checks ───────────────────────────────────────
        if (pe.timestamp == 0) {
            // .NET linker and legitimate Go/Rust compilers often emit zero timestamp.
            // Open-source tools also zero it for reproducible builds.
            int ts_score = (pe.is_dotnet || target.trust.isSigned) ? SCORE_ZERO_TS_TRUSTED : SCORE_ZERO_TS_UNKNOWN;
            indicators.emplace_back("[PEHeaderRule] Compile timestamp is exactly zero");
            score += ts_score;
        }
        else {
            // Use deterministic scan time from the engine, not the live clock
            uint64_t nowSec = FileTimeToUnixEpochSec(target.scanStartTime);

            if (static_cast<uint64_t>(pe.timestamp) > (nowSec + ONE_DAY_SECONDS)) {
                indicators.emplace_back("[PEHeaderRule] Compile timestamp is in the future — forged header");
                score += SCORE_FUTURE_TS;
            }
            if (pe.timestamp > 0 && pe.timestamp < TIMESTAMP_PE_CREATION) {
                indicators.emplace_back("[PEHeaderRule] Compile timestamp predates PE format mass adoption (pre-1995)");
                score += SCORE_ANCIENT_TS;
            }
        }

        // ── 3. .NET Context Rules ─────────────────────────────────────────────
        if (pe.is_dotnet) {
            // Subsystem 1 == IMAGE_SUBSYSTEM_NATIVE (Device Drivers). .NET cannot be a ring-0 driver.
            if (pe.subsystem == 1) {
                indicators.emplace_back("[PEHeaderRule] .NET file claiming native driver subsystem — structurally malformed/evasive");
                score += SCORE_DOTNET_NATIVE_DRIVER;
            }
            // Exit early for .NET: ASLR/DEP/EP checks below don't apply to managed IL boundaries
            return std::min(score, kMaxScore);
        }

        // ── 4. ASLR (Address Space Layout Randomization) ──────────────────────
        bool hasASLR = (pe.dllChars & PE::PE_ASLR);

        if (pe.is64 && !pe.isDll && !hasASLR && !target.trust.isMinGW) {
            indicators.emplace_back("[PEHeaderRule] 64-bit executable without ASLR — highly unusual for modern software");
            score += SCORE_NO_ASLR_64;
        }
        else if (!pe.is64 && !pe.isDll && !hasASLR && target.isInHighRiskLocation && !target.trust.isMinGW) {
            indicators.emplace_back("[PEHeaderRule] 32-bit executable without ASLR residing in high-risk location");
            score += SCORE_NO_ASLR_32_RISKY;
        }

        // ── 5. DEP (Data Execution Prevention) ────────────────────────────────
        bool hasDEP = (pe.dllChars & PE::PE_NX);
        if (!pe.is64 && !hasDEP) {
            score += SCORE_NO_DEP;
        }

        // ── 6. Entry Point Boundary Verification ──────────────────────────────
        if (pe.epRva != 0 && !pe.sections.empty()) {
            bool epInLegit = false;

            for (const auto& sec : pe.sections) {
                // PE Section names are max 8 bytes and NOT guaranteed to be null-terminated.
                size_t nameLen = 0;
                while (nameLen < 8 && sec.name[nameLen] != '\0') {
                    ++nameLen;
                }
                std::string_view secName(sec.name, nameLen);

                // Check if secName starts with any known legitimate code prefixes
                bool matchesLegit = std::ranges::any_of(kLegitSections, [secName](std::string_view legit) {
                    return secName.starts_with(legit);
                    });

                if (matchesLegit && pe.epRva >= sec.vaddr && pe.epRva < (sec.vaddr + std::max(sec.vsize, sec.rawSize))) {
                    epInLegit = true;
                    break;
                }
            }

            if (!epInLegit && !target.trust.isSignatureValid) {
                indicators.emplace_back("[PEHeaderRule] Entry point outside known code sections — likely packed binary");
                score += SCORE_ABNORMAL_EP;
            }
        }

        // ── 7. Cap and Return ─────────────────────────────────────────────────
        return std::min(score, kMaxScore);
    }

} // namespace Heuristics