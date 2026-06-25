// See AgeRule.h for full design documentation.

#include "AgeRule.h"
#include "../platform/windows/FileSystem.h" // Ensure this path matches your structure

#include <algorithm>   // std::min
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace Heuristics {

    // ---------------------------------------------------------------------------
    // Time constants (100-nanosecond intervals, Windows FILETIME epoch)
    // ---------------------------------------------------------------------------
    static constexpr uint64_t kTicksPerSecond = 10'000'000ULL;
    static constexpr uint64_t kPerHour = kTicksPerSecond * 3'600ULL;
    static constexpr uint64_t kPerDay = kPerHour * 24ULL;

    // Clock-skew tolerance for "timestamp is in the future" checks.
    // Covers NTP drift (~1-5 s) and minor hypervisor clock jitter.
    static constexpr uint64_t kClockSkewTolerance = kTicksPerSecond * 30ULL;

    // ---------------------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------------------

    uint64_t AgeRule::FtToU64(const FILETIME& ft) noexcept {
        ULARGE_INTEGER ul{};              // zero-initialise — avoids UB on MSVC/GCC
        ul.HighPart = ft.dwHighDateTime;
        ul.LowPart = ft.dwLowDateTime;
        return ul.QuadPart;
    }

    bool AgeRule::IsZero(const FILETIME& ft) noexcept {
        return ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0;
    }

    // ---------------------------------------------------------------------------
    // Evaluate
    // ---------------------------------------------------------------------------

    int AgeRule::Evaluate(const Core::ScanTarget& target,
        std::vector<std::string>& indicators)
    {
        // ── Guard: this rule only applies to real files in high-risk locations ──
        if (target.isRegistryKey || !target.isInHighRiskLocation) {
            return 0;
        }

        // ── 1. Resolve timestamps ───────────────────────────────────────────────
        FILETIME creation = target.creationTime;
        FILETIME lastWrite = target.lastWriteTime;

        if (IsZero(creation)) {
            try {
                auto [c, w] = Platform::GetFileTimes(target.filePath);
                creation = c;
                lastWrite = w;
            }
            catch (const std::exception&) {
                // Locked file, access denied, etc. Fail open.
                return 0;
            }
        }

        // ── 2. "Now" must come from the scan-start snapshot ────────────────────
        const uint64_t nowVal = FtToU64(target.scanStartTime);
        const uint64_t creVal = FtToU64(creation);
        const uint64_t wrtVal = FtToU64(lastWrite);

        if (nowVal == 0) {
            return 0; // Engine failed to init scanStartTime
        }

        int score = 0;

        // ── 3 & 4. Future Creation OR Age-based scoring ────────────────────────
        if (creVal > nowVal + kClockSkewTolerance) {
            // A creation time in the future is a strong indicator of timestomping.
            indicators.emplace_back("[AgeRule] Creation timestamp is in the future — timestomping suspected");
            score += SCORE_FUTURE_CREATION;
        }
        else if (creVal != 0) {
            // Only process age bands if the creation time is not in the future
            const uint64_t age = nowVal - creVal;

            if (age < kPerHour) {
                indicators.emplace_back("[AgeRule] File created < 1 hour ago in high-risk location");
                score += SCORE_LESS_THAN_1H;
            }
            else if (age < kPerDay) {
                indicators.emplace_back("[AgeRule] File created < 24 hours ago in high-risk location");
                score += SCORE_LESS_THAN_24H;
            }
            else if (age < kPerDay * 7ULL) {
                indicators.emplace_back("[AgeRule] File created < 7 days ago in high-risk location");
                score += SCORE_LESS_THAN_7D;
            }
        }

        // ── 5. Future last-write timestamp ─────────────────────────────────────
        if (wrtVal != 0 && wrtVal > nowVal + kClockSkewTolerance) {
            indicators.emplace_back("[AgeRule] Last-write timestamp is in the future — timestomping suspected");
            score += SCORE_FUTURE_WRITE;
        }

        // ── 6. Identical creation and last-write on a recent file ──────────────
        if (creVal != 0 && wrtVal != 0 && wrtVal <= nowVal) {

            if (creVal == wrtVal) {
                const uint64_t age = (nowVal > creVal) ? (nowVal - creVal) : 0ULL;
                if (age < kPerDay) {
                    indicators.emplace_back(
                        "[AgeRule] Creation and last-write are identical on a "
                        "recently-dropped file — automated dropper pattern");
                    score += SCORE_IDENTICAL_TIMESTAMPS;
                }
            }
        }

        // ── 7. Long-lived file, very recently modified ─────────────────────────
        if (creVal != 0 && wrtVal != 0 && wrtVal <= nowVal && creVal <= nowVal) {
            const uint64_t fileAge = nowVal - creVal;
            const uint64_t writeAge = nowVal - wrtVal;

            if (fileAge > kPerDay * 30ULL && writeAge < kPerHour) {
                indicators.emplace_back(
                    "[AgeRule] File > 30 days old was modified < 1 hour ago in "
                    "high-risk location — possible DLL hijack or in-place patch");
                score += SCORE_OLD_FILE_RECENT_WRITE;
            }
        }

        // ── 8. Cap and return ──────────────────────────────────────────────────
        return std::min(score, kMaxScore);
    }

} // namespace Heuristics