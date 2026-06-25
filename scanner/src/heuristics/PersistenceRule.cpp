#include "PersistenceRule.h"
#include "../platform/windows/Registry.h" // Assumes cached O(1) lookups
#include "../utils/StringUtils.h"
#include <algorithm>
#include <array>
#include <string_view>

namespace Heuristics {

    namespace {
        // Enterprise Standard: constexpr arrays for zero-allocation lookup
        constexpr std::array<std::wstring_view, 3> kRunKeys = {
            L"software\\microsoft\\windows\\currentversion\\run",
            L"software\\microsoft\\windows\\currentversion\\runonce",
            L"software\\wow6432node\\microsoft\\windows\\currentversion\\run"
        };
    } // namespace

    int PersistenceRule::Evaluate(const Core::ScanTarget& target, std::vector<std::string>& indicators) {
        int score = 0;

        // ── Scenario 1: The target is a Registry Key ──────────────────────────
        if (target.isRegistryKey) {
            // Allocate once for the key (keys are short, so this is acceptable)
            std::wstring lowKey = Utils::ToLower(target.registryKey);

            for (const auto& runKey : kRunKeys) {
                if (lowKey.find(runKey) != std::wstring::npos) {
                    indicators.emplace_back("[PersistenceRule] Registry target is a known auto-run persistence key");
                    score += SCORE_RUN_KEY_TARGET;
                    break; // Only trigger once
                }
            }
            return std::min(score, kMaxScore);
        }

        // ── Scenario 2: The target is a File on Disk ──────────────────────────

        // This assumes Platform::FileIsInRunKey is backed by an O(1) cached snapshot, 
        // NOT a live registry query per file.
        if (Platform::FileIsInRunKey(target.filePath.wstring())) {

            // DRY Principle: Utilize the boolean already calculated by the Engine
            if (target.isInHighRiskLocation) {
                indicators.emplace_back(
                    "[PersistenceRule] File registered in Run key AND located in a high-risk path (e.g., Temp/AppData) — strong persistence indicator");
                score += SCORE_RUN_KEY_HIGH_RISK;
            }
            else {
                indicators.emplace_back(
                    "[PersistenceRule] File registered in registry Run key — auto-starts on login");
                score += SCORE_RUN_KEY_STANDARD;
            }
        }

        return std::min(score, kMaxScore);
    }

} // namespace Heuristics