#include "HeuristicEngine.h"

// Rule Includes
#include "EntropyRule.h"
#include "SectionRule.h"
#include "ImportTableRule.h"
#include "PEHeaderRule.h"
#include "StringAnalysisRule.h"
#include "OverlayRule.h"
#include "FileTypeRule.h"
#include "LocationRule.h"
#include "AgeRule.h"
#include "SignatureRule.h"
#include "PersistenceRule.h"

#include <algorithm>
#include <chrono>
#include <format>
#include <stdexcept>
#include <windows.h> // Required for GetSystemTimeAsFileTime

namespace Heuristics {

    void HeuristicEngine::RegisterRule(std::unique_ptr<IHeuristicRule> rule) {
        if (rule) {
            rules_.emplace_back(std::move(rule));
        }
    }

    void HeuristicEngine::RegisterDefaultRules() {
        rules_.clear();
        rules_.reserve(11);

        RegisterRule(std::make_unique<EntropyRule>());
        RegisterRule(std::make_unique<SectionRule>());
        RegisterRule(std::make_unique<ImportTableRule>());
        RegisterRule(std::make_unique<PEHeaderRule>());
        RegisterRule(std::make_unique<StringAnalysisRule>());
        RegisterRule(std::make_unique<OverlayRule>());
        RegisterRule(std::make_unique<FileTypeRule>());
        RegisterRule(std::make_unique<LocationRule>());
        RegisterRule(std::make_unique<AgeRule>());
        RegisterRule(std::make_unique<SignatureRule>());
        RegisterRule(std::make_unique<PersistenceRule>());
    }

    Core::ScanResult HeuristicEngine::Analyze(Core::ScanTarget& target) {
        const auto startTime = std::chrono::steady_clock::now();

        Core::ScanResult result;
        result.targetPath = target.filePath;

        // ── Step 1: Whitelist check ───────────────────────────────────────────
        WhitelistResult wl = WhitelistManager::Check(target);
        if (wl.whitelisted) {
            result.riskScore = SCORE_MIN;
            result.indicators.emplace_back(wl.reason);

            if (!wl.matchedHash.empty()) {
                result.indicators.emplace_back(std::format("[Whitelist] Hash: {}", wl.matchedHash));
            }

            result.Finalize();
            result.scanDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime);
            return result;
        }

        // ── Step 2: Engine Pre-Flight Initialization (Moved UP) ───────────────
        if (target.scanStartTime.dwHighDateTime == 0 && target.scanStartTime.dwLowDateTime == 0) {
            ::GetSystemTimeAsFileTime(&target.scanStartTime);
        }
        if (!target.isRegistryKey) {
            target.MapFileToMemory(); // File is now mapped!
        }

   
        // ── Step 2: TrustAnalyzer ─────────────────────────────────────────────
        TrustAnalyzer::Analyze(target);

        if (target.trust.isSignatureValid &&
            target.trust.trustModifier <= TRUST_BYPASS_THRESHOLD &&
            !target.isInHighRiskLocation) {

            result.riskScore = SCORE_MIN;
            result.indicators.emplace_back(std::format(
                "[Trust] Valid signature from trusted publisher: {}", target.trust.signerName));

            result.Finalize();
            result.scanDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime);
            return result;
        }

        // ── Step 3: Engine Pre-Flight Initialization ──────────────────────────

        // 3a. Lock in the deterministic scan time for temporal rules (AgeRule)
        //if (target.scanStartTime.dwHighDateTime == 0 && target.scanStartTime.dwLowDateTime == 0) {
           // ::GetSystemTimeAsFileTime(&target.scanStartTime);
       // }

        // 3b. Ensure memory-mapped zero-copy buffer is initialized once before the loop
        // (Assuming you implement a map method on ScanTarget to prepare GetMappedData())
       // if (!target.isRegistryKey) {
        //    target.MapFileToMemory();
       // }

        // ── Step 4: Execute Heuristic Pipeline (Fault-Tolerant) ───────────────
        int totalWeight = 0;
        int weightedScore = 0;

        for (const auto& rule : rules_) {
            std::vector<std::string> ind;
            int raw = 0;
            int weight = rule->GetWeight();

            try {
                // Execute rule safely
                raw = std::clamp(rule->Evaluate(target, ind), SCORE_MIN, SCORE_MAX);
            }
            catch (const std::exception& e) {
                // Fault Tolerance: Log the crash, but keep scanning with the next rule
                result.indicators.emplace_back(std::format(
                    "[Engine] WARNING: Rule '{}' crashed during evaluation: {}",
                    rule->GetName(), e.what()));
                continue;
            }
            catch (...) {
                // Catch structured exceptions (SEH) or non-standard throws
                result.indicators.emplace_back(std::format(
                    "[Engine] CRITICAL: Rule '{}' encountered an unknown memory violation.",
                    rule->GetName()));
                continue;
            }

            weightedScore += (raw * weight);
            totalWeight += weight;

            // Use string_view directly if your ScanResult map supports it, 
            // otherwise construct string only when strictly necessary.
            result.ruleContributions[std::string(rule->GetName())] = raw;

            // Move semantics: transfer strings without copying memory
            for (auto& s : ind) {
                result.indicators.emplace_back(std::move(s));
            }
        }

        result.riskScore = (totalWeight > 0) ? std::min(SCORE_MAX, weightedScore / totalWeight) : SCORE_MIN;

        // ── Step 5: Apply Trust Modifiers ─────────────────────────────────────
        if (target.trust.trustModifier < 0 && result.riskScore > 0) {

            result.riskScore = std::clamp(result.riskScore + target.trust.trustModifier, 1, SCORE_MAX);

            if (target.trust.isSignatureValid && !target.trust.signerName.empty()) {
                result.indicators.emplace_back(std::format(
                    "[Trust] Risk mitigated — valid signature: {}", target.trust.signerName));
            }
            else if (target.trust.isSigned) {
                result.indicators.emplace_back("[Trust] Risk mitigated — signed binary (unrecognized publisher)");
            }

            if (target.trust.isInstaller) {
                result.indicators.emplace_back("[Trust] Context applied — installer package (high entropy expected)");
            }

            if (target.trust.isGameEngine) {
                result.indicators.emplace_back("[Trust] Context applied — game engine detected (anti-cheat APIs expected)");
            }

            if (target.trust.isElectron) {
                result.indicators.emplace_back("[Trust] Context applied — Electron app (bundled JS causes high entropy)");
            }
        }

        // ── Step 6: Teardown and Finalize ─────────────────────────────────────

        // Release the memory-mapped file handle before finalizing
        target.UnmapFileFromMemory();

        result.Finalize();
        result.scanDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime);

        return result;
    }

} // namespace Heuristics