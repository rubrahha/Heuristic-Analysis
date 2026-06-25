#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "IHeuristicRule.h"
#include "../core/ScanTarget.h"
#include <string_view>
#include <string>
#include <vector>

namespace Heuristics {

    // ---------------------------------------------------------------------------
    // ImportTableRule — API & Capability Heuristic
    //
    // Uses high-speed memory substring scanning to detect critical Windows API
    // strings. This acts as a proxy for reading the Import Address Table (IAT),
    // but is faster and highly resilient against basic IAT obfuscation and packers.
    // ---------------------------------------------------------------------------

    class ImportTableRule final : public IHeuristicRule {
    public:
        [[nodiscard]] int Evaluate(const Core::ScanTarget& target,
            std::vector<std::string>& indicators) override;

        [[nodiscard]] std::string_view GetName() const noexcept override { return "ImportTableRule"; }
        [[nodiscard]] int GetWeight() const noexcept override { return 30; }

        static constexpr int kMaxScore = 100;

    private:
        static constexpr uint16_t MAGIC_MZ = 0x5A4D;

        // Enterprise Standard: Centralized Scoring
        static constexpr int SCORE_DOTNET_EMIT = 45;
        static constexpr int SCORE_DOTNET_INJECT = 70;
        static constexpr int SCORE_DOTNET_LOAD = 35;

        static constexpr int SCORE_INJECT_WHITELIST = 10;
        static constexpr int SCORE_INJECT_SIGNED = 30;
        static constexpr int SCORE_INJECT_MALWARE = 80;

        static constexpr int SCORE_ANTI_DEBUG = 35;
        static constexpr int SCORE_CRED_THEFT = 65;
        static constexpr int SCORE_RANSOMWARE = 50;
        static constexpr int SCORE_NETWORK = 25;
        static constexpr int SCORE_KEYLOGGER = 55;
        static constexpr int SCORE_MANUAL_RESOLVER = 40;
    };

} // namespace Heuristics