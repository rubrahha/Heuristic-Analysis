#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "IHeuristicRule.h"
#include "../core/ScanTarget.h"

namespace Heuristics {

    // ---------------------------------------------------------------------------
    // SignatureRule — Fast String & Artifact Heuristic
    //
    // Performs a high-speed, zero-allocation substring scan over the file buffer
    // looking for common malicious artifacts (e.g., encoded PowerShell commands,
    // privilege escalation requests, and embedded packer stubs).
    // ---------------------------------------------------------------------------

    class SignatureRule final : public IHeuristicRule {
    public:
        [[nodiscard]] int Evaluate(const Core::ScanTarget& target,
            std::vector<std::string>& indicators) override;

        [[nodiscard]] std::string_view GetName() const noexcept override { return "SignatureRule"; }
        [[nodiscard]] int GetWeight() const noexcept override { return 15; }

        static constexpr int kMaxScore = 100;
    };

} // namespace Heuristics