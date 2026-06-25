#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include "IHeuristicRule.h"
#include "../core/ScanTarget.h"

namespace Heuristics {

    class EntropyRule final : public IHeuristicRule {
    public:
        [[nodiscard]] int Evaluate(const Core::ScanTarget& target,
            std::vector<std::string>& indicators) override;

        [[nodiscard]] std::string_view GetName() const noexcept override { return "EntropyRule"; }
        [[nodiscard]] int GetWeight() const noexcept override { return 25; }

        // Core Math: Exposed publicly for potential use by unit tests
        [[nodiscard]] static double CalculateShannonEntropy(std::span<const uint8_t> data) noexcept;

    private:
        // Maximum bytes to process for full-file entropy to prevent CPU denial-of-service
        static constexpr size_t MAX_ENTROPY_BYTES = 1024 * 1024 * 5; // 5 MB

        // Enterprise Standard: Centralized thresholds
        static constexpr double THRESHOLD_DOTNET = 7.8;
        static constexpr double THRESHOLD_ELECTRON = 7.9;
        static constexpr double THRESHOLD_INSTALLER = 7.9;
        static constexpr double THRESHOLD_GAME_ENGINE = 7.9;

        // Native PE thresholds
        static constexpr double THRESHOLD_NATIVE_CRITICAL = 7.5;
        static constexpr double THRESHOLD_NATIVE_HIGH = 7.2;
        static constexpr double THRESHOLD_NATIVE_ELEVATED = 6.8;
    };

} // namespace Heuristics