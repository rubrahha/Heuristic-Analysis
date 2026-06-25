#pragma once

#include "core/ScanTarget.h"
#include <string>
#include <string_view> // C++17/20 Zero-allocation strings
#include <vector>

namespace Heuristics {

    class IHeuristicRule {
    public:
        virtual ~IHeuristicRule() = default;

        // [[nodiscard]] forces the engine to actually use the returned score
        [[nodiscard]] virtual int Evaluate(const Core::ScanTarget& target,
            std::vector<std::string>& indicators) = 0;

        // Enterprise Standard: string_view prevents heap allocation during logging
        [[nodiscard]] virtual std::string_view GetName() const noexcept = 0;

        // noexcept guarantees this simple getter will never crash the program
        [[nodiscard]] virtual int GetWeight() const noexcept = 0;
    };

} // namespace Heuristics