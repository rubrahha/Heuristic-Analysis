#include "EntropyRule.h"
#include "PEParser.h" // Assuming this still provides target.trust / is_dotnet context
#include <algorithm>
#include <format>
#include <cmath>

namespace Heuristics {

    // ---------------------------------------------------------------------------
    // CalculateShannonEntropy
    // High-performance C++20 implementation. Processes arrays in a single pass.
    // ---------------------------------------------------------------------------
    double EntropyRule::CalculateShannonEntropy(std::span<const uint8_t> data) noexcept {
        if (data.empty()) {
            return 0.0;
        }

        size_t counts[256] = { 0 };
        for (const uint8_t byte : data) {
            counts[byte]++;
        }

        double entropy = 0.0;
        const double invSize = 1.0 / static_cast<double>(data.size());

        for (const size_t count : counts) {
            if (count > 0) {
                const double p = static_cast<double>(count) * invSize;
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }

    // ---------------------------------------------------------------------------
    // Evaluate
    // ---------------------------------------------------------------------------
    int EntropyRule::Evaluate(const Core::ScanTarget& target, std::vector<std::string>& indicators) {
        if (target.isRegistryKey) {
            return 0;
        }

        // ARCHITECTURE FIX: Zero-copy memory span instead of disk I/O
        std::span<const uint8_t> fileView = target.GetMappedData();
        if (fileView.empty() || fileView.size() < sizeof(IMAGE_DOS_HEADER)) {
            return 0;
        }

        // Safe DOS Header check using standard pointer arithmetic (no reinterpret_cast UB on unaligned spans)
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileView.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return 0; // Not a PE file, entropy analysis relies on structural context
        }

        // 1. Calculate Full File Entropy (capped for performance)
        const size_t bytesToAnalyze = std::min(fileView.size(), MAX_ENTROPY_BYTES);
        double maxEntropy = CalculateShannonEntropy(fileView.subspan(0, bytesToAnalyze));
        std::string highestEntropySource = "Full File";

        // 2. Safe PE Section iteration to find localized high entropy (The Anti-Dilution Fix)
        if (dosHeader->e_lfanew > 0 && dosHeader->e_lfanew < fileView.size() - sizeof(IMAGE_NT_HEADERS32)) {
            const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(fileView.data() + dosHeader->e_lfanew);

            if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                const WORD numSections = ntHeaders->FileHeader.NumberOfSections;

                // Locate the section table directly after the NT headers
                const size_t sectionTableOffset = dosHeader->e_lfanew +
                    offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
                    ntHeaders->FileHeader.SizeOfOptionalHeader;

                if (sectionTableOffset + (numSections * sizeof(IMAGE_SECTION_HEADER)) <= fileView.size()) {
                    const auto* sectionHeaders = reinterpret_cast<const IMAGE_SECTION_HEADER*>(fileView.data() + sectionTableOffset);

                    for (WORD i = 0; i < numSections; ++i) {
                        const IMAGE_SECTION_HEADER& sec = sectionHeaders[i];

                        // Only analyze sections that actually have raw data on disk
                        if (sec.SizeOfRawData > 0 && (sec.PointerToRawData + sec.SizeOfRawData) <= fileView.size()) {
                            std::span<const uint8_t> secData = fileView.subspan(sec.PointerToRawData, sec.SizeOfRawData);
                            double secEntropy = CalculateShannonEntropy(secData);

                            // Keep track of the highest entropy found
                            if (secEntropy > maxEntropy) {
                                maxEntropy = secEntropy;
                                // safely copy the 8-byte section name (not always null-terminated)
                                char nameBuf[9] = { 0 };
                                std::memcpy(nameBuf, sec.Name, 8);
                                highestEntropySource = std::format("Section '{}'", nameBuf);
                            }
                        }
                    }
                }
            }
        }

        // We still rely on the parser for behavioral context (.NET, Electron, etc.)
        // Ensure PE::Parse utilizes the zero-copy target buffer.
        auto peContext = PE::Parse(fileView);

        // Context-Aware Evaluation utilizing the max entropy found (either file or specific section)

        if (peContext.is_dotnet) {
            if (maxEntropy > THRESHOLD_DOTNET) {
                indicators.emplace_back(std::format(
                    "[EntropyRule] High entropy {:.2f}/8.0 in {} (.NET) — unusual even for managed code",
                    maxEntropy, highestEntropySource));
                return 60;
            }
            return 0;
        }

        if (target.trust.isElectron) {
            if (maxEntropy > THRESHOLD_ELECTRON) {
                indicators.emplace_back(std::format(
                    "[EntropyRule] High entropy {:.2f}/8.0 in {} (Electron) — possible payload appended to bundled JS",
                    maxEntropy, highestEntropySource));
                return 50;
            }
            return 0;
        }

        if (target.trust.isInstaller) {
            if (maxEntropy > THRESHOLD_INSTALLER) {
                indicators.emplace_back(std::format(
                    "[EntropyRule] High entropy {:.2f}/8.0 in {} — unusual compression density for standard installer",
                    maxEntropy, highestEntropySource));
                return 40;
            }
            return 0;
        }

        if (target.trust.isGameEngine) {
            if (maxEntropy > THRESHOLD_GAME_ENGINE) {
                indicators.emplace_back(std::format(
                    "[EntropyRule] High entropy {:.2f}/8.0 in {} — unusual for standard game engine binaries",
                    maxEntropy, highestEntropySource));
                return 30;
            }
            return 0;
        }

        // Native PE — standard thresholds against the highest localized entropy
        if (maxEntropy > THRESHOLD_NATIVE_CRITICAL) {
            indicators.emplace_back(std::format(
                "[EntropyRule] Critical entropy {:.2f}/8.0 in {} — strongly indicates a packed or encrypted payload",
                maxEntropy, highestEntropySource));
            return 85; // Capped or additive based on engine design
        }

        if (maxEntropy > THRESHOLD_NATIVE_HIGH) {
            indicators.emplace_back(std::format(
                "[EntropyRule] High entropy {:.2f}/8.0 in {} — likely packed",
                maxEntropy, highestEntropySource));
            return 65;
        }

        if (maxEntropy > THRESHOLD_NATIVE_ELEVATED) {
            indicators.emplace_back(std::format(
                "[EntropyRule] Elevated entropy {:.2f}/8.0 in {} — compressed sections present",
                maxEntropy, highestEntropySource));
            return 30;
        }

        return 0;
    }

} // namespace Heuristics