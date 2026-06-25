#include "OverlayRule.h"
#include "PEParser.h"
#include "EntropyRule.h" // DRY Principle: Reusing our high-speed math function
#include <algorithm>
#include <format>
#include <span>

namespace Heuristics {

    int OverlayRule::Evaluate(const Core::ScanTarget& target, std::vector<std::string>& indicators) {
        if (target.isRegistryKey) {
            return 0;
        }

        // ── 1. Zero-Copy I/O ──────────────────────────────────────────────────
        std::span<const uint8_t> fileView = target.GetMappedData();
        if (fileView.empty()) {
            return 0;
        }

        // Parse the PE directly from the memory span
        auto pe = PE::Parse(fileView);

        // Ensure the PE is structurally valid and the section boundaries are sane
        if (!pe.valid || pe.lastSecEnd == 0 || pe.lastSecEnd >= fileView.size()) {
            return 0;
        }

        const size_t overlaySize = fileView.size() - pe.lastSecEnd;

        // Ignore tiny overlays (often just compiler alignment padding)
        if (overlaySize < MIN_OVERLAY_SIZE) {
            return 0;
        }

        // ── 2. Isolate the Overlay Span ───────────────────────────────────────
        std::span<const uint8_t> overlayData = fileView.subspan(pe.lastSecEnd, overlaySize);

        double H = EntropyRule::CalculateShannonEntropy(overlayData);
        double ratioPercent = (static_cast<double>(overlaySize) / static_cast<double>(fileView.size())) * 100.0;

        int score = 0;

        // ── 3. Evaluate Embedded PE (Executable inside an Executable) ─────────
        if (overlaySize >= 2 && overlayData[0] == 0x4D && overlayData[1] == 0x5A) { // "MZ"

            if (target.trust.isSignatureValid) {
                indicators.emplace_back("[OverlayRule] Embedded PE executable in overlay — risk mitigated (valid signature)");
                score += SCORE_EMBEDDED_PE_SIGNED;
            }
            else {
                indicators.emplace_back("[OverlayRule] Embedded PE executable in overlay section — strongly indicates a dropper/binder");
                score += SCORE_EMBEDDED_PE_MALWARE;
            }

            // If it's a PE, we skip the archive/entropy checks to prevent duplicate overlapping penalties
            return std::min(score, kMaxScore);
        }

        // ── 4. Evaluate Embedded Archives ─────────────────────────────────────
        bool isZip = (overlaySize >= 4 && overlayData[0] == 0x50 && overlayData[1] == 0x4B); // "PK"
        bool isRar = (overlaySize >= 4 && overlayData[0] == 0x52 && overlayData[1] == 0x61 && overlayData[2] == 0x72 && overlayData[3] == 0x21); // "Rar!"
        bool is7z = (overlaySize >= 4 && overlayData[0] == 0x37 && overlayData[1] == 0x7A && overlayData[2] == 0xBC && overlayData[3] == 0xAF); // "7z"

        if (isZip || isRar || is7z) {
            if (target.trust.isInstaller || target.trust.isSignatureValid || target.trust.isSigned) {
                indicators.emplace_back(std::format(
                    "[OverlayRule] Embedded archive in overlay — risk mitigated ({})",
                    target.trust.isInstaller ? "installer context" : "signed software"));
                score += SCORE_EMBEDDED_ARCHIVE_TRUSTED;
            }
            else {
                indicators.emplace_back("[OverlayRule] Embedded archive (ZIP/RAR/7z) in overlay — indicates a dropper/extractor payload");
                score += SCORE_EMBEDDED_ARCHIVE_DROPPER;
            }

            return std::min(score, kMaxScore);
        }

        // ── 5. Evaluate High-Entropy (Encrypted) Data ─────────────────────────
        if (H > THRESHOLD_ENTROPY) {
            // Game engines and installers legitimately have massive high-entropy assets appended.
            // Signed software's overlay is overwhelmingly the Authenticode signature blob itself.
            if (!target.trust.isInstaller && !target.trust.isGameEngine &&
                !target.trust.isSignatureValid && !target.trust.isSigned) {

                indicators.emplace_back(std::format(
                    "[OverlayRule] High-entropy appended data ({:.2f}/8.0, {:.0f}% of file) — possible encrypted/packed payload",
                    H, ratioPercent));
                score += SCORE_HIGH_ENTROPY_PAYLOAD;
            }
        }

        // ── 6. Evaluate Suspiciously Large Appended Blocks (Unencrypted) ──────
        else if (overlaySize > LARGE_BLOCK_SIZE) {
            // Likely a certificate chain, version manifest, or uncompressed resource data.
            // We only lightly penalize totally unknown/unsigned files dropping huge unmapped blocks.
            if (!target.trust.isSigned && !target.trust.isInstaller && !target.trust.isGameEngine) {
                indicators.emplace_back(std::format(
                    "[OverlayRule] Unusually large appended data block ({:.0f}% of file) with moderate entropy — requires manual review",
                    ratioPercent));
                score += SCORE_LARGE_UNKNOWN_BLOCK;
            }
        }

        // ── 7. Cap and Return ─────────────────────────────────────────────────
        return std::min(score, kMaxScore);
    }

} // namespace Heuristics