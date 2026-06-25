#include "FileTypeRule.h"
#include "../utils/StringUtils.h" // Assume WstrToStr handles wide->UTF8 securely

#include <array>
#include <algorithm>
#include <ranges>
#include <format>
#include <cstdint>

namespace Heuristics {

    namespace {
        // Enterprise Standard: Zero-allocation, compile-time arrays.
        // MUST remain strictly alphabetical for std::ranges::binary_search.
        constexpr std::array<std::wstring_view, 18> kDangerousExts = {
            L".bat", L".cmd", L".com", L".cpl", L".dll", L".drv",
            L".exe", L".hta", L".jar", L".js", L".lnk", L".msi",
            L".ocx", L".pif", L".ps1", L".scr", L".sys", L".vbs"
        };

        constexpr std::array<std::wstring_view, 24> kBenignExts = {
            L".7z", L".avi", L".bmp", L".doc", L".docx", L".gif",
            L".gz", L".jpeg", L".jpg", L".json", L".mkv", L".mp3",
            L".mp4", L".pdf", L".png", L".ppt", L".pptx", L".rar",
            L".tar", L".txt", L".xls", L".xlsx", L".xml", L".zip"
        };
    } // namespace

    bool FileTypeRule::IsDangerousExt(std::wstring_view ext) noexcept {
        return std::ranges::binary_search(kDangerousExts, ext);
    }

    bool FileTypeRule::IsBenignExt(std::wstring_view ext) noexcept {
        return std::ranges::binary_search(kBenignExts, ext);
    }

    bool FileTypeRule::HasDecoyDoubleExt(const std::filesystem::path& path) {
        std::wstring outerExt = Utils::ToLower(path.extension().wstring());
        std::wstring innerExt = Utils::ToLower(path.stem().extension().wstring());

        if (outerExt.empty() || innerExt.empty()) {
            return false;
        }

        // True Threat: The outer extension is dangerous, but the inner extension
        // is trying to convince the user it is a safe document.
        // Example: report.pdf.exe -> outer(.exe) is Dangerous, inner(.pdf) is Benign.
        return IsDangerousExt(outerExt) && IsBenignExt(innerExt);
    }

    int FileTypeRule::Evaluate(const Core::ScanTarget& target, std::vector<std::string>& indicators) {
        if (target.isRegistryKey) {
            return 0;
        }

        int score = 0;

        // ── 1. Zero-Copy Magic Byte Check ───────────────────────────────────────
        std::span<const uint8_t> fileView = target.GetMappedData();
        bool hasMZ = false;

        // Safely check the buffer without performing any disk I/O
        if (fileView.size() >= sizeof(uint16_t)) {
            // Reinterpret cast is safe here as long as we are just checking 2 bytes 
            // of a mapped system buffer.
            hasMZ = (*reinterpret_cast<const uint16_t*>(fileView.data()) == MAGIC_MZ);
        }

        // ── 2. Extension Normalization ──────────────────────────────────────────
        // Ensure path parsing relies on std::filesystem for complex Unicode compliance
        const std::filesystem::path pathRaw(target.filePath);
        std::wstring outerExt = Utils::ToLower(pathRaw.extension().wstring());
        std::string extUtf8 = Utils::WstrToStr(outerExt);

        // ── 3. Disguised Executable (e.g., MZ header inside a .pdf) ─────────────
        if (IsBenignExt(outerExt) && hasMZ) {
            indicators.emplace_back(std::format(
                "[FileTypeRule] Extension mismatch: '{}' file contains a PE (MZ) header — disguised executable",
                extUtf8));
            score += SCORE_DISGUISED_EXE;
        }

        // ── 4. Script in a high-risk location ───────────────────────────────────
        else if (IsDangerousExt(outerExt) && !hasMZ && target.isInHighRiskLocation) {
            indicators.emplace_back(std::format(
                "[FileTypeRule] Executable script ('{}') found resting in a high-risk location",
                extUtf8));
            score += SCORE_RISKY_SCRIPT;
        }

        // ── 5. Social Engineering: Double Extension ─────────────────────────────
        if (HasDecoyDoubleExt(pathRaw)) {
            std::string fnameUtf8 = Utils::WstrToStr(pathRaw.filename().wstring());
            indicators.emplace_back(std::format(
                "[FileTypeRule] Decoy double extension in '{}' — classic social engineering pattern",
                fnameUtf8));
            score += SCORE_DOUBLE_EXT;
        }

        // ── 6. Evasion: Suspiciously long filename ──────────────────────────────
        // Count string length (characters), not byte size, for multi-byte Unicode names.
        std::wstring fname = pathRaw.filename().wstring();
        if (fname.length() > SUSPICIOUS_NAME_LENGTH && target.isInHighRiskLocation) {
            indicators.emplace_back(std::format(
                "[FileTypeRule] Suspiciously long filename ({} characters) in a sensitive location",
                fname.length()));
            score += SCORE_LONG_NAME;
        }

        // ── 7. Cap and Return ───────────────────────────────────────────────────
        return std::min(score, kMaxScore);
    }

} // namespace Heuristics