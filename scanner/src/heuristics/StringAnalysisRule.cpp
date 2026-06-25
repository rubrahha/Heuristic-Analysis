// ─── heuristics/StringAnalysisRule.cpp ───────────────────────────────────────
#include "StringAnalysisRule.h"
#include <algorithm>
#include <array>
#include <string_view>
#include <format> 
#include <span>

namespace Heuristics {

    namespace {
        // Hardware-accelerated search
        [[nodiscard]] inline bool Has(std::string_view buf, std::string_view s) noexcept {
            return buf.find(s) != std::string_view::npos;
        }

        constexpr std::array<std::string_view, 10> kAntiVM = {
            "VMware", "VBOX", "VirtualBox", "Sandboxie", "SbieDll",
            "cuckoo", "wireshark", "procmon", "ollydbg", "x64dbg"
        };

        constexpr std::array<std::string_view, 9> kTools = {
            "mimikatz", "Meterpreter", "metsrv", "CobaltStrike",
            "empire", "sliver", "havoc", "metasploit", "powersploit"
        };
    } // namespace

    int StringAnalysisRule::Evaluate(const Core::ScanTarget& target, std::vector<std::string>& indicators) {
        if (target.isRegistryKey) {
            return 0;
        }

        // ── 1. Zero-Copy I/O ──────────────────────────────────────────────────
        std::span<const uint8_t> fileView = target.GetMappedData();
        if (fileView.size() < sizeof(uint16_t)) {
            return 0;
        }

        if (*reinterpret_cast<const uint16_t*>(fileView.data()) != MAGIC_MZ) {
            return 0;
        }

        int score = 0;

        // Bounded scan limit (2MB) to prevent CPU DOS on massive files
        const size_t scanLimit = std::min(fileView.size(), static_cast<size_t>(2 * 1024 * 1024));
        std::string_view bufView(reinterpret_cast<const char*>(fileView.data()), scanLimit);

        // ── 2. Additive Scoring Pipeline ──────────────────────────────────────
        int vmHits = 0;
        for (const auto& s : kAntiVM) {
            if (Has(bufView, s)) ++vmHits;
        }

        if (vmHits >= 2) {
            indicators.emplace_back(std::format(
                "[StringAnalysisRule] Anti-VM/sandbox evasion strings ({} hits)", vmHits));
            score += SCORE_ANTI_VM;
        }

        for (const auto& s : kTools) {
            if (Has(bufView, s)) {
                indicators.emplace_back(std::format("[StringAnalysisRule] Offensive tool string '{}' found", s));
                score += SCORE_OFFENSIVE_TOOL;
            }
        }

        bool hasIEX = Has(bufView, "IEX") || Has(bufView, "Invoke-Expression");
        bool hasEnc = Has(bufView, "-EncodedCommand") || Has(bufView, "-enc ");
        bool hasDL = Has(bufView, "DownloadString") || Has(bufView, "DownloadFile");
        bool hasWC = Has(bufView, "Net.WebClient") || Has(bufView, "WebClient");

        if ((hasIEX || hasEnc) && (hasDL || hasWC)) {
            indicators.emplace_back("[StringAnalysisRule] PowerShell download-and-execute pattern detected");
            score += SCORE_PS_DOWNLOADER;
        }

        if (Has(bufView, "schtasks") || Has(bufView, "CurrentVersion\\Run") || Has(bufView, "sc create")) {
            indicators.emplace_back("[StringAnalysisRule] Persistence command strings detected");
            score += SCORE_PERSISTENCE;
        }

        if (Has(bufView, "vssadmin delete") || Has(bufView, "wbadmin delete") || Has(bufView, "shadowcopy delete")) {
            indicators.emplace_back("[StringAnalysisRule] Backup/shadow copy deletion command — strong ransomware indicator");
            score += SCORE_RANSOMWARE;
        }

        if (Has(bufView, ".onion") || Has(bufView, "pastebin.com") || Has(bufView, "ngrok.io")) {
            indicators.emplace_back("[StringAnalysisRule] C2/exfiltration domain strings detected");
            score += SCORE_C2_DOMAIN;
        }

        return std::min(score, kMaxScore);
    }

} // namespace Heuristics