#include "SignatureRule.h"
#include <algorithm>
#include <array>
#include <string_view>
#include <format> 
#include <span>

namespace Heuristics {

    namespace {

        // Enterprise Standard: Zero-allocation string struct
        struct Sig {
            std::string_view str;
            int score;
            bool requiresHighRiskLocation;
            std::string_view desc;
        };

        // constexpr array pushes the table construction to compile-time
        constexpr std::array<Sig, 14> kSigs = { {
                // Packers — only meaningful when NOT in a known installer
                {"UPX0",     15, false, "[SignatureRule] UPX packer section (UPX0)"},
                {"UPX!",     15, false, "[SignatureRule] UPX packer stub"},
                {"MPRESS1",  15, false, "[SignatureRule] MPRESS packer"},
                {"ASPack",   15, false, "[SignatureRule] ASPack packer"},
                {"Themida",  15, false, "[SignatureRule] Themida protector"},
                {"WinLicense",15, false, "[SignatureRule] WinLicense protector"},

                // Shell execution strings — context-dependent
                {"cmd.exe /c",          10, true,  "[SignatureRule] Shell execution string (cmd.exe /c)"},
                {"WScript.Shell",       10, true,  "[SignatureRule] WScript Shell invocation"},
                {"Shell.Application",   10, true,  "[SignatureRule] Shell.Application invocation"},

                // PowerShell — very common in legitimate scripts AND malware
                {"powershell -",         5, true,  "[SignatureRule] PowerShell execution string"},
                {"powershell.exe -enc", 20, true,  "[SignatureRule] PowerShell encoded command — common in obfuscated malware"},

                // Privilege escalation — more targeted, flag anywhere but lower score
                {"net localgroup administrators", 12, false, "[SignatureRule] Admin group manipulation command"},
                {"SeDebugPrivilege",              10, false, "[SignatureRule] Debug privilege request"},
                {"net user ",                      8, true,  "[SignatureRule] User account manipulation"},
        } };

        // Hardware-accelerated search instead of manual memcmp
        [[nodiscard]] inline bool Has(std::string_view buf, std::string_view s) noexcept {
            return buf.find(s) != std::string_view::npos;
        }

    } // namespace

    int SignatureRule::Evaluate(const Core::ScanTarget& target, std::vector<std::string>& indicators) {
        if (target.isRegistryKey) {
            return 0;
        }

        // ── 1. Zero-Copy I/O ──────────────────────────────────────────────────
        std::span<const uint8_t> fileView = target.GetMappedData();
        if (fileView.size() < 64) {
            return 0;
        }

        int score = 0;

        // ── 2. Bounded View Generation ────────────────────────────────────────
        // Cap the string scan at 512KB to prevent CPU denial-of-service on massive files
        const size_t scanLimit = std::min(fileView.size(), static_cast<size_t>(512 * 1024));

        // Create a blazing-fast string_view window over the raw memory-mapped buffer
        std::string_view bufView(reinterpret_cast<const char*>(fileView.data()), scanLimit);

        for (const auto& sig : kSigs) {
            if (!Has(bufView, sig.str)) {
                continue;
            }

            // Context filter: skip if it requires a high-risk location and we aren't in one
            if (sig.requiresHighRiskLocation && !target.isInHighRiskLocation) {
                continue;
            }

            // Packer strings: installers and signed software legitimately use packers
            bool isPacker = (sig.str.starts_with("UPX") ||
                sig.str == "MPRESS1" ||
                sig.str == "ASPack" ||
                sig.str == "Themida" ||
                sig.str == "WinLicense");

            if (isPacker && (target.trust.isSignatureValid || target.trust.isSigned)) {
                // Signed software using a packer = copy protection, not malware
                score += 3;
                indicators.emplace_back(std::format("{} (suppressed — signed binary)", sig.desc));
                continue;
            }

            score += sig.score;
            indicators.emplace_back(std::string(sig.desc));
        }

        // ── 3. Cap and Return ─────────────────────────────────────────────────
        return std::min(score, kMaxScore);
    }

} // namespace Heuristics