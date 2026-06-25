#include "LocationRule.h"
#include "../utils/StringUtils.h"

#include <windows.h>
#include <shlobj.h>
#include <format>
#include <vector>
#include <string_view>
#include <algorithm>

namespace Heuristics {

    namespace {

        struct LocEntry {
            std::wstring path;
            int score;         // Score for standard unknown/unsigned files
            int trustedScore;  // Mitigated score for cryptographically trusted files
            std::string_view indicator;
        };

        [[nodiscard]] std::vector<LocEntry> BuildTable() {
            std::vector<LocEntry> t;
            t.reserve(10);

            auto addEnv = [&](const wchar_t* ev, int sc, int ts, std::string_view ind) {
                std::wstring p = Utils::ExpandEnvVars(ev);
                if (!p.empty()) {
                    t.push_back({ std::move(p), sc, ts, ind });
                }
                };

            auto addShell = [&](int csidl, int sc, int ts, std::string_view ind) {
                wchar_t buf[MAX_PATH] = {};
                // Note: SHGetFolderPathW is legacy but highly backward compatible. 
                // For a strict modern Windows 10/11 engine, consider SHGetKnownFolderPath.
                if (SUCCEEDED(::SHGetFolderPathW(nullptr, csidl, nullptr, SHGFP_TYPE_CURRENT, buf))) {
                    t.push_back({ std::wstring(buf), sc, ts, ind });
                }
                };

            // ── Persistence: High risk, even if signed (living-off-the-land attacks)
            addShell(CSIDL_STARTUP, 80, 50, "[LocationRule] File in Startup folder — auto-runs on login");
            addShell(CSIDL_COMMON_STARTUP, 80, 50, "[LocationRule] File in All-Users Startup folder");

            // ── Temp/Delivery: High for unsigned. Near-zero for signed (installers)
            addEnv(L"%TEMP%", 65, 10, "[LocationRule] Executable running from Temp folder");
            addEnv(L"%TMP%", 65, 10, "[LocationRule] Executable running from TMP folder");

            // ── User Data: Moderate risk. Discord/Teams live here, but so do RATs.
            addShell(CSIDL_APPDATA, 35, 5, "[LocationRule] Executable in Roaming AppData");
            addShell(CSIDL_LOCAL_APPDATA, 20, 3, "[LocationRule] Executable in Local AppData");

            // ── Documents/Desktop: Low inherent location risk.
            addShell(CSIDL_DESKTOPDIRECTORY, 10, 0, "[LocationRule] Executable on the Desktop");
            addShell(CSIDL_PERSONAL, 5, 0, "[LocationRule] Executable in Documents folder");

            return t;
        }

        [[nodiscard]] const std::vector<LocEntry>& Table() noexcept {
            // Thread-safe Magic Static ensures this is only built once per engine lifecycle
            static const std::vector<LocEntry> t = BuildTable();
            return t;
        }

    } // namespace

    int LocationRule::Evaluate(const Core::ScanTarget& target, std::vector<std::string>& indicators) {
        if (target.isRegistryKey) {
            return 0;
        }

        // Zero-allocation path checking
        std::wstring_view targetPathView = target.filePath.native();

        const LocEntry* matched = nullptr;
        for (const auto& e : Table()) {
            if (e.path.empty()) continue;

            // Assumes Utils::StartsWithW_i is an optimized, case-insensitive string_view comparison
            if (Utils::StartsWithW_i(targetPathView, e.path)) {
                if (!matched || e.score > matched->score) {
                    matched = &e;
                }
            }
        }

        if (!matched) {
            return 0;
        }

        // ── Security Fix: Strict Trust Evaluation ──────────────────────────────
        // .NET and Electron are NOT trust signals. Only valid cryptography or 
        // verified installer behavior mitigates a dangerous drop location.
        bool isTrusted = target.trust.isSignatureValid || target.trust.isInstaller;

        int finalScore = isTrusted ? matched->trustedScore : matched->score;

        if (finalScore > 0) {
            if (isTrusted && matched->trustedScore < matched->score) {
                indicators.emplace_back(std::format("{} (risk mitigated via valid signature/installer context)", matched->indicator));
            }
            else {
                // Emplace string_view directly into the string vector
                indicators.emplace_back(std::string(matched->indicator));
            }
        }

        return std::min(finalScore, kMaxScore);
    }

} // namespace Heuristics