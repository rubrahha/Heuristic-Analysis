#include "ImportTableRule.h"
#include "PEParser.h" // Needed for target context/PE verification
#include <algorithm>
#include <span>

namespace Heuristics {

    namespace {
        // High-performance, zero-allocation substring search
        [[nodiscard]] bool Has(std::string_view buf, std::string_view pattern) noexcept {
            return buf.find(pattern) != std::string_view::npos;
        }

        // Language fingerprinting to suppress false positives on massive runtime imports
        [[nodiscard]] bool IsDelphiRuntime(std::string_view buf) noexcept {
            return Has(buf, "rtl") || Has(buf, "vcl") ||
                Has(buf, "Borland") || Has(buf, "CodeGear") || Has(buf, "Embarcadero");
        }

        [[nodiscard]] bool IsGoRuntime(std::string_view buf) noexcept {
            return Has(buf, "Go build") || Has(buf, "go:buildid") ||
                Has(buf, "runtime.goexit") || Has(buf, "GOARCH");
        }

        [[nodiscard]] bool IsRustRuntime(std::string_view buf) noexcept {
            return Has(buf, "rustc ") || Has(buf, "__rust_") || Has(buf, "Rust panicked");
        }
    } // namespace

    int ImportTableRule::Evaluate(const Core::ScanTarget& target, std::vector<std::string>& indicators) {
        if (target.isRegistryKey) {
            return 0;
        }

        // ── 1. Zero-Copy I/O ──────────────────────────────────────────────────
        std::span<const uint8_t> fileView = target.GetMappedData();

        if (fileView.size() < sizeof(uint16_t)) {
            return 0;
        }

        // Safe MZ Header check
        if (*reinterpret_cast<const uint16_t*>(fileView.data()) != MAGIC_MZ) {
            return 0; // Not a PE file
        }

        // ── 2. Bounded View Generation ────────────────────────────────────────
        // Cap the scan at 2MB to prevent CPU denial-of-service on giant binaries
        const size_t scanLimit = std::min(fileView.size(), static_cast<size_t>(2 * 1024 * 1024));

        // Reinterpret the binary span as an ASCII string_view for blazing-fast string operations
        std::string_view bufView(reinterpret_cast<const char*>(fileView.data()), scanLimit);

        // Ideally, PE::Parse operates directly on the span instead of allocating memory.
        auto pe = PE::Parse(fileView);
        int score = 0;

        // ── 3. .NET Managed Executable Rules ──────────────────────────────────
        if (pe.is_dotnet) {
            if (Has(bufView, "System.Reflection.Emit") && Has(bufView, "DynamicMethod")) {
                indicators.emplace_back("[ImportTableRule] Dynamic IL emission — runtime code generation");
                score += SCORE_DOTNET_EMIT;
            }
            if (!target.trust.isGameEngine) {
                if (Has(bufView, "VirtualAlloc") || Has(bufView, "WriteProcessMemory") || Has(bufView, "CreateRemoteThread")) {
                    indicators.emplace_back("[ImportTableRule] P/Invoke to process injection APIs");
                    score += SCORE_DOTNET_INJECT;
                }
            }
            if (Has(bufView, "Assembly.Load") || Has(bufView, "Assembly.LoadFrom")) {
                indicators.emplace_back("[ImportTableRule] Dynamic assembly loading — possible reflective loader");
                score += SCORE_DOTNET_LOAD;
            }
            return std::min(score, kMaxScore);
        }

        // ── 4. Native PE Rules ────────────────────────────────────────────────
        bool hasVAE = Has(bufView, "VirtualAllocEx");
        bool hasWPM = Has(bufView, "WriteProcessMemory");
        bool hasCRT = Has(bufView, "CreateRemoteThread");

        // Process Injection Triad
        if (hasVAE && hasWPM && hasCRT) {
            if (target.trust.isGameEngine) {
                indicators.emplace_back("[ImportTableRule] Process injection APIs — suppressed (game engine/anti-cheat context)");
                score += SCORE_INJECT_WHITELIST;
            }
            else if (target.trust.isSignatureValid) {
                indicators.emplace_back("[ImportTableRule] Process injection APIs — signed binary, possible security tool");
                score += SCORE_INJECT_SIGNED;
            }
            else {
                indicators.emplace_back("[ImportTableRule] Process injection triad: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread");
                score += SCORE_INJECT_MALWARE;
            }
        }

        // Anti-debug / Evasion
        if (Has(bufView, "IsDebuggerPresent") || Has(bufView, "NtQueryInformationProcess") || Has(bufView, "CheckRemoteDebuggerPresent")) {
            if (!target.trust.isGameEngine && !target.trust.isSignatureValid) {
                indicators.emplace_back("[ImportTableRule] Anti-debugging and analysis-evasion APIs present");
                score += SCORE_ANTI_DEBUG;
            }
        }

        // Credential Theft (LSASS / SAM)
        if (Has(bufView, "SamOpenDomain") || Has(bufView, "LsaOpenPolicy") || Has(bufView, "CredEnumerateA")) {
            indicators.emplace_back("[ImportTableRule] Credential-access APIs (SAM/LSA/CredEnumerate)");
            score += SCORE_CRED_THEFT;
        }

        // Ransomware Cryptography
        if (Has(bufView, "CryptEncrypt") && Has(bufView, "CryptGenKey")) {
            if (!target.trust.isSignatureValid) {
                indicators.emplace_back("[ImportTableRule] Cryptography API pair commonly used by ransomware");
                score += SCORE_RANSOMWARE;
            }
        }

        // Network / Possible C2
        if (Has(bufView, "InternetOpenA") || Has(bufView, "InternetOpenW") || Has(bufView, "WinHttpOpen") || Has(bufView, "HttpSendRequest")) {
            if (!target.trust.isSigned && !target.trust.isGameEngine) {
                indicators.emplace_back("[ImportTableRule] WinINet/WinHTTP APIs — network communication capabilities");
                score += SCORE_NETWORK;
            }
        }

        // Keylogger Hooks
        if (Has(bufView, "SetWindowsHookEx") && Has(bufView, "GetAsyncKeyState")) {
            if (!target.trust.isGameEngine && !target.trust.isSignatureValid) {
                indicators.emplace_back("[ImportTableRule] Global keyboard hook APIs — possible keylogger");
                score += SCORE_KEYLOGGER;
            }
        }

        // ── 5. Manual API Resolver / Packer Signature ─────────────────────────
        // Highly suspicious: A binary that only imports LoadLibrary and GetProcAddress,
        // and resolves all other functions dynamically to evade static analysis.
        bool hasLL = Has(bufView, "LoadLibraryA") || Has(bufView, "LoadLibraryW");
        bool hasGP = Has(bufView, "GetProcAddress");

        if (hasLL && hasGP && !hasVAE && score == 0 &&
            !target.trust.isInstaller && !target.trust.isGameEngine &&
            !target.trust.isMinGW &&
            !IsDelphiRuntime(bufView) && !IsGoRuntime(bufView) && !IsRustRuntime(bufView)) {

            indicators.emplace_back("[ImportTableRule] Only LoadLibrary + GetProcAddress detected — manual API resolver/packer stub");
            score += SCORE_MANUAL_RESOLVER;
        }

        // ── 6. Cap and Return ─────────────────────────────────────────────────
        return std::min(score, kMaxScore);
    }

} // namespace Heuristics