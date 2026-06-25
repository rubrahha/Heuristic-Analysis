#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <filesystem>
#include "../core/ScanTarget.h"

namespace Heuristics {

    // ---------------------------------------------------------------------------
    // TrustAnalyzer — Digital Signature & Context Engine
    //
    // Evaluates the inherent trust of a binary before heuristic rules execute.
    // Verifies Authenticode PKCS#7 signatures via WinVerifyTrust and scans
    // for standard software frameworks (Installers, Game Engines, Electron)
    // to dynamically adjust risk scoring and prevent false positives.
    // ---------------------------------------------------------------------------

    class TrustAnalyzer final {
    public:
        // Populate target.trust — Call this AFTER target.MapFileToMemory()
        static void Analyze(Core::ScanTarget& target);

    private:
        static void CheckSignature(Core::ScanTarget& target);
        static void DetectFileType(Core::ScanTarget& target);

        [[nodiscard]] static bool IsKnownPublisher(std::wstring_view signerName) noexcept;

        // Enterprise Constants for Trust Modifiers
        static constexpr int MODIFIER_TRUSTED_PUBLISHER = -60;
        static constexpr int MODIFIER_SIGNED_UNKNOWN = -15;
        static constexpr int MODIFIER_GAME_ENGINE = -40;
        static constexpr int MODIFIER_ELECTRON_APP = -35;
        static constexpr int MODIFIER_INSTALLER = -30;
        static constexpr int MODIFIER_MINGW_COMPILER = -30;
    };

} // namespace Heuristics