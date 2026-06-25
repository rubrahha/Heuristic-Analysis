#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h> 
#include <vector>
#include <cstdint>
#include <cmath>
#include <string_view>
#include <span> // C++20 Zero-copy memory views

namespace PE {

    static constexpr uint32_t PE_SCN_EXEC = IMAGE_SCN_MEM_EXECUTE;
    static constexpr uint32_t PE_SCN_WRITE = IMAGE_SCN_MEM_WRITE;
    static constexpr uint16_t PE_FILE_DLL = IMAGE_FILE_DLL;
    static constexpr uint16_t PE_ASLR = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    static constexpr uint16_t PE_NX = IMAGE_DLLCHARACTERISTICS_NX_COMPAT;

    struct Section {
        char     name[9];
        uint32_t vaddr;
        uint32_t vsize;
        uint32_t rawPtr;
        uint32_t rawSize;
        uint32_t chars;

        [[nodiscard]] bool IsExec()  const noexcept { return (chars & PE_SCN_EXEC) != 0; }
        [[nodiscard]] bool IsWrite() const noexcept { return (chars & PE_SCN_WRITE) != 0; }
    };

    struct ParsedPE {
        bool     valid = false;
        bool     is64 = false;
        bool     isDll = false;
        bool     is_dotnet = false;  // CLR Runtime Header present
        uint32_t timestamp = 0;
        uint16_t numSections = 0;
        uint16_t subsystem = 0;
        uint16_t dllChars = 0;
        uint32_t epRva = 0;
        uint32_t importRva = 0;
        uint32_t importSize = 0;
        uint32_t clrRva = 0;
        uint32_t lastSecEnd = 0;
        std::vector<Section> sections;
    };

    // ── Upgraded to std::span for Zero-Copy Pipeline Integration ───────────
    [[nodiscard]] inline ParsedPE Parse(std::span<const uint8_t> buf) {
        ParsedPE pe;
        if (buf.size() < sizeof(IMAGE_DOS_HEADER)) return pe;

        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return pe;

        // Bounds check the NT Header offset
        if (dosHeader->e_lfanew <= 0 || dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > buf.size()) return pe;

        const auto* ntHeaders32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buf.data() + dosHeader->e_lfanew);
        if (ntHeaders32->Signature != IMAGE_NT_SIGNATURE) return pe;

        pe.numSections = ntHeaders32->FileHeader.NumberOfSections;
        pe.timestamp = ntHeaders32->FileHeader.TimeDateStamp;
        pe.isDll = (ntHeaders32->FileHeader.Characteristics & PE_FILE_DLL) != 0;

        // Determine 32-bit vs 64-bit
        pe.is64 = (ntHeaders32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

        DWORD ddCount = 0;
        const IMAGE_DATA_DIRECTORY* dataDirs = nullptr;
        const IMAGE_SECTION_HEADER* sectionHeaders = nullptr;

        // Note: IMAGE_FIRST_SECTION is a WinAPI macro. It safely calculates the offset.
        if (pe.is64) {
            if (dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > buf.size()) return pe;
            const auto* ntHeaders64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + dosHeader->e_lfanew);

            pe.subsystem = ntHeaders64->OptionalHeader.Subsystem;
            pe.dllChars = ntHeaders64->OptionalHeader.DllCharacteristics;
            pe.epRva = ntHeaders64->OptionalHeader.AddressOfEntryPoint;
            ddCount = ntHeaders64->OptionalHeader.NumberOfRvaAndSizes;
            dataDirs = ntHeaders64->OptionalHeader.DataDirectory;
            sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders64);
        }
        else {
            pe.subsystem = ntHeaders32->OptionalHeader.Subsystem;
            pe.dllChars = ntHeaders32->OptionalHeader.DllCharacteristics;
            pe.epRva = ntHeaders32->OptionalHeader.AddressOfEntryPoint;
            ddCount = ntHeaders32->OptionalHeader.NumberOfRvaAndSizes;
            dataDirs = ntHeaders32->OptionalHeader.DataDirectory;
            sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders32);
        }

        // Bounds check Data Directories
        if (reinterpret_cast<const uint8_t*>(dataDirs) + (ddCount * sizeof(IMAGE_DATA_DIRECTORY)) > buf.data() + buf.size()) {
            return pe;
        }

        if (ddCount > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            pe.importRva = dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            pe.importSize = dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }

        if (ddCount > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
            pe.clrRva = dataDirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
            pe.is_dotnet = (pe.clrRva != 0);
        }

        // Parse Sections safely
        if (reinterpret_cast<const uint8_t*>(sectionHeaders) + (pe.numSections * sizeof(IMAGE_SECTION_HEADER)) > buf.data() + buf.size()) {
            return pe;
        }

        pe.sections.reserve(pe.numSections);
        for (uint16_t i = 0; i < pe.numSections; ++i) {
            const auto& winSec = sectionHeaders[i];
            Section s{};

            strncpy_s(s.name, sizeof(s.name), reinterpret_cast<const char*>(winSec.Name), 8);

            s.vaddr = winSec.VirtualAddress;
            s.vsize = winSec.Misc.VirtualSize;
            s.rawPtr = winSec.PointerToRawData;
            s.rawSize = winSec.SizeOfRawData;
            s.chars = winSec.Characteristics;

            uint32_t end = s.rawPtr + s.rawSize;
            if (end > pe.lastSecEnd) pe.lastSecEnd = end;
            pe.sections.push_back(s);
        }

        pe.valid = true;
        return pe;
    }

    // ── Upgraded to std::span (Consider removing if using EntropyRule instead) ──
    [[nodiscard]] inline double Entropy(std::span<const uint8_t> data) noexcept {
        if (data.empty()) return 0.0;

        uint64_t freq[256] = {};
        for (const uint8_t byte : data) {
            ++freq[byte];
        }

        double H = 0.0;
        const double n = static_cast<double>(data.size());

        for (const auto c : freq) {
            if (c == 0) continue;
            double p = static_cast<double>(c) / n;
            H -= p * std::log2(p);
        }
        return H;
    }

} // namespace PE