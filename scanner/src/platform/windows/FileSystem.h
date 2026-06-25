#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <filesystem>
#include <vector>
#include <cstdint>
#include <span>

namespace Platform {

    // ── Zero-Copy Memory Mapped File Wrapper ──────────────────────────────
    // Retains the mapped view so rules can read it without copying data.
    class MemoryMappedFile final {
    public:
        MemoryMappedFile() = default;
        ~MemoryMappedFile() { Close(); }

        MemoryMappedFile(const MemoryMappedFile&) = delete;
        MemoryMappedFile& operator=(const MemoryMappedFile&) = delete;

        MemoryMappedFile(MemoryMappedFile&& other) noexcept;
        MemoryMappedFile& operator=(MemoryMappedFile&& other) noexcept;

        [[nodiscard]] bool Open(const std::wstring& path);
        void Close() noexcept;

        [[nodiscard]] std::span<const uint8_t> GetSpan() const noexcept {
            return std::span<const uint8_t>(view_, size_);
        }

    private:
        HANDLE hFile_ = INVALID_HANDLE_VALUE;
        HANDLE hMap_ = nullptr;
        const uint8_t* view_ = nullptr;
        size_t size_ = 0;
    };

    // ── System Queries ────────────────────────────────────────────────────
    struct FileTimes {
        FILETIME creationTime{ 0, 0 };
        FILETIME lastWriteTime{ 0, 0 };
    };

    [[nodiscard]] uint64_t GetFileSize(const std::filesystem::path& path) noexcept;

    [[nodiscard]] FileTimes GetFileTimes(const std::filesystem::path& path);

    [[nodiscard]] bool IsExecutable(const std::filesystem::path& path);

    [[nodiscard]] std::vector<std::filesystem::path> EnumerateFiles(const std::filesystem::path& dir, bool recursive = true);

} // namespace Platform