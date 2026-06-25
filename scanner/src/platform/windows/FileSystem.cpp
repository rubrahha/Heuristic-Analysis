#include "FileSystem.h"
#include <stdexcept>

namespace Platform {

    // ── MemoryMappedFile Implementation ───────────────────────────────────

    MemoryMappedFile::MemoryMappedFile(MemoryMappedFile&& other) noexcept
        : hFile_(other.hFile_), hMap_(other.hMap_), view_(other.view_), size_(other.size_) {
        other.hFile_ = INVALID_HANDLE_VALUE;
        other.hMap_ = nullptr;
        other.view_ = nullptr;
        other.size_ = 0;
    }

    MemoryMappedFile& MemoryMappedFile::operator=(MemoryMappedFile&& other) noexcept {
        if (this != &other) {
            Close();
            hFile_ = other.hFile_;
            hMap_ = other.hMap_;
            view_ = other.view_;
            size_ = other.size_;

            other.hFile_ = INVALID_HANDLE_VALUE;
            other.hMap_ = nullptr;
            other.view_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    bool MemoryMappedFile::Open(const std::wstring& path) {
        Close();

        hFile_ = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hFile_ == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER liSize;
        if (!::GetFileSizeEx(hFile_, &liSize) || liSize.QuadPart == 0) {
            Close();
            return false;
        }

        // Enforce hard RAM limit for the map (e.g., 200MB limit for analysis)
        size_ = static_cast<size_t>(std::min(liSize.QuadPart, 200LL * 1024 * 1024));

        hMap_ = ::CreateFileMappingW(hFile_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap_) {
            Close();
            return false;
        }

        view_ = static_cast<const uint8_t*>(::MapViewOfFile(hMap_, FILE_MAP_READ, 0, 0, size_));
        if (!view_) {
            Close();
            return false;
        }

        return true;
    }

    void MemoryMappedFile::Close() noexcept {
        if (view_) { ::UnmapViewOfFile(view_); view_ = nullptr; }
        if (hMap_) { ::CloseHandle(hMap_); hMap_ = nullptr; }
        if (hFile_ != INVALID_HANDLE_VALUE) { ::CloseHandle(hFile_); hFile_ = INVALID_HANDLE_VALUE; }
        size_ = 0;
    }

    // ── Utilities ─────────────────────────────────────────────────────────

    uint64_t GetFileSize(const std::filesystem::path& path) noexcept {
        std::error_code ec;
        auto sz = std::filesystem::file_size(path, ec);
        return ec ? 0ULL : static_cast<uint64_t>(sz);
    }

    FileTimes GetFileTimes(const std::filesystem::path& path) {
        FileTimes ft;
        HANDLE hFile = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            ::GetFileTime(hFile, &ft.creationTime, nullptr, &ft.lastWriteTime);
            ::CloseHandle(hFile);
        }
        return ft;
    }

    bool IsExecutable(const std::filesystem::path& path) {
        MemoryMappedFile map;
        if (map.Open(path.wstring())) {
            auto span = map.GetSpan();
            return span.size() >= 2 && span[0] == 0x4D && span[1] == 0x5A;
        }
        return false;
    }

    std::vector<std::filesystem::path> EnumerateFiles(const std::filesystem::path& dir, bool recursive) {
        std::vector<std::filesystem::path> out;
        std::error_code ec;

        if (recursive) {
            auto opts = std::filesystem::directory_options::skip_permission_denied |
                std::filesystem::directory_options::follow_directory_symlink;
            try {
                for (auto it = std::filesystem::recursive_directory_iterator(dir, opts, ec);
                    it != std::filesystem::recursive_directory_iterator(); ) {
                    if (ec) { ec.clear(); it.increment(ec); continue; }
                    try { if (it->is_regular_file(ec) && !ec) out.push_back(it->path()); }
                    catch (...) {}
                    it.increment(ec);
                }
            }
            catch (...) {}
        }
        else {
            try {
                for (const auto& e : std::filesystem::directory_iterator(dir, ec)) {
                    if (!ec && e.is_regular_file(ec) && !ec) out.push_back(e.path());
                }
            }
            catch (...) {}
        }
        return out;
    }

} // namespace Platform