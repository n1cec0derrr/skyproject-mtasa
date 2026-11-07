#pragma once

#include "CSkyDLCCrypto.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace SkyDLC
{
    namespace fs = std::filesystem;

    constexpr uint32_t FORMAT_VERSION = 3;

    enum class DLCType : uint32_t
    {
        Vehicles = 1,
        Buildings = 2,
        Map = 3,
        Textures = 4,
        Other = 255
    };

    class CSkyDLCPackage;

    struct DLCFile
    {
        CSkyDLCPackage* package = nullptr;
        uint64_t        offset = 0;
        uint64_t        size = 0;
    };

    class CSkyDLCManager
    {
    public:
        CSkyDLCManager();
        ~CSkyDLCManager();

        bool Initialize(const fs::path& dlcDirectory, const AESKey& masterKey);
        void Shutdown();

        size_t GetPackageCount() const { return m_packages.size(); }
        size_t GetFileCount() const { return m_files.size(); }

        // Path is relative to the GTA directory (data/gta.dat) or starts with resources/<name>/.
        const DLCFile* FindFile(std::string path) const;

        // Thread safe. Returns false if the data does not pass authentication.
        bool Read(const DLCFile& file, uint64_t offset, void* buffer, uint32_t size, uint32_t& bytesRead) const;
        bool ReadFile(const std::string& path, std::string& data) const;

        const fs::path& GetPackagePath(const DLCFile& file) const;

        static std::string NormalizePath(std::string path);

    private:
        bool LoadPackage(const fs::path& path, const AESKey& masterKey);

        std::vector<std::unique_ptr<CSkyDLCPackage>> m_packages;
        std::unordered_map<std::string, DLCFile>     m_files;
    };

    // Single instance used by the file hooks and the Lua engine functions.
    CSkyDLCManager& GetDLCManager();

    // Makes the game see the files of the packages as ordinary files.
    bool InstallFileHooks();
}
