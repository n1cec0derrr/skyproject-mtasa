
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace SkyDLC
{
    namespace fs = std::filesystem;

    constexpr uint32_t FORMAT_VERSION = 2;

    enum class DLCType : uint32_t
    {
        Vehicles = 1,
        Buildings = 2,
        Map = 3,
        Textures = 4,
        Other = 255
    };

    struct DLCHeader
    {
        char     magic[8];
        uint32_t version;
        uint32_t type;
        uint64_t encryptedSize;

        uint8_t nonce[12];
        uint8_t tag[16];
    };

    struct DLCPackage
    {
        fs::path path;
        DLCType type = DLCType::Other;
        uint64_t encryptedSize = 0;
        bool valid = false;
    };

    class CSkyDLCManager
    {
    public:
        bool Initialize(const fs::path& dlcDirectory);
        void Shutdown();

        const std::vector<DLCPackage>& GetPackages() const;


        bool WasTestDecryptionAttempted() const { return m_testDecryptionAttempted; }

        bool WasTestDecryptionSuccessful() const { return m_testDecryptionSuccessful; }

        size_t GetTestDecryptedSize() const { return m_testDecryptedSize; }

    private:
        bool LoadPackage(const fs::path& path);

        fs::path m_dlcDirectory;
        std::vector<DLCPackage> m_packages;


        bool   m_testDecryptionAttempted = false;
        bool   m_testDecryptionSuccessful = false;
        size_t m_testDecryptedSize = 0;
    };
}
