#include "StdInc.h"
#include "CSkyDLCManager.h"
#include "CSkyDLCCrypto.h"

#include <array>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <system_error>

namespace SkyDLC
{
    namespace
    {
        constexpr char DLC_MAGIC[8] = {'S', 'K', 'Y', 'D', 'L', 'C', '2', '\0'};
    }

    bool CSkyDLCManager::Initialize(const fs::path& dlcDirectory)
    {
        Shutdown();

        m_dlcDirectory = dlcDirectory;

        std::error_code ec;

        if (!fs::exists(m_dlcDirectory, ec))
        {
            std::cout << "[SkyDLC] DLC directory not found.\n";
            return true;
        }

        if (!fs::is_directory(m_dlcDirectory, ec))
            return false;

        for (const auto& entry :
             fs::directory_iterator(
                 m_dlcDirectory,
                 fs::directory_options::skip_permission_denied,
                 ec))
        {
            if (ec)
                break;

            if (!entry.is_regular_file(ec))
                continue;

            if (entry.path().extension() != L".skydlc")
                continue;

            LoadPackage(entry.path());
        }

        
        return !ec;
    }

    bool CSkyDLCManager::LoadPackage(const fs::path& path)
    {
        std::ifstream file(path, std::ios::binary);

        if (!file)
            return false;

        DLCHeader header{};

        // Read fields individually to avoid struct padding.
        file.read(header.magic, sizeof(header.magic));
        file.read(reinterpret_cast<char*>(&header.version),
                  sizeof(header.version));
        file.read(reinterpret_cast<char*>(&header.type),
                  sizeof(header.type));
        file.read(reinterpret_cast<char*>(&header.encryptedSize),
                  sizeof(header.encryptedSize));
        file.read(reinterpret_cast<char*>(header.nonce), sizeof(header.nonce));

        file.read(reinterpret_cast<char*>(header.tag), sizeof(header.tag));

        if (!file)
            return false;

        if (std::memcmp(
                header.magic,
                DLC_MAGIC,
                sizeof(DLC_MAGIC)) != 0)
            return false;

        if (header.version != FORMAT_VERSION)
            return false;

        if (header.type < 1 ||
            (header.type > 4 && header.type != 255))
            return false;

        std::error_code ec;
        const auto fileSize = fs::file_size(path, ec);

        constexpr uint64_t HEADER_SIZE = 52;

        if (ec || fileSize < HEADER_SIZE ||
            header.encryptedSize != fileSize - HEADER_SIZE)
            return false;

        DLCPackage package;
        package.path = path;
        package.type = static_cast<DLCType>(header.type);
        package.encryptedSize = header.encryptedSize;
        package.valid = true;

                // Development-only decryption test.
        if (header.type == 255)
        {

            m_testDecryptionAttempted = true;

            const fs::path keyPath = path.string() + ".key";

            std::ifstream keyFile(keyPath, std::ios::binary | std::ios::ate);

            if (!keyFile || keyFile.tellg() != 32)
            {
                std::cout << "[SkyDLC] Test key missing\n";
                return false;
            }

            AESKey key{};

            keyFile.seekg(0);

            if (!keyFile.read(reinterpret_cast<char*>(key.data()), static_cast<std::streamsize>(key.size())))
            {
                SecureZeroMemory(key.data(), key.size());
                return false;
            }

            AESNonce nonce{};
            AESTag   tag{};

            std::memcpy(nonce.data(), header.nonce, nonce.size());
            std::memcpy(tag.data(), header.tag, tag.size());

            // Test-only size limit: 16 MiB.
            constexpr uint64_t MAX_TEST_SIZE = 16ull * 1024 * 1024;

            if (header.encryptedSize > MAX_TEST_SIZE)
            {
                SecureZeroMemory(key.data(), key.size());
                return false;
            }

            std::vector<uint8_t> encrypted(static_cast<size_t>(header.encryptedSize));

            if (!encrypted.empty() && !file.read(reinterpret_cast<char*>(encrypted.data()), static_cast<std::streamsize>(encrypted.size())))
            {
                SecureZeroMemory(key.data(), key.size());
                return false;
            }

            std::vector<uint8_t> decrypted;

            const bool success = CSkyDLCCrypto::Decrypt(key, nonce, tag, encrypted, decrypted);

            SecureZeroMemory(key.data(), key.size());

            m_testDecryptionSuccessful = success;
            m_testDecryptedSize = success ? decrypted.size() : 0;

            if (!success)
            {
                std::cout << "[SkyDLC] AES-GCM authentication FAILED\n";
                return false;
            }

            std::cout << "[SkyDLC] AES-GCM authentication PASSED, bytes=" << decrypted.size() << '\n';
        }

        m_packages.push_back(std::move(package));

        std::cout << "[SkyDLC] Found package: "
                  << path.filename().string() << '\n';

        return true;
    }

    void CSkyDLCManager::Shutdown()
    {
        m_testDecryptionAttempted = false;
        m_testDecryptionSuccessful = false;
        m_testDecryptedSize = 0;

        m_packages.clear();
        m_dlcDirectory.clear();
    }

    const std::vector<DLCPackage>&
    CSkyDLCManager::GetPackages() const
    {
        return m_packages;
    }
}
