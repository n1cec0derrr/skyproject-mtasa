#include "StdInc.h"
#include "CSkyDLCManager.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <set>

namespace SkyDLC
{
    namespace
    {
        constexpr char     DLC_MAGIC[8] = {'S', 'K', 'Y', 'D', 'L', 'C', '3', '\0'};
        constexpr uint32_t HEADER_SIZE = 68;
        constexpr uint32_t HEADER_AUTH_SIZE = 52;
        constexpr uint32_t SALT_OFFSET = 36;
        constexpr uint32_t SALT_SIZE = 16;
        constexpr uint32_t MIN_CHUNK_SIZE = 4096;
        constexpr uint32_t MAX_CHUNK_SIZE = 16 * 1024 * 1024;
        constexpr uint32_t MAX_TOC_SIZE = 64 * 1024 * 1024;
        constexpr size_t   CACHE_SLOTS = 8;

        enum : uint32_t
        {
            NONCE_DOMAIN_CHUNK = 0,
            NONCE_DOMAIN_TOC = 1
        };

        AESNonce MakeNonce(uint32_t domain, uint64_t index)
        {
            AESNonce nonce{};
            std::memcpy(nonce.data(), &domain, sizeof(domain));
            std::memcpy(nonce.data() + sizeof(domain), &index, sizeof(index));
            return nonce;
        }

        template <typename T>
        T ReadValue(const uint8_t* data)
        {
            T value;
            std::memcpy(&value, data, sizeof(value));
            return value;
        }

        bool ReadAt(HANDLE file, uint64_t offset, void* buffer, DWORD size)
        {
            OVERLAPPED overlapped{};
            overlapped.Offset = static_cast<DWORD>(offset);
            overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32);

            DWORD bytesRead = 0;
            return ::ReadFile(file, buffer, size, &bytesRead, &overlapped) && bytesRead == size;
        }
    }

    class CSkyDLCPackage
    {
    public:
        CSkyDLCPackage() { InitializeCriticalSection(&m_lock); }

        ~CSkyDLCPackage()
        {
            if (m_file != INVALID_HANDLE_VALUE)
                CloseHandle(m_file);

            DeleteCriticalSection(&m_lock);
        }

        CSkyDLCPackage(const CSkyDLCPackage&) = delete;
        CSkyDLCPackage& operator=(const CSkyDLCPackage&) = delete;

        bool Open(const fs::path& path, const AESKey& masterKey, std::vector<std::pair<std::string, DLCFile>>& files);
        bool Read(uint64_t offset, uint8_t* buffer, uint32_t size);

        const fs::path& GetPath() const { return m_path; }

    private:
        struct SCacheSlot
        {
            uint64_t             index = UINT64_MAX;
            std::vector<uint8_t> data;
        };

        uint32_t GetChunkSize(uint64_t index) const
        {
            const uint64_t remaining = m_plainSize - index * m_chunkSize;
            return static_cast<uint32_t>(std::min<uint64_t>(remaining, m_chunkSize));
        }

        bool           DecryptChunk(uint64_t index, uint8_t* output);
        const uint8_t* GetCachedChunk(uint64_t index);

        fs::path         m_path;
        HANDLE           m_file = INVALID_HANDLE_VALUE;
        CRITICAL_SECTION m_lock;
        CSkyDLCCipher    m_cipher;
        uint64_t         m_plainSize = 0;
        uint32_t         m_chunkSize = 0;

        std::vector<uint8_t>                m_encrypted;
        std::array<SCacheSlot, CACHE_SLOTS> m_cache;
        size_t                              m_nextSlot = 0;
    };

    bool CSkyDLCPackage::Open(const fs::path& path, const AESKey& masterKey, std::vector<std::pair<std::string, DLCFile>>& files)
    {
        m_path = path;
        m_file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (m_file == INVALID_HANDLE_VALUE)
            return false;

        LARGE_INTEGER fileSize{};

        if (!GetFileSizeEx(m_file, &fileSize))
            return false;

        std::array<uint8_t, HEADER_SIZE> header{};

        if (!ReadAt(m_file, 0, header.data(), HEADER_SIZE))
            return false;

        if (std::memcmp(header.data(), DLC_MAGIC, sizeof(DLC_MAGIC)) != 0 || ReadValue<uint32_t>(&header[8]) != FORMAT_VERSION)
            return false;

        m_chunkSize = ReadValue<uint32_t>(&header[16]);

        const uint64_t tocOffset = ReadValue<uint64_t>(&header[24]);
        const uint32_t tocSize = ReadValue<uint32_t>(&header[32]);

        if (m_chunkSize < MIN_CHUNK_SIZE || m_chunkSize > MAX_CHUNK_SIZE || tocSize < 12 || tocSize > MAX_TOC_SIZE ||
            tocOffset != static_cast<uint64_t>(fileSize.QuadPart) - tocSize)
            return false;

        AESKey     packageKey{};
        const bool keyReady = CSkyDLCCrypto::DeriveKey(masterKey, &header[SALT_OFFSET], SALT_SIZE, packageKey) && m_cipher.Open(packageKey);

        SecureZeroMemory(packageKey.data(), packageKey.size());

        if (!keyReady)
            return false;

        std::vector<uint8_t> encryptedToc(tocSize);
        std::vector<uint8_t> toc(tocSize);

        if (!ReadAt(m_file, tocOffset, encryptedToc.data(), tocSize))
            return false;

        // Also authenticates the header
        if (!m_cipher.Decrypt(MakeNonce(NONCE_DOMAIN_TOC, 0), header.data(), HEADER_AUTH_SIZE, encryptedToc.data(), tocSize, &header[HEADER_AUTH_SIZE], toc.data()))
            return false;

        m_plainSize = ReadValue<uint64_t>(&toc[0]);

        const uint32_t entryCount = ReadValue<uint32_t>(&toc[8]);
        size_t         position = 12;

        for (uint32_t i = 0; i < entryCount; i++)
        {
            if (position + sizeof(uint16_t) > toc.size())
                return false;

            const uint16_t pathSize = ReadValue<uint16_t>(&toc[position]);
            position += sizeof(uint16_t);

            if (position + pathSize + 2 * sizeof(uint64_t) > toc.size())
                return false;

            std::string name(reinterpret_cast<const char*>(&toc[position]), pathSize);
            position += pathSize;

            DLCFile file;
            file.package = this;
            file.offset = ReadValue<uint64_t>(&toc[position]);
            file.size = ReadValue<uint64_t>(&toc[position + sizeof(uint64_t)]);
            position += 2 * sizeof(uint64_t);

            if (file.offset > m_plainSize || file.size > m_plainSize - file.offset)
                return false;

            files.emplace_back(std::move(name), file);
        }

        m_encrypted.resize(m_chunkSize + AES_TAG_SIZE);

        for (SCacheSlot& slot : m_cache)
            slot.data.resize(m_chunkSize);

        return true;
    }

    bool CSkyDLCPackage::DecryptChunk(uint64_t index, uint8_t* output)
    {
        const uint32_t size = GetChunkSize(index);
        const uint64_t offset = HEADER_SIZE + index * (static_cast<uint64_t>(m_chunkSize) + AES_TAG_SIZE);

        if (!ReadAt(m_file, offset, m_encrypted.data(), size + AES_TAG_SIZE))
            return false;

        return m_cipher.Decrypt(MakeNonce(NONCE_DOMAIN_CHUNK, index), nullptr, 0, m_encrypted.data(), size, m_encrypted.data() + size, output);
    }

    const uint8_t* CSkyDLCPackage::GetCachedChunk(uint64_t index)
    {
        for (SCacheSlot& slot : m_cache)
        {
            if (slot.index == index)
                return slot.data.data();
        }

        SCacheSlot& slot = m_cache[m_nextSlot];
        m_nextSlot = (m_nextSlot + 1) % m_cache.size();

        slot.index = UINT64_MAX;

        if (!DecryptChunk(index, slot.data.data()))
            return nullptr;

        slot.index = index;
        return slot.data.data();
    }

    bool CSkyDLCPackage::Read(uint64_t offset, uint8_t* buffer, uint32_t size)
    {
        EnterCriticalSection(&m_lock);

        bool success = true;

        while (size > 0)
        {
            const uint64_t index = offset / m_chunkSize;
            const uint32_t chunkOffset = static_cast<uint32_t>(offset % m_chunkSize);
            const uint32_t chunkSize = GetChunkSize(index);
            const uint32_t piece = std::min(size, chunkSize - chunkOffset);

            // Whole chunks of a model go straight to the game's buffer
            if (piece == chunkSize)
            {
                success = DecryptChunk(index, buffer);
            }
            else if (const uint8_t* chunk = GetCachedChunk(index))
            {
                std::memcpy(buffer, chunk + chunkOffset, piece);
            }
            else
            {
                success = false;
            }

            if (!success)
                break;

            offset += piece;
            buffer += piece;
            size -= piece;
        }

        LeaveCriticalSection(&m_lock);
        return success;
    }

    CSkyDLCManager::CSkyDLCManager() = default;
    CSkyDLCManager::~CSkyDLCManager() = default;

    bool CSkyDLCManager::Initialize(const fs::path& dlcDirectory, const AESKey& masterKey)
    {
        Shutdown();

        std::error_code ec;

        if (!fs::is_directory(dlcDirectory, ec))
        {
            WriteDebugEvent("SkyDLC: directory not found");
            return true;
        }

        std::vector<fs::path> paths;

        for (const auto& entry : fs::directory_iterator(dlcDirectory, fs::directory_options::skip_permission_denied, ec))
        {
            if (entry.is_regular_file(ec) && entry.path().extension() == L".skydlc")
                paths.push_back(entry.path());
        }

        // Packages loaded later override the earlier ones, so the order must not depend on the file system
        std::sort(paths.begin(), paths.end());

        bool success = !ec;

        for (const fs::path& path : paths)
        {
            if (!LoadPackage(path, masterKey))
            {
                WriteDebugEvent(SString("SkyDLC: rejected package: %s", path.filename().string().c_str()));
                success = false;
            }
        }

        AddPatchArchivesToGtaDat();

        return success;
    }

    // An archive (.img) that a patch (zz_*.skydlc) brings is put into data/gta.dat before every other IMG line.
    // The game takes a model from the first archive that has it, so the patch replaces models of the main
    // package (a car in data/Paths/skyproject_vehs.img) and no patch has to carry its own gta.dat.
    // gta3.img and gta_int.img are opened by the engine before gta.dat: their models a patch cannot replace.
    void CSkyDLCManager::AddPatchArchivesToGtaDat()
    {
        if (m_patchArchives.empty())
            return;

        const auto it = m_files.find("data/gta.dat");
        if (it == m_files.end())
        {
            WriteDebugEvent("SkyDLC: patch archives not added, no data/gta.dat in the packages");
            return;
        }

        std::string original;
        if (!ReadFile("data/gta.dat", original))
        {
            WriteDebugEvent("SkyDLC: patch archives not added, data/gta.dat cannot be read");
            return;
        }

        const std::string newline = original.find("\r\n") != std::string::npos ? "\r\n" : "\n";

        // Where the first IMG line starts, and which archives gta.dat already has
        size_t                firstImg = std::string::npos;
        std::set<std::string> listed;
        for (size_t start = 0; start < original.size();)
        {
            size_t end = original.find('\n', start);
            if (end == std::string::npos)
                end = original.size();

            std::string line = original.substr(start, end - start);
            const size_t first = line.find_first_not_of(" \t");
            line = first == std::string::npos ? std::string() : line.substr(first);
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
                line.pop_back();

            if (line.size() > 4 && NormalizePath(line.substr(0, 4)) == "img ")
            {
                if (firstImg == std::string::npos)
                    firstImg = start;
                std::string path = line.substr(4);
                path.erase(0, path.find_first_not_of(" \t"));
                listed.insert(NormalizePath(path));
            }
            start = end + 1;
        }

        std::string lines;
        for (const std::string& archive : m_patchArchives)
        {
            if (listed.count(archive))
                continue;
            std::string native = archive;
            std::replace(native.begin(), native.end(), '/', '\\');
            lines += "IMG " + native + newline;
            WriteDebugEvent(SString("SkyDLC: patch archive added to gta.dat: %s", archive.c_str()));
        }
        if (lines.empty())
            return;

        auto text = std::make_shared<std::string>(original);
        text->insert(firstImg == std::string::npos ? text->size() : firstImg, lines);

        DLCFile file;
        file.package = it->second.package;
        file.size = text->size();
        file.memory = std::move(text);
        it->second = std::move(file);
    }

    bool CSkyDLCManager::LoadPackage(const fs::path& path, const AESKey& masterKey)
    {
        auto package = std::make_unique<CSkyDLCPackage>();

        std::vector<std::pair<std::string, DLCFile>> files;

        if (!package->Open(path, masterKey, files))
            return false;

        const std::string fileName = NormalizePath(path.filename().string());
        const bool        isPatch = fileName.rfind("zz_", 0) == 0;

        for (auto& [name, file] : files)
        {
            std::string normalized = NormalizePath(std::move(name));

            // A new archive of a patch (not one that replaces an archive of the main package as a whole)
            if (isPatch && normalized.size() > 4 && normalized.compare(normalized.size() - 4, 4, ".img") == 0 && !m_files.count(normalized) &&
                std::find(m_patchArchives.begin(), m_patchArchives.end(), normalized) == m_patchArchives.end())
                m_patchArchives.push_back(normalized);

            m_files[std::move(normalized)] = file;
        }

        WriteDebugEvent(SString("SkyDLC: loaded package: %s, files=%d", path.filename().string().c_str(), static_cast<int>(files.size())));

        m_packages.push_back(std::move(package));
        return true;
    }

    void CSkyDLCManager::Shutdown()
    {
        m_patchArchives.clear();
        m_files.clear();
        m_packages.clear();
    }

    std::string CSkyDLCManager::NormalizePath(std::string path)
    {
        std::replace(path.begin(), path.end(), '\\', '/');
        std::transform(path.begin(), path.end(), path.begin(),
                       [](unsigned char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : static_cast<char>(c); });
        return path;
    }

    const DLCFile* CSkyDLCManager::FindFile(std::string path) const
    {
        if (m_files.empty())
            return nullptr;

        const auto it = m_files.find(NormalizePath(std::move(path)));
        return it != m_files.end() ? &it->second : nullptr;
    }

    bool CSkyDLCManager::Read(const DLCFile& file, uint64_t offset, void* buffer, uint32_t size, uint32_t& bytesRead) const
    {
        bytesRead = 0;

        if (offset >= file.size)
            return true;

        const uint32_t available = static_cast<uint32_t>(std::min<uint64_t>(file.size - offset, size));

        if (file.memory)
        {
            std::memcpy(buffer, file.memory->data() + offset, available);
            bytesRead = available;
            return true;
        }

        if (available > 0 && !file.package->Read(file.offset + offset, static_cast<uint8_t*>(buffer), available))
            return false;

        bytesRead = available;
        return true;
    }

    bool CSkyDLCManager::ReadFile(const std::string& path, std::string& data) const
    {
        const DLCFile* file = FindFile(path);

        if (!file || file->size > std::numeric_limits<uint32_t>::max())
            return false;

        data.resize(static_cast<size_t>(file->size));

        uint32_t bytesRead = 0;
        return Read(*file, 0, data.data(), static_cast<uint32_t>(data.size()), bytesRead) && bytesRead == data.size();
    }

    const fs::path& CSkyDLCManager::GetPackagePath(const DLCFile& file) const
    {
        return file.package->GetPath();
    }

    CSkyDLCManager& GetDLCManager()
    {
        static CSkyDLCManager manager;
        return manager;
    }
}
