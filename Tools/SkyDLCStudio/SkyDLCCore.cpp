#include "SkyDLCCore.h"

#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <cstring>
#include <fstream>
#include <memory>
#include <set>
#include <sstream>

#pragma comment(lib, "bcrypt.lib")

namespace sky
{
    namespace
    {
        // ------------------------------------------------------------ format v3, must match Client/core/DLC/CSkyDLCManager.cpp

        constexpr char     MAGIC[8] = {'S', 'K', 'Y', 'D', 'L', 'C', '3', '\0'};
        constexpr uint32_t FORMAT_VERSION = 3;
        constexpr uint32_t HEADER_SIZE = 68;
        constexpr uint32_t HEADER_AUTH_SIZE = 52;
        constexpr uint32_t SALT_OFFSET = 36;
        constexpr uint32_t SALT_SIZE = 16;
        constexpr uint32_t TAG_SIZE = 16;
        constexpr uint32_t CHUNK_SIZE = 64 * 1024;
        constexpr uint32_t MIN_CHUNK_SIZE = 4096;
        constexpr uint32_t MAX_CHUNK_SIZE = 16 * 1024 * 1024;
        constexpr uint32_t MAX_TOC_SIZE = 64 * 1024 * 1024;

        constexpr uint32_t TYPE_MAP = 3;
        constexpr uint32_t TYPE_OTHER = 255;

        // ------------------------------------------------------------ IMG VER2

        constexpr uint32_t SECTOR = 2048;
        constexpr size_t   IMG_NAME_SIZE = 24;
        constexpr uint32_t IMG_ENTRY_SIZE = 32;

        // ------------------------------------------------------------ studio layout

        const char*    FILES_ID = "files";
        const char*    PATCH_ID = "patch";             // models of the patch IMG
        const char*    PATCH_FILES_ID = "patchfiles";  // data files of the patch (single layout)
        const wchar_t* FILES_PACKAGE = L"files.skydlc";
        const wchar_t* SINGLE_PACKAGE = L"sky_project.skydlc";
        const wchar_t* PATCH_PACKAGE = L"zz_patch.skydlc";  // sorts after the others, so it overrides them
        const char*    PATCH_IMG = "models/sky_patch.img";
        const char*    PATCH_LINE = "IMG models\\sky_patch.img";
        const char*    GTA_DAT = "data/gta.dat";
        const wchar_t* STATE_DIR = L".skystudio";
        const wchar_t* STATE_FILE = L"state.txt";

        using Nonce = std::array<uint8_t, 12>;

        [[noreturn]] void Fail(const std::wstring& message) { throw Error(message); }

        std::string Lower(std::string text)
        {
            for (char& c : text)
                if (c >= 'A' && c <= 'Z')
                    c = static_cast<char>(c + 32);
            return text;
        }

        std::wstring LowerW(std::wstring text)
        {
            for (wchar_t& c : text)
                c = static_cast<wchar_t>(towlower(c));
            return text;
        }

        std::string Generic(const fs::path& path) { return Narrow(path.generic_wstring()); }

        std::wstring Native(const std::string& generic)
        {
            std::wstring text = Widen(generic);
            std::replace(text.begin(), text.end(), L'/', L'\\');
            return text;
        }

        template <typename T>
        void Put(uint8_t* data, T value)
        {
            std::memcpy(data, &value, sizeof(value));
        }

        template <typename T>
        void Append(Bytes& data, T value)
        {
            const size_t position = data.size();
            data.resize(position + sizeof(value));
            std::memcpy(data.data() + position, &value, sizeof(value));
        }

        template <typename T>
        T Get(const uint8_t* data)
        {
            T value;
            std::memcpy(&value, data, sizeof(value));
            return value;
        }

        Nonce MakeNonce(uint32_t domain, uint64_t index)
        {
            Nonce nonce{};
            std::memcpy(nonce.data(), &domain, sizeof(domain));
            std::memcpy(nonce.data() + sizeof(domain), &index, sizeof(index));
            return nonce;
        }

        std::wstring Hex(const uint8_t* data, size_t size)
        {
            static const wchar_t digits[] = L"0123456789ABCDEF";
            std::wstring         text;
            for (size_t i = 0; i < size; i++)
            {
                text += digits[data[i] >> 4];
                text += digits[data[i] & 15];
            }
            return text;
        }

        // ------------------------------------------------------------ crypto (BCrypt, same as the client)

        void RandomBytes(uint8_t* data, size_t size)
        {
            if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, data, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
                Fail(L"BCryptGenRandom не сработал");
        }

        Key DeriveKey(const Key& master, const uint8_t* salt)
        {
            static constexpr char LABEL[] = "SkyDLC3";

            BCRYPT_ALG_HANDLE  algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            Key                result{};

            const bool ok = BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)) &&
                            BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, nullptr, 0, const_cast<PUCHAR>(master.data()), 32, 0)) &&
                            BCRYPT_SUCCESS(BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(LABEL)), sizeof(LABEL) - 1, 0)) &&
                            BCRYPT_SUCCESS(BCryptHashData(hash, const_cast<PUCHAR>(salt), SALT_SIZE, 0)) &&
                            BCRYPT_SUCCESS(BCryptFinishHash(hash, result.data(), 32, 0));

            if (hash)
                BCryptDestroyHash(hash);
            if (algorithm)
                BCryptCloseAlgorithmProvider(algorithm, 0);
            if (!ok)
                Fail(L"HMAC-SHA256 не сработал");
            return result;
        }

        class Cipher
        {
        public:
            explicit Cipher(const Key& key)
            {
                DWORD length = 0, returned = 0;

                if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&m_algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0)) ||
                    !BCRYPT_SUCCESS(BCryptSetProperty(m_algorithm, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                                                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0)) ||
                    !BCRYPT_SUCCESS(BCryptGetProperty(m_algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&length), sizeof(length), &returned, 0)))
                    Fail(L"AES-GCM недоступен");

                m_object.resize(length);

                if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(m_algorithm, &m_key, m_object.data(), length, const_cast<PUCHAR>(key.data()), 32, 0)))
                    Fail(L"не удалось подготовить ключ AES");
            }

            ~Cipher()
            {
                if (m_key)
                    BCryptDestroyKey(m_key);
                if (!m_object.empty())
                    SecureZeroMemory(m_object.data(), m_object.size());
                if (m_algorithm)
                    BCryptCloseAlgorithmProvider(m_algorithm, 0);
            }

            Cipher(const Cipher&) = delete;
            Cipher& operator=(const Cipher&) = delete;

            void Encrypt(const Nonce& nonce, const uint8_t* aad, uint32_t aadSize, const uint8_t* input, uint32_t size, uint8_t* output, uint8_t* tag)
            {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
                BCRYPT_INIT_AUTH_MODE_INFO(info);
                info.pbNonce = const_cast<PUCHAR>(nonce.data());
                info.cbNonce = static_cast<ULONG>(nonce.size());
                info.pbAuthData = const_cast<PUCHAR>(aad);
                info.cbAuthData = aadSize;
                info.pbTag = tag;
                info.cbTag = TAG_SIZE;

                ULONG written = 0;
                if (!BCRYPT_SUCCESS(BCryptEncrypt(m_key, const_cast<PUCHAR>(input), size, &info, nullptr, 0, output, size, &written, 0)) || written != size)
                    Fail(L"ошибка шифрования AES-GCM");
            }

            bool Decrypt(const Nonce& nonce, const uint8_t* aad, uint32_t aadSize, const uint8_t* input, uint32_t size, const uint8_t* tag, uint8_t* output)
            {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
                BCRYPT_INIT_AUTH_MODE_INFO(info);
                info.pbNonce = const_cast<PUCHAR>(nonce.data());
                info.cbNonce = static_cast<ULONG>(nonce.size());
                info.pbAuthData = const_cast<PUCHAR>(aad);
                info.cbAuthData = aadSize;
                info.pbTag = const_cast<PUCHAR>(tag);
                info.cbTag = TAG_SIZE;

                ULONG written = 0;
                return BCRYPT_SUCCESS(BCryptDecrypt(m_key, const_cast<PUCHAR>(input), size, &info, nullptr, 0, output, size, &written, 0)) && written == size;
            }

        private:
            BCRYPT_ALG_HANDLE m_algorithm = nullptr;
            BCRYPT_KEY_HANDLE m_key = nullptr;
            Bytes             m_object;
        };

        class Hasher
        {
        public:
            Hasher()
            {
                if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&m_algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) ||
                    !BCRYPT_SUCCESS(BCryptCreateHash(m_algorithm, &m_hash, nullptr, 0, nullptr, 0, 0)))
                    Fail(L"SHA-256 недоступен");
            }

            ~Hasher()
            {
                if (m_hash)
                    BCryptDestroyHash(m_hash);
                if (m_algorithm)
                    BCryptCloseAlgorithmProvider(m_algorithm, 0);
            }

            Hasher(const Hasher&) = delete;
            Hasher& operator=(const Hasher&) = delete;

            void Update(const uint8_t* data, size_t size)
            {
                if (size && !BCRYPT_SUCCESS(BCryptHashData(m_hash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0)))
                    Fail(L"ошибка SHA-256");
            }

            Hash Finish()
            {
                std::array<uint8_t, 32> full{};
                if (!BCRYPT_SUCCESS(BCryptFinishHash(m_hash, full.data(), 32, 0)))
                    Fail(L"ошибка SHA-256");
                Hash result{};
                std::memcpy(result.data(), full.data(), result.size());
                return result;
            }

        private:
            BCRYPT_ALG_HANDLE  m_algorithm = nullptr;
            BCRYPT_HASH_HANDLE m_hash = nullptr;
        };

        // ------------------------------------------------------------ files

        class InFile
        {
        public:
            explicit InFile(const fs::path& path) : m_path(path)
            {
                m_handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
                if (m_handle == INVALID_HANDLE_VALUE)
                    Fail(L"не удалось открыть " + path.wstring());
            }

            ~InFile()
            {
                if (m_handle != INVALID_HANDLE_VALUE)
                    CloseHandle(m_handle);
            }

            InFile(const InFile&) = delete;
            InFile& operator=(const InFile&) = delete;

            uint64_t Size() const
            {
                LARGE_INTEGER size{};
                GetFileSizeEx(m_handle, &size);
                return static_cast<uint64_t>(size.QuadPart);
            }

            void Seek(uint64_t offset)
            {
                LARGE_INTEGER position;
                position.QuadPart = static_cast<LONGLONG>(offset);
                if (!SetFilePointerEx(m_handle, position, nullptr, FILE_BEGIN))
                    Fail(L"ошибка чтения " + m_path.wstring());
            }

            // Reads up to size bytes, returns how many were read
            size_t ReadSome(void* buffer, size_t size)
            {
                size_t total = 0;
                while (total < size)
                {
                    const DWORD piece = static_cast<DWORD>(std::min<size_t>(size - total, 16 * 1024 * 1024));
                    DWORD       read = 0;
                    if (!ReadFile(m_handle, static_cast<uint8_t*>(buffer) + total, piece, &read, nullptr))
                        Fail(L"ошибка чтения " + m_path.wstring());
                    if (read == 0)
                        break;
                    total += read;
                }
                return total;
            }

            void Read(void* buffer, size_t size)
            {
                if (ReadSome(buffer, size) != size)
                    Fail(L"файл изменился во время сборки или обрезан: " + m_path.wstring());
            }

        private:
            fs::path m_path;
            HANDLE   m_handle = INVALID_HANDLE_VALUE;
        };

        class OutFile
        {
        public:
            explicit OutFile(const fs::path& path) : m_path(path)
            {
                m_handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
                if (m_handle == INVALID_HANDLE_VALUE)
                    Fail(L"не удалось создать " + path.wstring());
                m_buffer.reserve(BUFFER_SIZE);
            }

            ~OutFile()
            {
                if (m_handle != INVALID_HANDLE_VALUE)
                    CloseHandle(m_handle);
            }

            OutFile(const OutFile&) = delete;
            OutFile& operator=(const OutFile&) = delete;

            void Write(const void* data, size_t size)
            {
                const uint8_t* bytes = static_cast<const uint8_t*>(data);
                if (m_buffer.size() + size > BUFFER_SIZE)
                    Flush();
                if (size >= BUFFER_SIZE)
                    WriteRaw(bytes, size);
                else
                    m_buffer.insert(m_buffer.end(), bytes, bytes + size);
            }

            void Close()
            {
                Flush();
                if (!FlushFileBuffers(m_handle))
                    Fail(L"ошибка записи " + m_path.wstring());
                CloseHandle(m_handle);
                m_handle = INVALID_HANDLE_VALUE;
            }

        private:
            static constexpr size_t BUFFER_SIZE = 4 * 1024 * 1024;

            void Flush()
            {
                if (!m_buffer.empty())
                    WriteRaw(m_buffer.data(), m_buffer.size());
                m_buffer.clear();
            }

            void WriteRaw(const uint8_t* data, size_t size)
            {
                while (size > 0)
                {
                    const DWORD piece = static_cast<DWORD>(std::min<size_t>(size, 64 * 1024 * 1024));
                    DWORD       written = 0;
                    if (!WriteFile(m_handle, data, piece, &written, nullptr) || written != piece)
                        Fail(L"ошибка записи (место на диске?) " + m_path.wstring());
                    data += piece;
                    size -= piece;
                }
            }

            fs::path m_path;
            HANDLE   m_handle = INVALID_HANDLE_VALUE;
            Bytes    m_buffer;
        };

        int64_t ModifiedTime(const fs::path& path)
        {
            std::error_code ec;
            const auto      time = fs::last_write_time(path, ec);
            return ec ? 0 : static_cast<int64_t>(time.time_since_epoch().count());
        }

        Hash HashFile(const fs::path& path)
        {
            InFile file(path);
            Hasher hasher;
            Bytes  buffer(1024 * 1024);
            for (;;)
            {
                const size_t read = file.ReadSome(buffer.data(), buffer.size());
                if (read == 0)
                    break;
                hasher.Update(buffer.data(), read);
            }
            return hasher.Finish();
        }

        void ReplaceFile(const fs::path& from, const fs::path& to)
        {
            if (!MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                Fail(L"не удалось заменить " + to.wstring() + L" (игра запущена и держит пакет открытым?)");
        }

        // A file just written may be held for a moment by an antivirus or the indexer, so a few tries
        bool TryRemoveFile(const fs::path& path, std::wstring& error)
        {
            std::error_code ec;
            for (int attempt = 0; attempt < 10; attempt++)
            {
                if (!fs::exists(path, ec) || fs::remove(path, ec))
                    return true;
                Sleep(300);
            }
            error = Widen(ec.message());
            return false;
        }

        void RemoveFile(const fs::path& path)
        {
            std::wstring error;
            if (!TryRemoveFile(path, error))
                Fail(L"не удалось удалить " + path.wstring() + L": " + error);
        }

        // ------------------------------------------------------------ plain data of a package, produced on the fly

        struct Segment
        {
            enum class Kind
            {
                Memory,
                File,
                Zero
            };

            Kind                   kind = Kind::Zero;
            std::shared_ptr<Bytes> memory;
            fs::path               path;
            uint64_t               size = 0;
            Hash*                  hashOut = nullptr;  // filled with the hash of a File segment as it is read
            std::string            label;              // entry name for error messages
        };

        class SegmentReader
        {
        public:
            explicit SegmentReader(const std::vector<Segment>& segments) : m_segments(segments) {}

            void Read(uint8_t* output, size_t size)
            {
                while (size > 0)
                {
                    if (m_index >= m_segments.size())
                        Fail(L"внутренняя ошибка: данные пакета кончились раньше времени");

                    const Segment& segment = m_segments[m_index];
                    const size_t   piece = static_cast<size_t>(std::min<uint64_t>(size, segment.size - m_offset));

                    if (piece > 0)
                    {
                        if (segment.kind == Segment::Kind::Memory)
                        {
                            std::memcpy(output, segment.memory->data() + m_offset, piece);
                        }
                        else if (segment.kind == Segment::Kind::Zero)
                        {
                            std::memset(output, 0, piece);
                        }
                        else
                        {
                            if (!m_file)
                            {
                                m_file = std::make_unique<InFile>(segment.path);
                                if (m_file->Size() != segment.size)
                                    Fail(L"файл изменился во время сборки: " + segment.path.wstring());
                                if (segment.hashOut)
                                    m_hasher = std::make_unique<Hasher>();
                            }
                            m_file->Read(output, piece);
                            if (m_hasher)
                                m_hasher->Update(output, piece);
                        }
                    }

                    output += piece;
                    size -= piece;
                    m_offset += piece;

                    if (m_offset == segment.size)
                    {
                        if (segment.kind == Segment::Kind::File)
                        {
                            if (!m_file && segment.hashOut)  // empty file
                                m_hasher = std::make_unique<Hasher>();
                            if (m_hasher)
                                *segment.hashOut = m_hasher->Finish();
                        }
                        m_file.reset();
                        m_hasher.reset();
                        m_index++;
                        m_offset = 0;
                    }
                }
            }

            // Name of the entry at a position of the plain data, for "differs" messages
            std::string LabelAt(uint64_t position) const
            {
                uint64_t start = 0;
                for (const Segment& segment : m_segments)
                {
                    if (position < start + segment.size)
                        return segment.label.empty() ? "служебные данные" : segment.label;
                    start += segment.size;
                }
                return "?";
            }

        private:
            const std::vector<Segment>& m_segments;
            size_t                      m_index = 0;
            uint64_t                    m_offset = 0;
            std::unique_ptr<InFile>     m_file;
            std::unique_ptr<Hasher>     m_hasher;
        };

        uint64_t TotalSize(const std::vector<Segment>& segments)
        {
            uint64_t total = 0;
            for (const Segment& segment : segments)
                total += segment.size;
            return total;
        }

        struct TocEntry
        {
            std::string name;
            uint64_t    offset = 0;
            uint64_t    size = 0;
        };

        Bytes MakeToc(const std::vector<TocEntry>& entries, uint64_t total)
        {
            Bytes toc;
            Append<uint64_t>(toc, total);
            Append<uint32_t>(toc, static_cast<uint32_t>(entries.size()));
            for (const TocEntry& entry : entries)
            {
                if (entry.name.size() > 0xFFFF)
                    Fail(L"слишком длинный путь: " + Widen(entry.name));
                Append<uint16_t>(toc, static_cast<uint16_t>(entry.name.size()));
                toc.insert(toc.end(), entry.name.begin(), entry.name.end());
                Append<uint64_t>(toc, entry.offset);
                Append<uint64_t>(toc, entry.size);
            }
            if (toc.size() > MAX_TOC_SIZE)
                Fail(L"слишком много файлов в одном пакете");
            return toc;
        }

        void WritePackage(const fs::path& output, uint32_t type, const std::vector<TocEntry>& entries, const std::vector<Segment>& segments, const Key& master,
                          Reporter& reporter, const std::wstring& stage)
        {
            const uint64_t total = TotalSize(segments);
            const Bytes    toc = MakeToc(entries, total);
            const uint64_t chunkCount = (total + CHUNK_SIZE - 1) / CHUNK_SIZE;
            const uint64_t tocOffset = HEADER_SIZE + chunkCount * TAG_SIZE + total;

            std::array<uint8_t, HEADER_SIZE> header{};
            std::memcpy(header.data(), MAGIC, sizeof(MAGIC));
            Put<uint32_t>(&header[8], FORMAT_VERSION);
            Put<uint32_t>(&header[12], type);
            Put<uint32_t>(&header[16], CHUNK_SIZE);
            Put<uint32_t>(&header[20], 0);
            Put<uint64_t>(&header[24], tocOffset);
            Put<uint32_t>(&header[32], static_cast<uint32_t>(toc.size()));
            RandomBytes(&header[SALT_OFFSET], SALT_SIZE);

            Key    packageKey = DeriveKey(master, &header[SALT_OFFSET]);
            Cipher cipher(packageKey);
            SecureZeroMemory(packageKey.data(), packageKey.size());

            // The TOC tag authenticates the header too
            Bytes encryptedToc(toc.size());
            cipher.Encrypt(MakeNonce(1, 0), header.data(), HEADER_AUTH_SIZE, toc.data(), static_cast<uint32_t>(toc.size()), encryptedToc.data(),
                           &header[HEADER_AUTH_SIZE]);

            OutFile out(output);
            out.Write(header.data(), HEADER_SIZE);

            SegmentReader reader(segments);
            Bytes         plain(CHUNK_SIZE), encrypted(CHUNK_SIZE + TAG_SIZE);

            for (uint64_t index = 0; index < chunkCount; index++)
            {
                const uint32_t size = static_cast<uint32_t>(std::min<uint64_t>(CHUNK_SIZE, total - index * CHUNK_SIZE));
                reader.Read(plain.data(), size);
                cipher.Encrypt(MakeNonce(0, index), nullptr, 0, plain.data(), size, encrypted.data(), encrypted.data() + size);
                out.Write(encrypted.data(), size + TAG_SIZE);

                if ((index & 63) == 0)
                {
                    reporter.Check();
                    reporter.Progress(stage, index * CHUNK_SIZE, total);
                }
            }

            out.Write(encryptedToc.data(), encryptedToc.size());
            out.Close();

            if (fs::file_size(output) != tocOffset + toc.size())
                Fail(L"размер записанного пакета не сходится: " + output.wstring());
        }

        // Reads the package the way the client does and compares every byte with the sources
        void VerifyPackage(const fs::path& path, const std::vector<TocEntry>* expectedEntries, const std::vector<Segment>* expected, const Key& master,
                           Reporter& reporter, const std::wstring& stage, std::vector<TocEntry>* entriesOut = nullptr)
        {
            InFile         in(path);
            const uint64_t fileSize = in.Size();

            std::array<uint8_t, HEADER_SIZE> header{};
            if (fileSize < HEADER_SIZE)
                Fail(L"пакет слишком маленький: " + path.wstring());
            in.Read(header.data(), HEADER_SIZE);

            if (std::memcmp(header.data(), MAGIC, sizeof(MAGIC)) != 0 || Get<uint32_t>(&header[8]) != FORMAT_VERSION)
                Fail(L"это не пакет SKYDLC3: " + path.wstring());

            const uint32_t chunkSize = Get<uint32_t>(&header[16]);
            const uint64_t tocOffset = Get<uint64_t>(&header[24]);
            const uint32_t tocSize = Get<uint32_t>(&header[32]);

            if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE || tocSize < 12 || tocSize > MAX_TOC_SIZE || tocOffset != fileSize - tocSize)
                Fail(L"клиент отклонит заголовок пакета: " + path.wstring());

            Key    packageKey = DeriveKey(master, &header[SALT_OFFSET]);
            Cipher cipher(packageKey);
            SecureZeroMemory(packageKey.data(), packageKey.size());

            Bytes encryptedToc(tocSize), toc(tocSize);
            in.Seek(tocOffset);
            in.Read(encryptedToc.data(), tocSize);

            if (!cipher.Decrypt(MakeNonce(1, 0), header.data(), HEADER_AUTH_SIZE, encryptedToc.data(), tocSize, &header[HEADER_AUTH_SIZE], toc.data()))
                Fail(L"оглавление не расшифровывается (другой ключ или пакет повреждён): " + path.wstring());

            const uint64_t total = Get<uint64_t>(&toc[0]);
            const uint32_t count = Get<uint32_t>(&toc[8]);
            const uint64_t chunkCount = (total + chunkSize - 1) / chunkSize;

            if (HEADER_SIZE + chunkCount * TAG_SIZE + total != tocOffset)
                Fail(L"размер данных не совпадает с оглавлением: " + path.wstring());

            std::vector<TocEntry> entries;
            size_t                position = 12;
            for (uint32_t i = 0; i < count; i++)
            {
                if (position + 2 > toc.size())
                    Fail(L"оглавление повреждено");
                const uint16_t length = Get<uint16_t>(&toc[position]);
                position += 2;
                if (position + length + 16 > toc.size())
                    Fail(L"оглавление повреждено");

                TocEntry entry;
                entry.name.assign(reinterpret_cast<const char*>(&toc[position]), length);
                position += length;
                entry.offset = Get<uint64_t>(&toc[position]);
                entry.size = Get<uint64_t>(&toc[position + 8]);
                position += 16;

                if (entry.offset > total || entry.size > total - entry.offset)
                    Fail(L"запись оглавления за пределами данных: " + Widen(entry.name));
                entries.push_back(entry);
            }

            if (expectedEntries)
            {
                bool same = entries.size() == expectedEntries->size();
                for (size_t i = 0; same && i < entries.size(); i++)
                {
                    const TocEntry& a = entries[i];
                    const TocEntry& b = (*expectedEntries)[i];
                    same = a.name == b.name && a.offset == b.offset && a.size == b.size;
                }
                if (!same)
                    Fail(L"оглавление пакета не совпадает с ожидаемым: " + path.wstring());
            }

            if (expected && TotalSize(*expected) != total)
                Fail(L"размер данных пакета не совпадает с исходниками: " + path.wstring());

            std::unique_ptr<SegmentReader> reader;
            if (expected)
                reader = std::make_unique<SegmentReader>(*expected);

            Bytes encrypted(chunkSize + TAG_SIZE), plain(chunkSize), original(chunkSize);
            in.Seek(HEADER_SIZE);

            for (uint64_t index = 0; index < chunkCount; index++)
            {
                const uint32_t size = static_cast<uint32_t>(std::min<uint64_t>(chunkSize, total - index * chunkSize));
                in.Read(encrypted.data(), size + TAG_SIZE);

                if (!cipher.Decrypt(MakeNonce(0, index), nullptr, 0, encrypted.data(), size, encrypted.data() + size, plain.data()))
                    Fail(L"чанк " + std::to_wstring(index) + L" не расшифровывается: " + path.wstring());

                if (reader)
                {
                    reader->Read(original.data(), size);
                    if (std::memcmp(original.data(), plain.data(), size) != 0)
                    {
                        size_t at = 0;
                        while (original[at] == plain[at])
                            at++;
                        Fail(L"расшифрованные данные не совпадают с исходником (" + Widen(reader->LabelAt(index * chunkSize + at)) + L"): " + path.wstring());
                    }
                }

                if ((index & 63) == 0)
                {
                    reporter.Check();
                    reporter.Progress(stage, index * chunkSize, total);
                }
            }

            if (entriesOut)
                *entriesOut = std::move(entries);
        }

        // ------------------------------------------------------------ content folder

        struct Item
        {
            fs::path    path;
            std::string name;  // IMG entry name, or path relative to the content root for loose files
            uint64_t    size = 0;
            int64_t     mtime = 0;
            Hash        hash{};
        };

        struct Archive
        {
            std::string               id;    // "models/gta3.img", as on disk
            fs::path                  dir;
            std::vector<Item>         items;  // sorted by lower case name
            std::vector<std::wstring> problems;

            std::string  LowerId() const { return Lower(id); }
            std::wstring PackageName() const;
        };

        bool IsSpecialId(const std::string& key) { return key == FILES_ID || key == PATCH_ID || key == PATCH_FILES_ID; }

        // Package of an archive in the split layout: models/gta3.img -> models_gta3.skydlc
        std::wstring SplitPackageName(const std::string& id)
        {
            std::string name = Lower(id);
            if (name.size() > 4 && name.compare(name.size() - 4, 4, ".img") == 0)
                name.resize(name.size() - 4);
            std::replace(name.begin(), name.end(), '/', '_');
            return Widen(name) + L".skydlc";
        }

        std::wstring Archive::PackageName() const { return SplitPackageName(id); }

        // Where a record's content lives in the chosen layout
        std::wstring ExpectedPackage(const Settings& settings, const std::string& id)
        {
            const std::string key = Lower(id);
            if (key == PATCH_ID || key == PATCH_FILES_ID)
                return PATCH_PACKAGE;
            if (settings.single)
                return SINGLE_PACKAGE;
            return key == FILES_ID ? std::wstring(FILES_PACKAGE) : SplitPackageName(id);
        }

        struct Content
        {
            std::vector<Archive> archives;
            std::vector<Item>    files;  // sorted by lower case path
        };

        bool IsIgnoredName(const std::wstring& name)
        {
            const std::wstring lower = LowerW(name);
            return name.empty() || name[0] == L'.' || lower == L"thumbs.db" || lower == L"desktop.ini";
        }

        bool IsValidImgName(const std::string& name)
        {
            if (name.empty() || name.size() >= IMG_NAME_SIZE)
                return false;
            for (unsigned char c : name)
            {
                if (c < 0x20 || c > 0x7E)
                    return false;
            }
            return true;
        }

        Content ReadContent(const fs::path& root)
        {
            if (!fs::is_directory(root))
                Fail(L"папка контента не найдена: " + root.wstring());

            Content content;

            for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied); it != fs::recursive_directory_iterator(); ++it)
            {
                const fs::path& path = it->path();

                if (IsIgnoredName(path.filename().wstring()))
                {
                    if (it->is_directory())
                        it.disable_recursion_pending();
                    continue;
                }

                if (it->is_directory())
                {
                    if (LowerW(path.extension().wstring()) != L".img")
                        continue;

                    it.disable_recursion_pending();

                    Archive archive;
                    archive.id = Generic(fs::relative(path, root));
                    archive.dir = path;

                    for (const auto& entry : fs::directory_iterator(path))
                    {
                        const std::wstring fileName = entry.path().filename().wstring();
                        if (IsIgnoredName(fileName))
                            continue;

                        if (entry.is_directory())
                        {
                            archive.problems.push_back(L"вложенная папка не попадёт в IMG: " + fileName);
                            continue;
                        }

                        Item item;
                        item.path = entry.path();
                        item.name = Narrow(fileName);
                        item.size = entry.file_size();
                        item.mtime = ModifiedTime(item.path);

                        if (!IsValidImgName(item.name))
                            archive.problems.push_back(L"имя не подходит для IMG (латиница, до 23 символов): " + fileName);
                        else if ((item.size + SECTOR - 1) / SECTOR > 0xFFFF)
                            archive.problems.push_back(L"файл больше 128 МБ, IMG такой не вместит: " + fileName);
                        else
                            archive.items.push_back(std::move(item));
                    }

                    std::sort(archive.items.begin(), archive.items.end(), [](const Item& a, const Item& b) { return Lower(a.name) < Lower(b.name); });
                    content.archives.push_back(std::move(archive));
                }
                else if (it->is_regular_file())
                {
                    Item item;
                    item.path = path;
                    item.name = Generic(fs::relative(path, root));
                    item.size = it->file_size();
                    item.mtime = ModifiedTime(path);
                    content.files.push_back(std::move(item));
                }
            }

            std::sort(content.archives.begin(), content.archives.end(), [](const Archive& a, const Archive& b) { return a.LowerId() < b.LowerId(); });
            std::sort(content.files.begin(), content.files.end(), [](const Item& a, const Item& b) { return Lower(a.name) < Lower(b.name); });
            return content;
        }

        // ------------------------------------------------------------ what was built last time

        struct FileRecord
        {
            std::string name;
            uint64_t    size = 0;
            int64_t     mtime = 0;
            Hash        hash{};
        };

        struct PackageRecord
        {
            std::string                       id;
            std::wstring                      fileName;
            uint64_t                          packageSize = 0;
            std::map<std::string, FileRecord> files;  // by lower case name
        };

        struct State
        {
            std::map<std::string, PackageRecord> packages;  // by lower case id

            fs::path path;

            void Load(const fs::path& content)
            {
                path = content / STATE_DIR / STATE_FILE;
                packages.clear();

                std::ifstream in(path, std::ios::binary);
                if (!in)
                    return;

                PackageRecord* current = nullptr;
                std::string    line;

                while (std::getline(in, line))
                {
                    if (!line.empty() && line.back() == '\r')
                        line.pop_back();

                    std::vector<std::string> parts;
                    std::stringstream        stream(line);
                    std::string              part;
                    while (std::getline(stream, part, '\t'))
                        parts.push_back(part);

                    try
                    {
                        if (parts.size() == 4 && parts[0] == "P")
                        {
                            PackageRecord record;
                            record.id = parts[1];
                            record.fileName = Widen(parts[2]);
                            record.packageSize = std::stoull(parts[3]);
                            current = &(packages[Lower(record.id)] = record);
                        }
                        else if (parts.size() == 5 && parts[0] == "F" && current)
                        {
                            FileRecord file;
                            file.name = parts[1];
                            file.size = std::stoull(parts[2]);
                            file.mtime = std::stoll(parts[3]);
                            if (parts[4].size() != file.hash.size() * 2)
                                continue;
                            for (size_t i = 0; i < file.hash.size(); i++)
                                file.hash[i] = static_cast<uint8_t>(std::stoul(parts[4].substr(i * 2, 2), nullptr, 16));
                            current->files[Lower(file.name)] = file;
                        }
                    }
                    catch (const std::exception&)
                    {
                        // a damaged line only means that package gets rebuilt
                    }
                }
            }

            void Save() const
            {
                fs::create_directories(path.parent_path());

                // Hidden, so the folder does not look like content
                SetFileAttributesW(path.parent_path().c_str(), FILE_ATTRIBUTE_HIDDEN);

                std::string text = "# Sky DLC Studio: what each package was built from. Delete to rebuild everything.\n";
                for (const auto& [key, record] : packages)
                {
                    text += "P\t" + record.id + "\t" + Narrow(record.fileName) + "\t" + std::to_string(record.packageSize) + "\n";
                    for (const auto& [name, file] : record.files)
                        text += "F\t" + file.name + "\t" + std::to_string(file.size) + "\t" + std::to_string(file.mtime) + "\t" +
                                Narrow(Hex(file.hash.data(), file.hash.size())) + "\n";
                }

                fs::path temporary = path;
                temporary += L".tmp";
                {
                    std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
                    out << text;
                    if (!out)
                        Fail(L"не удалось записать " + temporary.wstring());
                }
                ReplaceFile(temporary, path);
            }
        };

        struct Diff
        {
            std::vector<const Item*> added, changed;
            std::vector<std::string> removed;

            bool Empty() const { return added.empty() && changed.empty() && removed.empty(); }

            std::wstring Describe() const
            {
                std::wstring text;
                if (!added.empty())
                    text += L"+" + std::to_wstring(added.size()) + L" ";
                if (!changed.empty())
                    text += L"~" + std::to_wstring(changed.size()) + L" ";
                if (!removed.empty())
                    text += L"-" + std::to_wstring(removed.size()) + L" ";
                if (!text.empty())
                    text.pop_back();
                return text;
            }
        };

        // Compares the folder with what the package was built from. Files whose date changed are
        // hashed, if the content is the same the new date is remembered so they are not hashed again.
        Diff Compare(std::vector<Item>& items, PackageRecord& record, Reporter& reporter, bool& stateChanged)
        {
            Diff                  diff;
            std::set<std::string> seen;

            for (Item& item : items)
            {
                const std::string key = Lower(item.name);
                seen.insert(key);

                auto it = record.files.find(key);
                if (it == record.files.end())
                {
                    diff.added.push_back(&item);
                    continue;
                }

                FileRecord& file = it->second;
                if (file.size != item.size)
                {
                    diff.changed.push_back(&item);
                    continue;
                }

                if (file.mtime == item.mtime)
                {
                    item.hash = file.hash;
                    continue;
                }

                reporter.Check();
                reporter.Progress(L"Проверка изменённых файлов: " + Widen(item.name), 0, 0);
                item.hash = HashFile(item.path);

                if (item.hash == file.hash)
                {
                    file.mtime = item.mtime;
                    stateChanged = true;
                }
                else
                {
                    diff.changed.push_back(&item);
                }
            }

            for (const auto& [key, file] : record.files)
            {
                if (!seen.count(key))
                    diff.removed.push_back(file.name);
            }

            return diff;
        }

        PackageRecord MakeRecord(const std::string& id, const std::wstring& fileName, uint64_t packageSize, const std::vector<Item>& items)
        {
            PackageRecord record;
            record.id = id;
            record.fileName = fileName;
            record.packageSize = packageSize;
            for (const Item& item : items)
                record.files[Lower(item.name)] = {item.name, item.size, item.mtime, item.hash};
            return record;
        }

        bool PackageMatchesRecord(const fs::path& dlc, const PackageRecord& record)
        {
            std::error_code ec;
            const uint64_t  size = fs::file_size(dlc / record.fileName, ec);
            return !ec && size == record.packageSize;
        }

        // ------------------------------------------------------------ building

        std::vector<Segment> ImgSegments(std::vector<Item>& items, std::vector<TocEntry>* layoutOut = nullptr)
        {
            const uint64_t count = items.size();
            const uint64_t directorySize = 8 + IMG_ENTRY_SIZE * count;
            const uint64_t firstSector = (directorySize + SECTOR - 1) / SECTOR;

            auto header = std::make_shared<Bytes>(static_cast<size_t>(firstSector * SECTOR), uint8_t(0));
            std::memcpy(header->data(), "VER2", 4);
            Put<uint32_t>(header->data() + 4, static_cast<uint32_t>(count));

            std::vector<Segment> segments;
            segments.push_back({Segment::Kind::Memory, header, {}, header->size(), nullptr, {}});

            uint64_t sector = firstSector;
            for (size_t i = 0; i < items.size(); i++)
            {
                Item&          item = items[i];
                const uint64_t sectors = (item.size + SECTOR - 1) / SECTOR;

                if (sectors > 0xFFFF)
                    Fail(L"файл больше 128 МБ: " + Widen(item.name));
                if (sector > 0xFFFFFFFFull)
                    Fail(L"IMG получается больше 8 ТБ");

                uint8_t* entry = header->data() + 8 + IMG_ENTRY_SIZE * i;
                Put<uint32_t>(entry, static_cast<uint32_t>(sector));
                Put<uint16_t>(entry + 4, static_cast<uint16_t>(sectors));
                Put<uint16_t>(entry + 6, 0);
                std::memcpy(entry + 8, item.name.data(), item.name.size());

                if (layoutOut)
                    layoutOut->push_back({item.name, sector * SECTOR, item.size});

                segments.push_back({Segment::Kind::File, nullptr, item.path, item.size, &item.hash, item.name});
                if (sectors * SECTOR > item.size)
                    segments.push_back({Segment::Kind::Zero, nullptr, {}, sectors * SECTOR - item.size, nullptr, {}});

                sector += sectors;
            }

            return segments;
        }

        // Writes to a temporary file, checks it, then puts it in place, so a failed build never leaves a broken package
        uint64_t WriteAndVerify(const fs::path& target, uint32_t type, const std::vector<TocEntry>& entries, const std::vector<Segment>& segments, const Key& master,
                                Reporter& reporter, const std::wstring& title)
        {
            fs::create_directories(target.parent_path());

            fs::path temporary = target;
            temporary += L".building";

            try
            {
                WritePackage(temporary, type, entries, segments, master, reporter, L"Шифрование " + title);

                // The hashes were taken while encrypting, the check reads the sources again
                std::vector<Hash> hashes;
                for (const Segment& segment : segments)
                    if (segment.hashOut)
                        hashes.push_back(*segment.hashOut);

                VerifyPackage(temporary, &entries, &segments, master, reporter, L"Проверка " + title);

                size_t index = 0;
                for (const Segment& segment : segments)
                {
                    if (segment.hashOut && *segment.hashOut != hashes[index++])
                        Fail(L"файл изменился во время сборки: " + segment.path.wstring());
                }

                ReplaceFile(temporary, target);
            }
            catch (...)
            {
                std::error_code ec;
                fs::remove(temporary, ec);
                throw;
            }

            return fs::file_size(target);
        }

        uint64_t BuildImgPackage(const fs::path& target, const std::string& imgPath, std::vector<Item>& items, const Key& master, Reporter& reporter,
                                 uint32_t type)
        {
            std::vector<Segment> segments = ImgSegments(items);
            const uint64_t       total = TotalSize(segments);
            const std::wstring   title = target.filename().wstring();

            reporter.Log(L"Сборка " + title + L": " + Native(imgPath) + L", " + std::to_wstring(items.size()) + L" файлов, " + FormatSize(total));
            const uint64_t size = WriteAndVerify(target, type, {{imgPath, 0, total}}, segments, master, reporter, title);
            reporter.Log(L"  готово и проверено: " + FormatSize(size));
            return size;
        }

        uint64_t BuildFilesPackage(const fs::path& target, std::vector<Item>& files, const Key& master, Reporter& reporter)
        {
            std::vector<Segment>  segments;
            std::vector<TocEntry> entries;
            uint64_t              offset = 0;

            for (Item& item : files)
            {
                entries.push_back({item.name, offset, item.size});
                segments.push_back({Segment::Kind::File, nullptr, item.path, item.size, &item.hash, item.name});
                offset += item.size;
            }

            const std::wstring title = target.filename().wstring();
            reporter.Log(L"Сборка " + title + L": " + std::to_wstring(files.size()) + L" файлов, " + FormatSize(offset));
            const uint64_t size = WriteAndVerify(target, TYPE_OTHER, entries, segments, master, reporter, title);
            reporter.Log(L"  готово и проверено: " + FormatSize(size));
            return size;
        }

        // One package with any number of IMG archives (each built on the fly) and plain files
        struct ImgPart
        {
            std::string        path;   // path in the package, "models/gta3.img"
            std::vector<Item>* items;  // entries of the IMG
        };

        uint64_t BuildMixedPackage(const fs::path& target, uint32_t type, const std::vector<ImgPart>& imgs, std::vector<Item>& files, const Key& master,
                                   Reporter& reporter)
        {
            std::vector<Segment>  segments;
            std::vector<TocEntry> entries;
            uint64_t              offset = 0;

            for (const ImgPart& img : imgs)
            {
                std::vector<Segment> part = ImgSegments(*img.items);
                const uint64_t       size = TotalSize(part);
                entries.push_back({img.path, offset, size});
                segments.insert(segments.end(), part.begin(), part.end());
                offset += size;
            }

            for (Item& item : files)
            {
                entries.push_back({item.name, offset, item.size});
                segments.push_back({Segment::Kind::File, nullptr, item.path, item.size, &item.hash, item.name});
                offset += item.size;
            }

            const std::wstring title = target.filename().wstring();
            reporter.Log(L"Сборка " + title + L": архивов " + std::to_wstring(imgs.size()) + L", файлов данных " + std::to_wstring(files.size()) + L", " +
                         FormatSize(offset));
            const uint64_t size = WriteAndVerify(target, type, entries, segments, master, reporter, title);
            reporter.Log(L"  готово и проверено: " + FormatSize(size));
            return size;
        }

        // Same files with the same size and date as the record
        bool SameAsRecord(const State& state, const std::string& key, const std::vector<Item>& items)
        {
            const auto record = state.packages.find(key);
            if (record == state.packages.end() || record->second.files.size() != items.size())
                return false;
            for (const Item& item : items)
            {
                auto it = record->second.files.find(Lower(item.name));
                if (it == record->second.files.end() || it->second.size != item.size || it->second.mtime != item.mtime)
                    return false;
            }
            return true;
        }

        // How many of the changes are already in the patch record
        size_t CoveredByPatch(const State& state, const std::string& key, const Diff& diff)
        {
            const auto record = state.packages.find(key);
            if (record == state.packages.end())
                return 0;

            size_t covered = 0;
            for (const auto* list : {&diff.added, &diff.changed})
                for (const Item* item : *list)
                {
                    auto it = record->second.files.find(Lower(item->name));
                    if (it != record->second.files.end() && it->second.size == item->size && it->second.mtime == item->mtime)
                        covered++;
                }
            return covered;
        }

        struct PatchPlan
        {
            std::vector<Item>     items;
            std::set<std::string> names;
        };

        // Patch mode: puts the archive's changes into the plan. Returns false when the archive
        // has to be rebuilt whole instead (the patch could not replace its models).
        bool AddToPatch(const Archive& archive, const PackageRecord& record, const Diff& diff, const std::set<std::string>& overridable, PatchPlan& plan,
                        Reporter& reporter)
        {
            std::vector<const Item*> toPatch(diff.added.begin(), diff.added.end());

            if (overridable.count(archive.LowerId()))
            {
                toPatch.insert(toPatch.end(), diff.changed.begin(), diff.changed.end());
            }
            else if (!diff.changed.empty())
            {
                reporter.Log(Native(archive.id) + L" движок читает раньше патча, замена моделей через патч не сработает — нужна полная сборка");
                return false;
            }

            for (const Item* item : toPatch)
            {
                if (plan.names.count(Lower(item->name)))
                {
                    reporter.Log(L"Имя " + Widen(item->name) + L" уже есть в патче из другого архива — нужна полная сборка " + Native(archive.id));
                    return false;
                }
            }

            if (!diff.removed.empty())
                reporter.Log(Native(archive.id) + L": удалено файлов " + std::to_wstring(diff.removed.size()) +
                             L", из игры они пропадут только после полной сборки");

            for (const Item* item : toPatch)
            {
                plan.names.insert(Lower(item->name));
                plan.items.push_back(*item);
                reporter.Log((record.files.count(Lower(item->name)) ? L"  в патч (замена): " : L"  в патч (новый): ") + Native(archive.id) + L"\\" +
                             Widen(item->name));
            }
            return true;
        }

        // ------------------------------------------------------------ gta.dat

        struct TextFile
        {
            std::vector<std::string> lines;
            std::string              newline = "\r\n";
            bool                     finalNewline = true;
        };

        TextFile ReadText(const fs::path& path)
        {
            std::ifstream in(path, std::ios::binary);
            if (!in)
                Fail(L"не удалось прочитать " + path.wstring());

            std::stringstream buffer;
            buffer << in.rdbuf();
            const std::string text = buffer.str();

            TextFile file;
            file.newline = text.find("\r\n") != std::string::npos || text.find('\n') == std::string::npos ? "\r\n" : "\n";
            file.finalNewline = text.empty() || text.back() == '\n';

            std::string line;
            for (char c : text)
            {
                if (c == '\n')
                {
                    if (!line.empty() && line.back() == '\r')
                        line.pop_back();
                    file.lines.push_back(line);
                    line.clear();
                }
                else
                {
                    line += c;
                }
            }
            if (!line.empty())
                file.lines.push_back(line);
            return file;
        }

        void WriteText(const fs::path& path, const TextFile& file)
        {
            std::string text;
            for (size_t i = 0; i < file.lines.size(); i++)
            {
                text += file.lines[i];
                if (i + 1 < file.lines.size() || file.finalNewline)
                    text += file.newline;
            }

            fs::path temporary = path;
            temporary += L".tmp";
            {
                std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
                out << text;
                if (!out)
                    Fail(L"не удалось записать " + temporary.wstring());
            }
            ReplaceFile(temporary, path);
        }

        std::string Trim(const std::string& text)
        {
            const size_t start = text.find_first_not_of(" \t");
            if (start == std::string::npos)
                return {};
            const size_t end = text.find_last_not_of(" \t");
            return text.substr(start, end - start + 1);
        }

        // "IMG data\Paths\x.img" -> "data/paths/x.img"
        bool ParseImgLine(const std::string& line, std::string& path)
        {
            const std::string trimmed = Trim(line);
            if (trimmed.size() < 5 || Lower(trimmed.substr(0, 4)) != "img " )
                return false;
            path = Lower(Trim(trimmed.substr(4)));
            std::replace(path.begin(), path.end(), '\\', '/');
            return !path.empty();
        }

        // Archives listed in gta.dat are loaded after the patch line, so the patch can replace their models.
        // gta3.img and gta_int.img are opened by the engine itself before any gta.dat line.
        std::set<std::string> ImgLinesOfGtaDat(const Settings& settings)
        {
            std::set<std::string> result;
            fs::path              path = settings.content / Native(GTA_DAT);
            if (!fs::is_regular_file(path))
                path = settings.game / Native(GTA_DAT);
            if (!fs::is_regular_file(path))
                return result;

            std::string img;
            for (const std::string& line : ReadText(path).lines)
                if (ParseImgLine(line, img))
                    result.insert(img);
            return result;
        }

        // Adds or removes the patch archive line. Returns true when gta.dat in the content folder changed.
        bool SetPatchLine(const Settings& settings, bool want, Reporter& reporter)
        {
            const fs::path path = settings.content / Native(GTA_DAT);

            if (!fs::is_regular_file(path))
            {
                if (!want)
                    return false;

                const fs::path original = settings.game / Native(GTA_DAT);
                if (!fs::is_regular_file(original))
                    Fail(L"для патча нужен data\\gta.dat: его нет ни в контенте, ни в папке игры");

                fs::create_directories(path.parent_path());
                fs::copy_file(original, path);
                reporter.Log(L"data\\gta.dat скопирован из игры в контент, в него добавлена строка патча");
            }

            TextFile    file = ReadText(path);
            const std::string patch = Lower(PATCH_IMG);
            std::string       img;

            auto found = std::find_if(file.lines.begin(), file.lines.end(), [&](const std::string& line) { return ParseImgLine(line, img) && img == patch; });

            if (want == (found != file.lines.end()))
                return false;

            if (want)
            {
                // Before every other IMG line: the first archive that has a model wins
                auto first = std::find_if(file.lines.begin(), file.lines.end(), [&](const std::string& line) { return ParseImgLine(line, img); });
                file.lines.insert(first, PATCH_LINE);
                reporter.Log(L"В data\\gta.dat добавлена строка: " + Widen(PATCH_LINE));
            }
            else
            {
                file.lines.erase(found);
                reporter.Log(L"Из data\\gta.dat убрана строка патча");
            }

            WriteText(path, file);
            return true;
        }

        // Every file that gta.dat / default.dat point at must be found by the game: in a package or on disk.
        // Paths in those files are relative to the gta_sa.exe folder, like the package entries.
        void CheckDataReferences(const Settings& settings, const Content& content, Reporter& reporter)
        {
            std::set<std::string> packed;
            for (const Item& item : content.files)
                packed.insert(Lower(item.name));
            for (const Archive& archive : content.archives)
                packed.insert(archive.LowerId());
            packed.insert(Lower(PATCH_IMG));

            size_t                    inPackage = 0;
            std::vector<std::wstring> onDiskOnly, missing;

            for (const char* dat : {GTA_DAT, "data/default.dat"})
            {
                fs::path path = settings.content / Native(dat);
                if (!fs::is_regular_file(path))
                    path = settings.game / Native(dat);
                if (!fs::is_regular_file(path))
                    continue;

                for (const std::string& line : ReadText(path).lines)
                {
                    std::istringstream words(Trim(line));
                    std::string        keyword, file;
                    words >> keyword;
                    keyword = Lower(keyword);

                    if (keyword == "colfile")
                        words >> file;  // the level number
                    else if (keyword != "ide" && keyword != "ipl" && keyword != "img" && keyword != "texdiction" && keyword != "modelfile")
                        continue;

                    std::getline(words, file);
                    file = Lower(Trim(file));
                    std::replace(file.begin(), file.end(), '\\', '/');
                    if (file.empty())
                        continue;

                    if (packed.count(file))
                        inPackage++;
                    else if (fs::exists(settings.game / Native(file)))
                        onDiskOnly.push_back(Native(file));
                    else
                        missing.push_back(Native(file));
                }
            }

            auto list = [](const std::vector<std::wstring>& files) {
                std::wstring text;
                for (size_t i = 0; i < files.size() && i < 8; i++)
                    text += L"\n    " + files[i];
                if (files.size() > 8)
                    text += L"\n    … и ещё " + std::to_wstring(files.size() - 8);
                return text;
            };

            reporter.Log(L"Ссылки из gta.dat/default.dat: в пакетах " + std::to_wstring(inPackage) + L", только на диске игры " +
                         std::to_wstring(onDiskOnly.size()) + L", не найдено " + std::to_wstring(missing.size()));
            if (!onDiskOnly.empty())
                reporter.Log(L"Эти файлы игра возьмёт с диска, в DLC их нет:" + list(onDiskOnly));
            if (!missing.empty())
                reporter.Log(L"ВНИМАНИЕ: этих файлов нет ни в пакетах, ни на диске, игра упадёт при загрузке:" + list(missing));
        }

        // Packages in the dlc folder that this content folder built before (by the record of its last build)
        // but that no current record points at. Lower case names.
        // Only what this content folder built: a package with a studio name that came from elsewhere
        // (the main sky_project.skydlc copied in, another content folder) is never removed.
        std::set<std::wstring> StalePackages(const Settings& settings, const Content&, const State& state, const std::set<std::wstring>& before)
        {
            if (state.packages.empty())
                return {};  // the studio has not built into this folder

            const std::set<std::wstring>& ours = before;

            std::set<std::wstring> used;
            for (const auto& [key, record] : state.packages)
                used.insert(LowerW(record.fileName));

            std::set<std::wstring> stale;
            std::error_code        ec;
            for (const std::wstring& name : ours)
                if (!used.count(name) && fs::is_regular_file(settings.dlc / name, ec))
                    stale.insert(name);
            return stale;
        }

        // ------------------------------------------------------------ import

        bool IsValidFileName(const std::string& name)
        {
            if (name.empty() || name == "." || name == "..")
                return false;
            for (unsigned char c : name)
                if (c < 0x20 || std::strchr("<>:\"/\\|?*", c))
                    return false;
            return name.back() != '.' && name.back() != ' ';
        }

        void ExtractImg(const fs::path& source, const fs::path& target, Reporter& reporter)
        {
            InFile in(source);
            const uint64_t fileSize = in.Size();

            uint8_t header[8];
            if (fileSize < 8)
                Fail(L"не IMG: " + source.wstring());
            in.Read(header, 8);

            if (std::memcmp(header, "VER2", 4) != 0)
                Fail(L"поддерживается только IMG VER2 (San Andreas): " + source.wstring());

            const uint32_t count = Get<uint32_t>(header + 4);
            if (8 + static_cast<uint64_t>(count) * IMG_ENTRY_SIZE > fileSize)
                Fail(L"каталог IMG повреждён: " + source.wstring());

            Bytes directory(static_cast<size_t>(count) * IMG_ENTRY_SIZE);
            in.Read(directory.data(), directory.size());

            fs::path work = target;
            work += L".importing";
            std::error_code ec;
            fs::remove_all(work, ec);
            fs::create_directories(work);

            std::set<std::string> names;
            size_t                skipped = 0;
            uint64_t              extracted = 0;
            Bytes                 buffer;

            for (uint32_t i = 0; i < count; i++)
            {
                const uint8_t* entry = directory.data() + static_cast<size_t>(i) * IMG_ENTRY_SIZE;
                const uint64_t offset = static_cast<uint64_t>(Get<uint32_t>(entry)) * SECTOR;
                const uint16_t streaming = Get<uint16_t>(entry + 4);
                const uint16_t archived = Get<uint16_t>(entry + 6);
                uint64_t       size = static_cast<uint64_t>(streaming ? streaming : archived) * SECTOR;
                const char*    rawName = reinterpret_cast<const char*>(entry + 8);
                std::string    name(rawName, strnlen(rawName, IMG_NAME_SIZE));

                if (!IsValidFileName(name) || !IsValidImgName(name))
                {
                    reporter.Log(L"  пропущено: запись с негодным именем «" + Widen(name) + L"»");
                    skipped++;
                    continue;
                }

                // The game takes the first entry of a name, the copies are dead weight
                if (!names.insert(Lower(name)).second)
                {
                    reporter.Log(L"  пропущен дубликат: " + Widen(name));
                    skipped++;
                    continue;
                }

                if (offset > fileSize)
                {
                    reporter.Log(L"  пропущено: " + Widen(name) + L" за концом файла");
                    skipped++;
                    continue;
                }

                if (offset + size > fileSize)
                {
                    reporter.Log(L"  обрезано по концу файла: " + Widen(name));
                    size = fileSize - offset;
                }

                buffer.resize(static_cast<size_t>(size));
                in.Seek(offset);
                in.Read(buffer.data(), buffer.size());

                OutFile out(work / Widen(name));
                out.Write(buffer.data(), buffer.size());
                out.Close();

                extracted += size;
                if ((i & 31) == 0)
                {
                    reporter.Check();
                    reporter.Progress(L"Импорт " + source.filename().wstring(), extracted, fileSize);
                }
            }

            fs::rename(work, target);
            reporter.Log(L"  " + std::to_wstring(names.size()) + L" файлов" + (skipped ? L", пропущено " + std::to_wstring(skipped) : L""));
        }

        bool IsSkippedGameFolder(const std::wstring& name)
        {
            static const wchar_t* skipped[] = {L"mta", L"dlc", L"mods", L"redist", L"screenshots", L"enbseries", L"logs"};
            const std::wstring    lower = LowerW(name);
            for (const wchar_t* item : skipped)
                if (lower == item)
                    return true;
            return false;
        }
    }

    // ---------------------------------------------------------------- public

    Error::Error(const std::wstring& message) : std::runtime_error(Narrow(message)), text(message) {}

    std::wstring Widen(const std::string& utf8)
    {
        if (utf8.empty())
            return {};
        const int    size = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
        std::wstring text(size, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), text.data(), size);
        return text;
    }

    std::string Narrow(const std::wstring& text)
    {
        if (text.empty())
            return {};
        const int   size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        std::string utf8(size, '\0');
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), utf8.data(), size, nullptr, nullptr);
        return utf8;
    }

    std::wstring FormatSize(uint64_t size)
    {
        wchar_t text[32];
        if (size >= 1024ull * 1024 * 1024)
            swprintf(text, 32, L"%.2f ГБ", size / (1024.0 * 1024 * 1024));
        else if (size >= 1024 * 1024)
            swprintf(text, 32, L"%.1f МБ", size / (1024.0 * 1024));
        else
            swprintf(text, 32, L"%.1f КБ", size / 1024.0);
        return text;
    }

    Key LoadMasterKey(const fs::path& path)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file)
            Fail(L"не найден файл ключа: " + path.wstring());

        std::stringstream buffer;
        buffer << file.rdbuf();
        const std::string text = buffer.str();

        auto parse = [&](const std::string& name) {
            const size_t start = text.find("#define " + name);
            if (start == std::string::npos)
                Fail(Widen(name) + L" нет в файле ключа");

            const size_t open = text.find('{', start);
            const size_t close = text.find('}', open);
            if (open == std::string::npos || close == std::string::npos)
                Fail(Widen(name) + L": ожидалось { 0x.., ... }");

            Key                key{};
            size_t             count = 0;
            std::istringstream list(text.substr(open + 1, close - open - 1));
            std::string        item;

            while (std::getline(list, item, ','))
            {
                item.erase(std::remove_if(item.begin(), item.end(), [](unsigned char c) { return std::isspace(c) || c == '\\'; }), item.end());
                if (item.empty())
                    continue;
                if (count == key.size())
                    Fail(Widen(name) + L": больше 32 байт");

                size_t              used = 0;
                const unsigned long value = std::stoul(item, &used, 0);
                if (used != item.size() || value > 0xFF)
                    Fail(Widen(name) + L": неверный байт " + Widen(item));
                key[count++] = static_cast<uint8_t>(value);
            }

            if (count != key.size())
                Fail(Widen(name) + L": нужно 32 байта, найдено " + std::to_wstring(count));
            return key;
        };

        const Key partA = parse("SKYDLC_KEY_PART_A");
        const Key partB = parse("SKYDLC_KEY_PART_B");

        Key master{};
        for (size_t i = 0; i < master.size(); i++)
            master[i] = partA[i] ^ partB[i];
        return master;
    }

    // Same as SkyDLCPacker fingerprint, so both tools can be compared
    std::wstring KeyFingerprint(const Key& master)
    {
        const uint8_t salt[SALT_SIZE] = {'f', 'i', 'n', 'g', 'e', 'r', 'p', 'r', 'i', 'n', 't'};
        const Key     id = DeriveKey(master, salt);
        return Hex(id.data(), 8);
    }

    std::vector<std::pair<fs::path, uint64_t>> FindGameImages(const fs::path& game)
    {
        std::vector<std::pair<fs::path, uint64_t>> result;
        if (!fs::is_directory(game))
            return result;

        for (auto it = fs::recursive_directory_iterator(game, fs::directory_options::skip_permission_denied); it != fs::recursive_directory_iterator(); ++it)
        {
            if (it->is_directory())
            {
                if (IsSkippedGameFolder(it->path().filename().wstring()))
                    it.disable_recursion_pending();
                continue;
            }

            if (it->is_regular_file() && LowerW(it->path().extension().wstring()) == L".img")
                result.push_back({fs::relative(it->path(), game), it->file_size()});
        }

        std::sort(result.begin(), result.end());
        return result;
    }

    ScanResult Scan(const Settings& settings, Reporter& reporter)
    {
        ScanResult result;
        Content    content = ReadContent(settings.content);
        State      state;
        state.Load(settings.content);

        bool       stateChanged = false;
        size_t     dirty = 0;
        const auto overridable = ImgLinesOfGtaDat(settings);
        const auto patchRecord = state.packages.find(PATCH_ID);

        std::set<std::wstring> known = {LowerW(SINGLE_PACKAGE), LowerW(FILES_PACKAGE), LowerW(PATCH_PACKAGE)};
        for (const auto& [key, record] : state.packages)
            known.insert(LowerW(record.fileName));

        const bool patchOk = patchRecord != state.packages.end() && PackageMatchesRecord(settings.dlc, patchRecord->second);

        // Built, in the layout chosen now
        auto builtHere = [&](const PackageRecord& record) {
            return LowerW(record.fileName) == LowerW(ExpectedPackage(settings, record.id)) && PackageMatchesRecord(settings.dlc, record);
        };

        for (Archive& archive : content.archives)
        {
            PackageView view;
            view.fileName = ExpectedPackage(settings, archive.id);
            view.source = Native(archive.id);
            view.fileCount = archive.items.size();
            for (const Item& item : archive.items)
                view.size += item.size;
            known.insert(LowerW(view.fileName));

            auto record = state.packages.find(archive.LowerId());

            if (!archive.problems.empty())
            {
                view.status = L"ошибка: " + archive.problems.front();
                if (archive.problems.size() > 1)
                    view.status += L" (и ещё " + std::to_wstring(archive.problems.size() - 1) + L")";
                dirty++;
            }
            else if (record == state.packages.end())
            {
                view.status = L"не собран";
                dirty++;
            }
            else if (!builtHere(record->second))
            {
                view.status = LowerW(record->second.fileName) != LowerW(view.fileName) ? L"собран в другой раскладке — нужна сборка"
                                                                                        : L"пакета нет или он чужой — нужна сборка";
                dirty++;
            }
            else
            {
                const Diff diff = Compare(archive.items, record->second, reporter, stateChanged);
                if (diff.Empty())
                {
                    view.status = L"актуален";
                    view.upToDate = true;
                }
                else
                {
                    const size_t inPatch = patchOk ? CoveredByPatch(state, PATCH_ID, diff) : 0;
                    const size_t changes = diff.added.size() + diff.changed.size();
                    if (inPatch == changes && diff.removed.empty())
                    {
                        view.status = L"актуален, " + std::to_wstring(inPatch) + L" в патче";
                        view.upToDate = true;
                    }
                    else
                    {
                        view.status = L"изменён: " + diff.Describe();
                        if (!overridable.count(archive.LowerId()) && !diff.changed.empty())
                            view.status += L" (замена — только полной сборкой)";
                        dirty++;
                    }
                }
            }

            result.packages.push_back(view);
        }

        // Loose files
        {
            PackageView view;
            view.fileName = ExpectedPackage(settings, FILES_ID);
            view.source = L"файлы данных (вне .img)";
            view.fileCount = content.files.size();
            for (const Item& item : content.files)
                view.size += item.size;

            auto record = state.packages.find(FILES_ID);
            if (content.files.empty())
            {
                view.status = record != state.packages.end() ? L"файлов нет — уберутся при сборке" : L"нет файлов";
                view.upToDate = record == state.packages.end();
            }
            else if (record == state.packages.end())
            {
                view.status = L"не собран";
            }
            else if (!builtHere(record->second))
            {
                view.status = L"пакета нет или он в другой раскладке — нужна сборка";
            }
            else
            {
                const Diff diff = Compare(content.files, record->second, reporter, stateChanged);
                if (diff.Empty())
                {
                    view.upToDate = true;
                    view.status = L"актуален";
                }
                else
                {
                    // In the single layout the patch carries changed data files
                    const size_t inPatch = patchOk && settings.single ? CoveredByPatch(state, PATCH_FILES_ID, diff) : 0;
                    view.upToDate = inPatch == diff.added.size() + diff.changed.size() && diff.removed.empty();
                    view.status = view.upToDate ? L"актуален, " + std::to_wstring(inPatch) + L" в патче" : L"изменён: " + diff.Describe();
                }
            }

            if (!view.upToDate)
                dirty++;
            if (!content.files.empty() || record != state.packages.end())
                result.packages.push_back(view);
        }

        // Patch
        if (patchRecord != state.packages.end())
        {
            const auto   patchFiles = state.packages.find(PATCH_FILES_ID);
            const size_t models = patchRecord->second.files.size();
            const size_t data = patchFiles != state.packages.end() ? patchFiles->second.files.size() : 0;

            PackageView view;
            view.fileName = PATCH_PACKAGE;
            view.source = data ? Native(PATCH_IMG) + L" + файлы данных" : Native(PATCH_IMG);
            view.fileCount = models + data;
            for (const auto* record : {&patchRecord->second, patchFiles != state.packages.end() ? &patchFiles->second : nullptr})
                if (record)
                    for (const auto& [name, file] : record->files)
                        view.size += file.size;
            view.upToDate = patchOk;
            view.status = patchOk ? L"патч: моделей " + std::to_wstring(models) + L", файлов данных " + std::to_wstring(data) : L"пакета патча нет — нужна сборка";
            result.packages.push_back(view);
        }

        // Archives that were removed from the content
        for (const auto& [key, record] : state.packages)
        {
            if (IsSpecialId(key))
                continue;
            const bool exists = std::any_of(content.archives.begin(), content.archives.end(), [&](const Archive& a) { return a.LowerId() == key; });
            if (!exists)
            {
                PackageView view;
                view.fileName = record.fileName;
                view.source = Native(record.id);
                view.status = L"папки больше нет — пакет удалится при сборке";
                known.insert(LowerW(view.fileName));
                result.packages.push_back(view);
                dirty++;
            }
        }

        // Packages this content folder built in the other layout: the build replaces and removes them
        std::set<std::wstring> oldLayout;
        for (const auto& [key, record] : state.packages)
        {
            const std::wstring name = LowerW(record.fileName);
            std::error_code    existsError;
            const bool listed = std::any_of(result.packages.begin(), result.packages.end(), [&](const PackageView& v) { return LowerW(v.fileName) == name; });
            if (!listed && name != LowerW(ExpectedPackage(settings, record.id)) && fs::is_regular_file(settings.dlc / record.fileName, existsError))
                oldLayout.insert(name);
        }
        for (const std::wstring& name : oldLayout)
        {
            PackageView view;
            view.fileName = name;
            view.source = L"—";
            std::error_code sizeError;
            view.size = fs::file_size(settings.dlc / name, sizeError);
            view.status = L"лишний пакет (старая раскладка) — удалится при сборке";
            known.insert(name);
            result.packages.push_back(view);
            dirty++;
        }

        // Packages in the dlc folder that the studio did not make
        std::error_code ec;
        if (fs::is_directory(settings.dlc, ec))
        {
            for (const auto& entry : fs::directory_iterator(settings.dlc, ec))
            {
                const std::wstring name = entry.path().filename().wstring();
                if (LowerW(entry.path().extension().wstring()) == L".skydlc" && !known.count(LowerW(name)))
                {
                    PackageView view;
                    view.fileName = name;
                    view.source = L"?";
                    view.size = entry.file_size(ec);
                    view.status = L"чужой пакет: студия его не трогает, он может перекрывать файлы";
                    result.packages.push_back(view);
                }
            }
        }

        if (stateChanged)
            state.Save();

        result.summary = content.archives.empty() && content.files.empty()
                             ? L"Контент пуст. Нажмите «Импорт из игры», чтобы разложить .img по папкам."
                             : (dirty ? L"Требуют сборки: " + std::to_wstring(dirty) : L"Все пакеты актуальны");
        return result;
    }

    namespace
    {
        // A package per archive + files.skydlc; the patch holds only models
        size_t BuildSplit(const Settings& settings, BuildMode mode, Content& content, State& state, const Key& master, Reporter& reporter)
        {
            bool       stateChanged = false;
            const auto overridable = ImgLinesOfGtaDat(settings);
            PatchPlan  plan;
            size_t     built = 0;

            // Data files of a patch exist only in the single layout
            state.packages.erase(PATCH_FILES_ID);

            // 1. Archives
            for (Archive& archive : content.archives)
            {
                reporter.Check();

                auto       record = state.packages.find(archive.LowerId());
                const bool hasPackage = record != state.packages.end() && PackageMatchesRecord(settings.dlc, record->second);
                bool       full = mode == BuildMode::All || !hasPackage;

                if (!full)
                {
                    const Diff diff = Compare(archive.items, record->second, reporter, stateChanged);
                    if (diff.Empty())
                        continue;
                    full = mode == BuildMode::Changed || !AddToPatch(archive, record->second, diff, overridable, plan, reporter);
                }

                if (!full)
                    continue;

                if (archive.items.empty())
                    reporter.Log(L"Внимание: " + Native(archive.id) + L" пуст, IMG будет без файлов");

                const uint64_t size = BuildImgPackage(settings.dlc / archive.PackageName(), archive.id, archive.items, master, reporter, TYPE_MAP);
                state.packages[archive.LowerId()] = MakeRecord(archive.id, archive.PackageName(), size, archive.items);
                state.Save();
                stateChanged = false;
                built++;
            }

            // 2. Archives whose folder is gone
            for (auto it = state.packages.begin(); it != state.packages.end();)
            {
                const std::string key = it->first;
                const bool        keep = IsSpecialId(key) ||
                                  std::any_of(content.archives.begin(), content.archives.end(), [&](const Archive& a) { return a.LowerId() == key; });
                if (keep)
                {
                    ++it;
                    continue;
                }

                reporter.Log(L"Папки " + Native(it->second.id) + L" больше нет, её пакет убирается");
                it = state.packages.erase(it);
                state.Save();
            }

            // 3. Patch first, gta.dat after it: gta.dat never points at a missing archive
            const bool wantPatch = !plan.items.empty();

            if (wantPatch)
            {
                std::sort(plan.items.begin(), plan.items.end(), [](const Item& a, const Item& b) { return Lower(a.name) < Lower(b.name); });

                const auto record = state.packages.find(PATCH_ID);
                if (SameAsRecord(state, PATCH_ID, plan.items) && PackageMatchesRecord(settings.dlc, record->second))
                {
                    reporter.Log(L"Патч уже содержит эти изменения");
                }
                else
                {
                    const uint64_t size = BuildImgPackage(settings.dlc / PATCH_PACKAGE, PATCH_IMG, plan.items, master, reporter, TYPE_OTHER);
                    state.packages[PATCH_ID] = MakeRecord(PATCH_ID, PATCH_PACKAGE, size, plan.items);
                    state.Save();
                    built++;
                }
            }

            // 4. gta.dat and the loose files
            if (SetPatchLine(settings, wantPatch, reporter))
                content.files = ReadContent(settings.content).files;

            {
                auto record = state.packages.find(FILES_ID);
                if (content.files.empty())
                {
                    if (record != state.packages.end())
                    {
                        state.packages.erase(record);
                        state.Save();
                        reporter.Log(L"В контенте нет файлов вне .img, files.skydlc убирается");
                    }
                }
                else
                {
                    bool need = mode == BuildMode::All || record == state.packages.end() || !PackageMatchesRecord(settings.dlc, record->second);
                    if (!need)
                        need = !Compare(content.files, record->second, reporter, stateChanged).Empty();

                    if (need)
                    {
                        const uint64_t size = BuildFilesPackage(settings.dlc / FILES_PACKAGE, content.files, master, reporter);
                        state.packages[FILES_ID] = MakeRecord(FILES_ID, FILES_PACKAGE, size, content.files);
                        state.Save();
                        stateChanged = false;
                        built++;
                    }
                }
            }

            // 5. A patch that is no longer needed goes after gta.dat stopped pointing at it
            if (!wantPatch && state.packages.erase(PATCH_ID))
            {
                state.Save();
                reporter.Log(L"Патч больше не нужен: все изменения теперь внутри архивов");
            }

            if (stateChanged)
                state.Save();
            return built;
        }

        // Everything in sky_project.skydlc; the patch holds models and data files
        size_t BuildSingle(const Settings& settings, BuildMode mode, Content& content, State& state, const Key& master, Reporter& reporter)
        {
            bool       stateChanged = false;
            const auto overridable = ImgLinesOfGtaDat(settings);

            auto recordOk = [&](const std::string& key) {
                const auto record = state.packages.find(key);
                return record != state.packages.end() && PackageMatchesRecord(settings.dlc, record->second);
            };

            // Does the big file have to be rebuilt?
            bool full = mode == BuildMode::All;

            for (const Archive& archive : content.archives)
            {
                if (!full && !recordOk(archive.LowerId()))
                {
                    reporter.Log(Native(archive.id) + L" ещё нет в " + SINGLE_PACKAGE);
                    full = true;
                }
            }

            if (!full && content.files.empty() != (state.packages.count(FILES_ID) == 0))
                full = true;
            if (!full && !content.files.empty() && !recordOk(FILES_ID))
                full = true;

            for (const auto& [key, record] : state.packages)
            {
                if (full || IsSpecialId(key))
                    continue;
                if (!std::any_of(content.archives.begin(), content.archives.end(), [&](const Archive& a) { return a.LowerId() == key; }))
                {
                    reporter.Log(L"Папки " + Native(record.id) + L" больше нет — нужна полная сборка");
                    full = true;
                }
            }

            PatchPlan plan;
            for (Archive& archive : content.archives)
            {
                if (full)
                    break;
                reporter.Check();

                PackageRecord& record = state.packages[archive.LowerId()];
                const Diff     diff = Compare(archive.items, record, reporter, stateChanged);
                if (diff.Empty())
                    continue;
                full = mode != BuildMode::Patch || !AddToPatch(archive, record, diff, overridable, plan, reporter);
            }

            // Changed mode: a changed data file (a patch changes gta.dat too) means a full build as well
            if (!full && mode == BuildMode::Changed && !content.files.empty())
                full = !Compare(content.files, state.packages[FILES_ID], reporter, stateChanged).Empty();

            if (full)
            {
                if (SetPatchLine(settings, false, reporter))
                    content.files = ReadContent(settings.content).files;

                std::vector<ImgPart> imgs;
                for (Archive& archive : content.archives)
                {
                    if (archive.items.empty())
                        reporter.Log(L"Внимание: " + Native(archive.id) + L" пуст, IMG будет без файлов");
                    imgs.push_back({archive.id, &archive.items});
                }

                const uint64_t size = BuildMixedPackage(settings.dlc / SINGLE_PACKAGE, TYPE_MAP, imgs, content.files, master, reporter);

                // Every archive and the data files are now in the big file, nothing is left for the patch
                state.packages.clear();
                for (const Archive& archive : content.archives)
                    state.packages[archive.LowerId()] = MakeRecord(archive.id, SINGLE_PACKAGE, size, archive.items);
                if (!content.files.empty())
                    state.packages[FILES_ID] = MakeRecord(FILES_ID, SINGLE_PACKAGE, size, content.files);
                state.Save();
                return 1;
            }

            if (mode != BuildMode::Patch)
            {
                if (stateChanged)
                    state.Save();
                return 0;
            }

            // Patch: the models, gta.dat with the patch line when there are models, the changed data files
            const bool wantImg = !plan.items.empty();
            if (SetPatchLine(settings, wantImg, reporter))
                content.files = ReadContent(settings.content).files;

            std::vector<Item> patchFiles;
            if (state.packages.count(FILES_ID) || !content.files.empty())
            {
                PackageRecord& record = state.packages[FILES_ID];
                const Diff     diff = Compare(content.files, record, reporter, stateChanged);
                for (const auto* list : {&diff.added, &diff.changed})
                {
                    for (const Item* item : *list)
                    {
                        patchFiles.push_back(*item);
                        reporter.Log((record.files.count(Lower(item->name)) ? L"  в патч (замена): " : L"  в патч (новый): ") + Native(item->name));
                    }
                }
                if (!diff.removed.empty())
                    reporter.Log(L"Удалено файлов данных: " + std::to_wstring(diff.removed.size()) + L", из игры они пропадут только после полной сборки");

                // gta.dat appeared only for the patch: the big file has no data files yet
                if (record.id.empty())
                    state.packages.erase(FILES_ID);
            }

            std::sort(plan.items.begin(), plan.items.end(), [](const Item& a, const Item& b) { return Lower(a.name) < Lower(b.name); });

            if (plan.items.empty() && patchFiles.empty())
            {
                if (state.packages.erase(PATCH_ID) + state.packages.erase(PATCH_FILES_ID))
                    reporter.Log(L"Патч больше не нужен");
                state.Save();
                return 0;
            }

            if (SameAsRecord(state, PATCH_ID, plan.items) && SameAsRecord(state, PATCH_FILES_ID, patchFiles) && recordOk(PATCH_ID))
            {
                reporter.Log(L"Патч уже содержит эти изменения");
                if (stateChanged)
                    state.Save();
                return 0;
            }

            std::vector<ImgPart> imgs;
            if (wantImg)
                imgs.push_back({PATCH_IMG, &plan.items});

            const uint64_t size = BuildMixedPackage(settings.dlc / PATCH_PACKAGE, TYPE_OTHER, imgs, patchFiles, master, reporter);
            state.packages[PATCH_ID] = MakeRecord(PATCH_ID, PATCH_PACKAGE, size, plan.items);
            state.packages[PATCH_FILES_ID] = MakeRecord(PATCH_FILES_ID, PATCH_PACKAGE, size, patchFiles);
            state.Save();
            return 1;
        }
    }

    void Build(const Settings& settings, BuildMode mode, Reporter& reporter)
    {
        const Key master = LoadMasterKey(settings.key);
        reporter.Log(L"Отпечаток ключа: " + KeyFingerprint(master));

        Content content = ReadContent(settings.content);
        State   state;
        state.Load(settings.content);

        for (const Archive& archive : content.archives)
            for (const std::wstring& problem : archive.problems)
                Fail(Native(archive.id) + L": " + problem);

        // A full DLC always has the game archives (gta3.img and the others). A content folder without any
        // is a mistake: usually new models put there to add on top of the main package.
        if (content.archives.empty())
            Fail(L"в папке контента нет ни одной папки .img (" + settings.content.wstring() + L"). "
                 L"Полный пакет игры так собрать нельзя. Чтобы добавить модели или файлы поверх основного пакета "
                 L"(машины, скины, правки), используйте «Патч из папки».");

        fs::create_directories(settings.dlc);

        // Packages the studio made before this build
        std::set<std::wstring> before;
        bool                   switched = false;
        for (const auto& [key, record] : state.packages)
        {
            before.insert(LowerW(record.fileName));
            if (LowerW(record.fileName) != LowerW(ExpectedPackage(settings, record.id)))
                switched = true;
        }

        // A package with a studio name that this content folder did not build (another content folder, a
        // deleted state file, a package copied in by hand) is never overwritten: it may hold the whole map.
        {
            const std::wstring name = settings.single ? SINGLE_PACKAGE : FILES_PACKAGE;
            if (fs::exists(settings.dlc / name) && !before.count(LowerW(name)))
                Fail(L"в папке dlc уже лежит " + name + L", но собран он не из этой папки контента. "
                     L"Сборка заменила бы его тем, что есть в контенте сейчас (" + std::to_wstring(content.archives.size()) + L" архивов, " +
                     std::to_wstring(content.files.size()) + L" файлов), и всё остальное из него пропало бы. "
                     L"Проверьте папку контента и папку dlc; если пакет действительно не нужен, удалите или переместите его вручную. "
                     L"Чтобы добавить что-то поверх, используйте «Патч из папки».");
        }

        if (switched && mode != BuildMode::All)
        {
            reporter.Log(settings.single ? L"Раскладка сменилась на один общий файл — собирается всё" : L"Раскладка сменилась на пакет на архив — собирается всё");
            mode = BuildMode::All;
        }

        const size_t built = settings.single ? BuildSingle(settings, mode, content, state, master, reporter)
                                             : BuildSplit(settings, mode, content, state, master, reporter);

        // Packages no record points at any more: the old layout, removed archives, a patch that is not needed.
        // Removed only now, after the new packages are in place. One that cannot be removed now is found
        // again by its name at the next build.
        for (const std::wstring& name : StalePackages(settings, content, state, before))
        {
            std::wstring error;
            if (TryRemoveFile(settings.dlc / name, error))
                reporter.Log(L"Удалён лишний пакет " + name);
            else
                reporter.Log(L"ВНИМАНИЕ: не удалось удалить лишний пакет " + name + L" (" + error +
                             L"). Пока он лежит, игра может брать файлы из него. Закройте то, что его держит, и нажмите «Собрать изменённые».");
        }

        CheckDataReferences(settings, content, reporter);

        reporter.Log(built ? L"Сборка завершена, пакетов собрано: " + std::to_wstring(built) : L"Всё и так актуально, собирать нечего");
    }

    void Import(const Settings& settings, Reporter& reporter)
    {
        if (!fs::is_regular_file(settings.game / L"gta_sa.exe"))
            Fail(L"в папке игры нет gta_sa.exe: " + settings.game.wstring());

        fs::create_directories(settings.content);

        const auto images = FindGameImages(settings.game);
        if (images.empty())
            reporter.Log(L"В папке игры нет .img");

        for (const auto& [relative, size] : images)
        {
            reporter.Check();
            const fs::path target = settings.content / relative;

            std::error_code ec;
            if (fs::is_directory(target, ec) && !fs::is_empty(target, ec))
            {
                reporter.Log(L"Пропущен " + relative.wstring() + L": папка в контенте уже есть");
                continue;
            }
            if (fs::exists(target, ec))
                fs::remove(target, ec);

            reporter.Log(L"Импорт " + relative.wstring() + L" (" + FormatSize(size) + L")");
            fs::create_directories(target.parent_path());
            ExtractImg(settings.game / relative, target, reporter);
        }

        // Data files: everything in data\maps (map pieces with their subfolders), gta.dat, default.dat
        // and the .ide/.ipl elsewhere in data. Paths stay relative to the gta_sa.exe folder.
        const fs::path data = settings.game / L"data";
        size_t         copied = 0;
        if (fs::is_directory(data))
        {
            for (const auto& entry : fs::recursive_directory_iterator(data, fs::directory_options::skip_permission_denied))
            {
                if (!entry.is_regular_file())
                    continue;

                const fs::path     relative = fs::relative(entry.path(), settings.game);
                const std::wstring name = LowerW(entry.path().filename().wstring());
                const std::wstring extension = LowerW(entry.path().extension().wstring());
                const bool         inMaps = LowerW(relative.generic_wstring()).rfind(L"data/maps/", 0) == 0;

                if (!inMaps && name != L"gta.dat" && name != L"default.dat" && extension != L".ide" && extension != L".ipl")
                    continue;

                const fs::path target = settings.content / relative;
                if (fs::exists(target))
                    continue;

                fs::create_directories(target.parent_path());
                fs::copy_file(entry.path(), target);
                copied++;
            }
        }
        reporter.Log(L"Файлов данных скопировано: " + std::to_wstring(copied) + L" (уже существующие не перезаписываются)");
        reporter.Log(L"Импорт завершён");
    }

    void BuildFolderPatch(const Settings& settings, const fs::path& folder, Reporter& reporter)
    {
        const Key master = LoadMasterKey(settings.key);
        reporter.Log(L"Отпечаток ключа: " + KeyFingerprint(master));

        Content content = ReadContent(folder);

        for (const Archive& archive : content.archives)
            for (const std::wstring& problem : archive.problems)
                Fail(Native(archive.id) + L": " + problem);

        if (content.archives.empty() && content.files.empty())
            Fail(L"в папке нет файлов: " + folder.wstring());

        // A model outside an archive and outside resources\ is never opened by the game
        for (const Item& item : content.files)
        {
            const std::string  lower = Lower(item.name);
            const std::wstring extension = LowerW(item.path.extension().wstring());
            const bool         model = extension == L".dff" || extension == L".txd" || extension == L".col" || extension == L".ifp";
            if (model && lower.rfind("resources/", 0) != 0)
                Fail(L"«" + Native(item.name) + L"» игра не найдёт: модель должна лежать по тому пути, по которому её грузят. "
                     L"Для машины из ресурса это resources\\<имя ресурса>\\<путь из скрипта>, например resources\\sky_carshop\\models\\" +
                     item.path.filename().wstring() + L". Для замены модели игры — в папке архива, например data\\Paths\\skyproject_vehs.img\\");
        }

        std::wstring name = LowerW(folder.filename().wstring());
        for (wchar_t& c : name)
            if (!(iswalnum(c) || c == L'_' || c == L'-'))
                c = L'_';
        if (name.empty())
            name = L"patch";

        const std::wstring package = L"zz_" + name + L".skydlc";
        if (LowerW(package) == LowerW(PATCH_PACKAGE))
            Fail(L"имя zz_patch занято патчем студии, переименуйте папку");

        std::vector<ImgPart> imgs;
        for (Archive& archive : content.archives)
            imgs.push_back({archive.id, &archive.items});

        fs::create_directories(settings.dlc);
        BuildMixedPackage(settings.dlc / package, TYPE_OTHER, imgs, content.files, master, reporter);

        for (const Archive& archive : content.archives)
            reporter.Log(L"  " + Native(archive.id) + L" (" + std::to_wstring(archive.items.size()) + L" файлов)");
        for (const Item& item : content.files)
            reporter.Log(L"  " + Native(item.name));
        reporter.Log(L"Патч " + package + L" лежит в папке dlc и перекрывает такие же файлы из остальных пакетов. Чтобы убрать, удалите файл.");
    }

    void VerifyAll(const Settings& settings, Reporter& reporter)
    {
        const Key master = LoadMasterKey(settings.key);
        reporter.Log(L"Отпечаток ключа: " + KeyFingerprint(master));

        std::vector<fs::path> packages;
        std::error_code       ec;
        for (const auto& entry : fs::directory_iterator(settings.dlc, ec))
            if (entry.is_regular_file() && LowerW(entry.path().extension().wstring()) == L".skydlc")
                packages.push_back(entry.path());
        std::sort(packages.begin(), packages.end());

        if (packages.empty())
            reporter.Log(L"В папке dlc нет пакетов");

        size_t failed = 0;
        for (const fs::path& package : packages)
        {
            try
            {
                std::vector<TocEntry> entries;
                VerifyPackage(package, nullptr, nullptr, master, reporter, L"Проверка " + package.filename().wstring(), &entries);

                std::wstring list;
                for (size_t i = 0; i < entries.size() && i < 3; i++)
                    list += (i ? L", " : L"") + Native(entries[i].name);
                if (entries.size() > 3)
                    list += L", …";
                reporter.Log(L"OK " + package.filename().wstring() + L": " + std::to_wstring(entries.size()) + L" файлов (" + list + L")");
            }
            catch (const Error& e)
            {
                reporter.Log(L"ОШИБКА " + package.filename().wstring() + L": " + e.text);
                failed++;
            }
        }

        if (failed)
            Fail(L"не прошли проверку: " + std::to_wstring(failed));
        reporter.Log(L"Все пакеты расшифровываются этим ключом");
    }
}
