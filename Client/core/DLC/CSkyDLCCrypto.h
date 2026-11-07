
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace SkyDLC
{
    constexpr size_t AES_KEY_SIZE = 32;
    constexpr size_t AES_NONCE_SIZE = 12;
    constexpr size_t AES_TAG_SIZE = 16;

    using AESKey = std::array<uint8_t, AES_KEY_SIZE>;
    using AESNonce = std::array<uint8_t, AES_NONCE_SIZE>;
    using AESTag = std::array<uint8_t, AES_TAG_SIZE>;

    class CSkyDLCCrypto
    {
    public:
        // AES-256-GCM authenticated decryption.
        // Returns false if authentication fails.
        // Output must be cleared on failure.
        static bool Decrypt(const AESKey& key, const AESNonce& nonce, const AESTag& tag, const std::vector<uint8_t>& encryptedData,
                            std::vector<uint8_t>& decryptedData);

        // Package key: HMAC-SHA256(master key, "SkyDLC3" + salt).
        static bool DeriveKey(const AESKey& masterKey, const uint8_t* salt, size_t saltSize, AESKey& packageKey);

        // Master key built into the client. Returns false when this build has none.
        static bool GetMasterKey(AESKey& key);
    };

    // AES-256-GCM key kept open between calls, a package decrypts thousands of chunks.
    class CSkyDLCCipher
    {
    public:
        CSkyDLCCipher() = default;
        ~CSkyDLCCipher();

        CSkyDLCCipher(const CSkyDLCCipher&) = delete;
        CSkyDLCCipher& operator=(const CSkyDLCCipher&) = delete;

        bool Open(const AESKey& key);
        void Close();

        // Output buffer must hold size bytes. Returns false if authentication fails.
        bool Decrypt(const AESNonce& nonce, const uint8_t* additionalData, uint32_t additionalSize, const uint8_t* encrypted, uint32_t size,
                     const uint8_t* tag, uint8_t* output);

    private:
        void*                m_algorithm = nullptr;
        void*                m_key = nullptr;
        std::vector<uint8_t> m_keyObject;
    };
}
