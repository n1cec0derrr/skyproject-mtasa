
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
    };
}
