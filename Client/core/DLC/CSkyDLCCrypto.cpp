
#include "StdInc.h"
#include "CSkyDLCCrypto.h"

#include <Windows.h>
#include <bcrypt.h>

#include <climits>
#include <cstring>
#include <limits>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

// Generated together with the master key, must never be committed.
#if __has_include("SkyDLCKey.local.h")
    #include "SkyDLCKey.local.h"
#endif

namespace SkyDLC
{
    bool CSkyDLCCrypto::Decrypt(const AESKey& key, const AESNonce& nonce, const AESTag& tag, const std::vector<uint8_t>& encryptedData,
                                std::vector<uint8_t>& decryptedData)
    {
        decryptedData.clear();

        if (encryptedData.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max()))
        {
            return false;
        }

        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_KEY_HANDLE keyHandle = nullptr;

        std::vector<uint8_t> keyObject;
        std::vector<uint8_t> plaintext;

        bool success = false;

        do
        {
            NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);

            if (!BCRYPT_SUCCESS(status))
                break;

            status = BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                                       sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

            if (!BCRYPT_SUCCESS(status))
                break;

            DWORD objectLength = 0;
            DWORD bytesReturned = 0;

            status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &bytesReturned, 0);

            if (!BCRYPT_SUCCESS(status))
                break;

            keyObject.resize(objectLength);

            status = BCryptGenerateSymmetricKey(algorithm, &keyHandle, keyObject.empty() ? nullptr : keyObject.data(), static_cast<ULONG>(keyObject.size()),
                                                const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);

            if (!BCRYPT_SUCCESS(status))
                break;

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

            authInfo.pbNonce = const_cast<PUCHAR>(nonce.data());

            authInfo.cbNonce = static_cast<ULONG>(nonce.size());

            authInfo.pbTag = const_cast<PUCHAR>(tag.data());

            authInfo.cbTag = static_cast<ULONG>(tag.size());

            plaintext.resize(encryptedData.size());

            ULONG decryptedLength = 0;

            status =
                BCryptDecrypt(keyHandle, encryptedData.empty() ? nullptr : const_cast<PUCHAR>(encryptedData.data()), static_cast<ULONG>(encryptedData.size()),
                              &authInfo, nullptr, 0, plaintext.empty() ? nullptr : plaintext.data(), static_cast<ULONG>(plaintext.size()), &decryptedLength, 0);

            if (!BCRYPT_SUCCESS(status))
                break;

            if (decryptedLength > plaintext.size())
                break;

            plaintext.resize(decryptedLength);
            decryptedData.swap(plaintext);

            success = true;

        } while (false);

        if (!success)
        {
            decryptedData.clear();
        }

        if (!plaintext.empty())
        {
            SecureZeroMemory(plaintext.data(), plaintext.size());
        }

        if (keyHandle)
            BCryptDestroyKey(keyHandle);

        if (!keyObject.empty())
        {
            SecureZeroMemory(keyObject.data(), keyObject.size());
        }

        if (algorithm)
            BCryptCloseAlgorithmProvider(algorithm, 0);

        return success;
    }

    bool CSkyDLCCrypto::DeriveKey(const AESKey& masterKey, const uint8_t* salt, size_t saltSize, AESKey& packageKey)
    {
        static constexpr char LABEL[] = "SkyDLC3";

        BCRYPT_ALG_HANDLE  algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;

        bool success = false;

        do
        {
            if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
                break;

            if (!BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, nullptr, 0, const_cast<PUCHAR>(masterKey.data()), static_cast<ULONG>(masterKey.size()), 0)))
                break;

            if (!BCRYPT_SUCCESS(BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(LABEL)), sizeof(LABEL) - 1, 0)))
                break;

            if (!BCRYPT_SUCCESS(BCryptHashData(hash, const_cast<PUCHAR>(salt), static_cast<ULONG>(saltSize), 0)))
                break;

            if (!BCRYPT_SUCCESS(BCryptFinishHash(hash, packageKey.data(), static_cast<ULONG>(packageKey.size()), 0)))
                break;

            success = true;

        } while (false);

        if (hash)
            BCryptDestroyHash(hash);

        if (algorithm)
            BCryptCloseAlgorithmProvider(algorithm, 0);

        return success;
    }

    bool CSkyDLCCrypto::GetMasterKey(AESKey& key)
    {
#ifdef SKYDLC_KEY_PART_A
        const AESKey partA = SKYDLC_KEY_PART_A;
        const AESKey partB = SKYDLC_KEY_PART_B;

        for (size_t i = 0; i < key.size(); i++)
            key[i] = partA[i] ^ partB[i];

        return true;
#else
        return false;
#endif
    }

    CSkyDLCCipher::~CSkyDLCCipher()
    {
        Close();
    }

    bool CSkyDLCCipher::Open(const AESKey& key)
    {
        Close();

        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_KEY_HANDLE keyHandle = nullptr;

        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0)))
            return false;

        m_algorithm = algorithm;

        if (!BCRYPT_SUCCESS(BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                                              sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        {
            Close();
            return false;
        }

        DWORD objectLength = 0;
        DWORD bytesReturned = 0;

        if (!BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &bytesReturned, 0)))
        {
            Close();
            return false;
        }

        m_keyObject.resize(objectLength);

        if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(algorithm, &keyHandle, m_keyObject.data(), static_cast<ULONG>(m_keyObject.size()),
                                                       const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0)))
        {
            Close();
            return false;
        }

        m_key = keyHandle;
        return true;
    }

    void CSkyDLCCipher::Close()
    {
        if (m_key)
            BCryptDestroyKey(m_key);

        if (!m_keyObject.empty())
            SecureZeroMemory(m_keyObject.data(), m_keyObject.size());

        if (m_algorithm)
            BCryptCloseAlgorithmProvider(m_algorithm, 0);

        m_key = nullptr;
        m_algorithm = nullptr;
        m_keyObject.clear();
    }

    bool CSkyDLCCipher::Decrypt(const AESNonce& nonce, const uint8_t* additionalData, uint32_t additionalSize, const uint8_t* encrypted, uint32_t size,
                                const uint8_t* tag, uint8_t* output)
    {
        if (!m_key)
            return false;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

        authInfo.pbNonce = const_cast<PUCHAR>(nonce.data());
        authInfo.cbNonce = static_cast<ULONG>(nonce.size());
        authInfo.pbAuthData = const_cast<PUCHAR>(additionalData);
        authInfo.cbAuthData = additionalSize;
        authInfo.pbTag = const_cast<PUCHAR>(tag);
        authInfo.cbTag = AES_TAG_SIZE;

        ULONG decryptedLength = 0;

        const NTSTATUS status = BCryptDecrypt(m_key, const_cast<PUCHAR>(encrypted), size, &authInfo, nullptr, 0, output, size, &decryptedLength, 0);

        return BCRYPT_SUCCESS(status) && decryptedLength == size;
    }
}
