
#include "StdInc.h"
#include "CSkyDLCCrypto.h"

#include <Windows.h>
#include <bcrypt.h>

#include <climits>
#include <cstring>
#include <limits>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

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
}
