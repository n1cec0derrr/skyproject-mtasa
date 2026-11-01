#define NOMINMAX

#include <Windows.h>
#include <bcrypt.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;

constexpr size_t KEY_SIZE = 32;
constexpr size_t NONCE_SIZE = 12;
constexpr size_t TAG_SIZE = 16;

using Key = std::array<uint8_t, KEY_SIZE>;
using Nonce = std::array<uint8_t, NONCE_SIZE>;
using Tag = std::array<uint8_t, TAG_SIZE>;

bool Encrypt(const Key& key, const Nonce& nonce, const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext, Tag& tag)
{
    ciphertext.clear();
    tag.fill(0);

    if (plaintext.size() > std::numeric_limits<ULONG>::max())
        return false;

    BCRYPT_ALG_HANDLE    algorithm = nullptr;
    BCRYPT_KEY_HANDLE    keyHandle = nullptr;
    std::vector<uint8_t> keyObject;

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
        DWORD returned = 0;

        status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &returned, 0);

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
        authInfo.pbTag = tag.data();
        authInfo.cbTag = static_cast<ULONG>(tag.size());

        ciphertext.resize(plaintext.size());

        ULONG written = 0;

        status = BCryptEncrypt(keyHandle, plaintext.empty() ? nullptr : const_cast<PUCHAR>(plaintext.data()), static_cast<ULONG>(plaintext.size()), &authInfo,
                               nullptr, 0, ciphertext.empty() ? nullptr : ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &written, 0);

        if (!BCRYPT_SUCCESS(status))
            break;

        ciphertext.resize(written);
        success = true;

    } while (false);

    if (keyHandle)
        BCryptDestroyKey(keyHandle);

    if (!keyObject.empty())
        SecureZeroMemory(keyObject.data(), keyObject.size());

    if (algorithm)
        BCryptCloseAlgorithmProvider(algorithm, 0);

    if (!success)
    {
        ciphertext.clear();
        tag.fill(0);
    }

    return success;
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cout << "Sky DLC Packer v1\n"
                  << "Usage: SkyDLCPacker.exe <input> <output.skydlc>\n";
        return 1;
    }

    const fs::path inputPath = argv[1];
    const fs::path outputPath = argv[2];

    std::ifstream input(inputPath, std::ios::binary | std::ios::ate);

    if (!input)
    {
        std::cerr << "Cannot open input file.\n";
        return 1;
    }

    const auto inputSize = input.tellg();

    if (inputSize < 0 || static_cast<uint64_t>(inputSize) > std::numeric_limits<ULONG>::max())
    {
        std::cerr << "Input file is too large.\n";
        return 1;
    }

    std::vector<uint8_t> plaintext(static_cast<size_t>(inputSize));

    input.seekg(0);

    if (!plaintext.empty() && !input.read(reinterpret_cast<char*>(plaintext.data()), static_cast<std::streamsize>(plaintext.size())))
    {
        std::cerr << "Cannot read input.\n";
        return 1;
    }

    Key   key{};
    Nonce nonce{};
    Tag   tag{};

    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ||
        !BCRYPT_SUCCESS(BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
        std::cerr << "Random generation failed.\n";
        return 1;
    }

    std::vector<uint8_t> ciphertext;

    if (!Encrypt(key, nonce, plaintext, ciphertext, tag))
    {
        std::cerr << "Encryption failed.\n";
        SecureZeroMemory(key.data(), key.size());
        return 1;
    }

    std::ofstream output(outputPath, std::ios::binary);

    if (!output)
    {
        std::cerr << "Cannot create output file.\n";
        SecureZeroMemory(key.data(), key.size());
        return 1;
    }

    const char magic[8] = {'S', 'K', 'Y', 'D', 'L', 'C', '2', '\0'};

    const uint32_t version = 2;
    const uint32_t type = 255;
    const uint64_t encryptedSize = ciphertext.size();

    output.write(magic, sizeof(magic));
    output.write(reinterpret_cast<const char*>(&version), sizeof(version));
    output.write(reinterpret_cast<const char*>(&type), sizeof(type));
    output.write(reinterpret_cast<const char*>(&encryptedSize), sizeof(encryptedSize));
    output.write(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    output.write(reinterpret_cast<const char*>(tag.data()), tag.size());

    if (!ciphertext.empty())
        output.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());

    output.close();

    if (!output)
    {
        std::cerr << "Failed to write DLC.\n";
        SecureZeroMemory(key.data(), key.size());
        return 1;
    }

    // Development-only key file.
    // Never distribute this file with production DLC.
    const fs::path keyPath = outputPath.string() + ".key";

    std::ofstream keyFile(keyPath, std::ios::binary);

    if (!keyFile || !keyFile.write(reinterpret_cast<const char*>(key.data()), key.size()))
    {
        std::cerr << "Failed to save test key.\n";
        SecureZeroMemory(key.data(), key.size());
        return 1;
    }

    keyFile.close();
    SecureZeroMemory(key.data(), key.size());

    std::cout << "Sky DLC created successfully!\n";
    std::cout << "Output: " << outputPath << '\n';
    std::cout << "Encrypted bytes: " << encryptedSize << '\n';
    std::cout << "Test key: " << keyPath << '\n';

    return 0;
}
