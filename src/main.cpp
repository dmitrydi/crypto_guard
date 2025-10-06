#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <algorithm>
#include <array>
#include <boost/scope/defer.hpp>
#include <fstream>
#include <ios>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>
#include <utility>

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

int main(int argc, char *argv[]) {
    try {

        CryptoGuard::ProgramOptions options;

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        options.Parse(argc, argv);

        if (options.GetCommand() == COMMAND_TYPE::HELP) {
            std::cerr << options.GetDesc() << std::endl;
            return 1;
        }

        std::ifstream ifs(options.GetInputFile(), std::ios_base::binary);
        if (!ifs.is_open()) {
            throw std::runtime_error(std::format("could not open file {}", options.GetInputFile()));
        }
        std::ofstream ofs(options.GetOutputFile(), std::ios_base::binary);
        if (!ofs.is_open()) {
            throw std::runtime_error(std::format("could not open file {}", options.GetOutputFile()));
        }

        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            cryptoCtx.EncryptFile(ifs, ofs, options.GetPassword());
            std::print("File encoded successfully\n");
            break;

        case COMMAND_TYPE::DECRYPT:
            cryptoCtx.DecryptFile(ifs, ofs, options.GetPassword());
            std::print("File decoded successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM: {
            auto checksum = cryptoCtx.CalculateChecksum(ifs);
            ofs << checksum;
            std::print("Checksum: {}\n", checksum);
        } break;

        case COMMAND_TYPE::HELP:
            std::cerr << options.GetDesc() << std::endl;
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}