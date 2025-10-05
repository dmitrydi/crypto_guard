#include "crypto_guard_ctx.h"
#include "utility.hpp"
#include <array>
#include <iostream>
#include <iterator>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

inline AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
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

class CryptoGuardCtx::Impl {
public:
    Impl() = default;
    ~Impl() = default;
    void EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password);
    void DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::istream &inStream) { return {}; }

private:
    using CipherPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); })>;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<CryptoGuardCtx::Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream) { return pImpl_->CalculateChecksum(inStream); }

void CryptoGuardCtx::Impl::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    static const size_t kBlockSize = 16;
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 1;
    CipherPtr ctx(EVP_CIPHER_CTX_new());
    EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

    std::vector<unsigned char> outBuf(kBlockSize + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(kBlockSize);
    int outLen;

    auto iter = std::istream_iterator<unsigned char>(inStream);
    while (iter != std::istream_iterator<unsigned char>()) {
        auto r = GryptoGuard::Utility::read_block(iter, inBuf, kBlockSize);
        if (auto res = EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(r.second));
            res != 1) {
            unsigned long err_code = ERR_get_error();
            throw std::runtime_error(std::format("{}", ERR_error_string(err_code, nullptr)));
        }
        for (int i = 0; i < outLen; ++i) {
            outStream << outBuf[i];
        }
        iter = r.first;
    }
    EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen);
    for (int i = 0; i < outLen; ++i) {
        outStream << outBuf[i];
    }
}

void CryptoGuardCtx::Impl::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    static const size_t kBlockSize = 16;
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 0;  // Set to 0 for decryption
    CipherPtr ctx(EVP_CIPHER_CTX_new());
    EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

    std::vector<unsigned char> outBuf(kBlockSize + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(kBlockSize);
    int outLen;

    auto iter = std::istream_iterator<unsigned char>(inStream);
    while (iter != std::istream_iterator<unsigned char>()) {
        auto r = GryptoGuard::Utility::read_block(iter, inBuf, kBlockSize);
        EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(r.second));
        for (int i = 0; i < outLen; ++i) {
            outStream << outBuf[i];
        }
        iter = r.first;
    }
    EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen);
    for (int i = 0; i < outLen; ++i) {
        outStream << outBuf[i];
    }
}

/*
        //
        // OpenSSL пример использования:
        //
        std::string input = "01234567890123456789";
        std::string output;

        OpenSSL_add_all_algorithms();

        auto params = CreateChiperParamsFromPassword("12341234");
        params.encrypt = 1;
        auto *ctx = EVP_CIPHER_CTX_new();

        // Инициализируем cipher
        EVP_CipherInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen;

        // Обрабатываем первые N символов
        std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Обрабатываем оставшиеся символы
        std::copy(std::next(input.begin(), 16), input.end(), inBuf.begin());
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(input.size() - 16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Заканчиваем работу с cipher
        EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }
        EVP_CIPHER_CTX_free(ctx);
        std::print("String encoded successfully. Result: '{}'\n\n", output);
        EVP_cleanup();
        //
        // Конец примера
        //
*/

}  // namespace CryptoGuard