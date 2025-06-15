#pragma once
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <cstdio>

#include <filesystem>
#include <expected>

#include "common.h"

using RAII_EVP_CIPHER_CTX = RAII1<EVP_CIPHER_CTX*, EVP_CIPHER_CTX_free>;

class AESCipher
{
public:
    enum class OperationMode
    {
        Encrypt,
        Decrypt
    };
    std::expected<int, bool> init(const IV & iv, const KEY &key, OperationMode mode);

    std::expected<Data::iterator, int> encryptBlock(Data::const_iterator plaintextStart, Data::const_iterator plaintextEnd,
                                      Data::iterator ciphertextStart, Data::iterator ciphertextEnd);

    std::expected<Data::iterator, int> encrypt(Data::const_iterator plaintextStart, Data::const_iterator plaintextEnd,
                                      Data::iterator ciphertextStart, Data::iterator ciphertextEnd);

    std::expected<Data::iterator, int> encryptFinalize(Data::iterator ciphertextStart, Data::iterator ciphertextEnd);

    std::expected<Data::iterator, int> decryptBlock(Data::const_iterator ciphertextStart, Data::const_iterator ciphertextEnd, 
                                      Data::iterator plaintextStart, Data::iterator plaintextEnd);

    std::expected<Data::iterator, int> decrypt(Data::const_iterator ciphertextStart, Data::const_iterator ciphertextEnd, 
                                      Data::iterator plaintextStart, Data::iterator plaintextEnd);

    std::expected<Data::iterator, int> decryptFinalize(Data::iterator plaintextStart, Data::iterator plaintextEnd);
    
private:
    RAII_EVP_CIPHER_CTX ctx;
    int cipherBlockSize = 0;

    void handleErrors();
};

using RAII_PKEY_CTX = RAII1<EVP_PKEY_CTX*, EVP_PKEY_CTX_free>;
using RAII_EVP_PKEY = RAII1<EVP_PKEY*, EVP_PKEY_free>;
using RAII_EVP_PKEY_CTX = RAII1<EVP_PKEY_CTX*, EVP_PKEY_CTX_free>;

class RSACipher
{
public:
    std::expected<Data, int> encrypt(const Data &ciphertext);

    std::expected<Data, int> decrypt(const Data &ciphertext);

    bool loadPublicKey(const std::filesystem::path &pubkey_path);

    bool loadPrivateKey(const std::filesystem::path &privkey_path);

    // Sign data using the private key
    int sign(const unsigned char *data, size_t data_len,
             unsigned char *sig, size_t *sig_len)
    {
        if (!private_key)
            return -1;
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (!md_ctx)
        {
            handleErrors();
            return -1;
        }
        int ret = -1;
        if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, *private_key) <= 0)
            goto end;
        if (EVP_DigestSignUpdate(md_ctx, data, data_len) <= 0)
            goto end;
        if (EVP_DigestSignFinal(md_ctx, nullptr, sig_len) <= 0)
            goto end;
        if (EVP_DigestSignFinal(md_ctx, sig, sig_len) <= 0)
            goto end;
        ret = static_cast<int>(*sig_len);
    end:
        if (ret == -1)
            handleErrors();
        EVP_MD_CTX_free(md_ctx);
        return ret;
    }

    // Verify signature using the public key
    bool verify(const unsigned char *data, size_t data_len,
                const unsigned char *sig, size_t sig_len)
    {
        if (!public_key)
            return false;
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (!md_ctx)
        {
            handleErrors();
            return false;
        }
        bool result = false;
        if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, *public_key) <= 0)
            goto end;
        if (EVP_DigestVerifyUpdate(md_ctx, data, data_len) <= 0)
            goto end;
        if (EVP_DigestVerifyFinal(md_ctx, sig, sig_len) == 1)
            result = true;
    end:
        if (!result)
            handleErrors();
        EVP_MD_CTX_free(md_ctx);
        return result;
    }

private:
    RAII_EVP_PKEY public_key;
    RAII_EVP_PKEY private_key;

    void handleErrors()
    {
        ERR_print_errors_fp(stderr);
    }
};

