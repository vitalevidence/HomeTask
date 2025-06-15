#include "cipher.h"
#include <stdexcept>
#include <iostream>

std::expected<Data::iterator, int> AESCipher::encryptBlock(Data::const_iterator plaintextStart, Data::const_iterator plaintextEnd,
                                                      Data::iterator ciphertextStart, Data::iterator ciphertextEnd)
{
    if (!ctx)
    {
        return std::unexpected(-3);
    }
    if (plaintextEnd - plaintextStart > cipherBlockSize)
    {
        return std::unexpected(-4);
    }

    if (ciphertextEnd - ciphertextStart < cipherBlockSize)
    {
        std::cerr << "Ciphertext buffer is too small for encryption " << (ciphertextEnd - ciphertextStart) << " < " << cipherBlockSize << std::endl;
        return std::unexpected(-5);
    }

    auto len = cipherBlockSize;
    if (1 != EVP_EncryptUpdate(*ctx, &(*ciphertextStart), &len, &(*plaintextStart), plaintextEnd - plaintextStart))
    {
        handleErrors();
        return std::unexpected(-1);
    }
    return ciphertextStart + len;
}

std::expected<Data::iterator, int> AESCipher::encrypt(Data::const_iterator plaintextStart, Data::const_iterator plaintextEnd,
                                                      Data::iterator ciphertextStart, Data::iterator ciphertextEnd)
{
    auto encStart = ciphertextStart;
    for(auto start = plaintextStart; start < plaintextEnd; start += cipherBlockSize) {
        auto encryptedResult = encryptBlock(start, start + cipherBlockSize, encStart, ciphertextEnd);
        if(!encryptedResult){
            return encryptedResult;
        }
        encStart = encryptedResult.value();
    }
    return encStart;
}

std::expected<Data::iterator, int> AESCipher::encryptFinalize(Data::iterator ciphertextStart, Data::iterator ciphertextEnd)
{
    if (!ctx || ciphertextEnd - ciphertextStart < cipherBlockSize)
    {
        return std::unexpected(-2);
    }

    auto final_len = cipherBlockSize;
    if (1 != EVP_EncryptFinal_ex(*ctx, &(*ciphertextStart), &final_len))
    {
        handleErrors();
        return std::unexpected(-1);
    }
    return ciphertextStart + final_len;
}

std::expected<Data::iterator, int> AESCipher::decryptBlock(Data::const_iterator ciphertextStart, Data::const_iterator ciphertextEnd, Data::iterator plaintextStart, Data::iterator plaintextEnd)
{
    if (!ctx)
    {
        return std::unexpected(-5);
    }
    
    if(ciphertextEnd - ciphertextStart != cipherBlockSize)
    {
        return std::unexpected(-4);
    }
    
    if(plaintextEnd - plaintextStart < cipherBlockSize)
    {
        return std::unexpected(-3);
    }
    
    auto len = cipherBlockSize;
    if (1 != EVP_DecryptUpdate(*ctx, &(*plaintextStart), &len, &(*ciphertextStart), ciphertextEnd - ciphertextStart))
    {
        handleErrors();
        return std::unexpected(-1);
    }
    return plaintextStart + len;
}

std::expected<Data::iterator, int> AESCipher::decrypt(Data::const_iterator ciphertextStart, Data::const_iterator ciphertextEnd, Data::iterator plaintextStart, Data::iterator plaintextEnd)
{
    auto decStart = plaintextStart;
    for(auto start = ciphertextStart; start != ciphertextEnd; start += cipherBlockSize) {
        auto decryptedResult = decryptBlock(start, start + cipherBlockSize, decStart, plaintextEnd);
        if(!decryptedResult){
            return decryptedResult;
        }
        decStart = decryptedResult.value();
    }
    return decStart;
}

std::expected<Data::iterator, int> AESCipher::decryptFinalize(Data::iterator plaintextStart, Data::iterator plaintextEnd)
{
    if (!ctx)
    {
        return std::unexpected(-5);
    }

    if(plaintextEnd - plaintextStart < cipherBlockSize)
    {
        return std::unexpected(-14);
    }

    auto final_len = cipherBlockSize;
    if (1 != EVP_DecryptFinal_ex(*ctx, &(*plaintextStart), &final_len))
    {
        handleErrors();
        return std::unexpected(-11);
    }
    return plaintextStart + final_len;
}

std::expected<int, bool> AESCipher::init(const IV &iv, const KEY &key, OperationMode mode)
{
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        std::cerr << "Failed to create cipher context";
        handleErrors();
        return std::unexpected(false);
    }
    if (mode == OperationMode::Decrypt)
    {
        if (1 != EVP_DecryptInit_ex(*ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data()))
        {
            handleErrors();
            std::cerr << "Failed to init aes-128-cbc decryption";
            return std::unexpected(false);
        }
    }
    else if (mode == OperationMode::Encrypt)
    {
        if (1 != EVP_EncryptInit_ex(*ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data()))
        {
            handleErrors();
            std::cerr << "Failed to init aes-128-cbc encryption";
            return std::unexpected(false);
        }
    }

    cipherBlockSize = EVP_CIPHER_CTX_block_size(*ctx);
    auto cipherKeyLength = EVP_CIPHER_CTX_key_length(*ctx);
    auto cipherIvLength = EVP_CIPHER_CTX_iv_length(*ctx);

    if (cipherIvLength != IV_SIZE || cipherKeyLength != KEY_SIZE)
    {
        std::cerr << "Cipher parameters do not match expected sizes: "
                  << "IV size: " << cipherIvLength << ", "
                  << "Key size: " << cipherKeyLength << ", "
                  << "Block size: " << cipherBlockSize << std::endl;
        return std::unexpected(false);
    }

    return cipherBlockSize;
}

/*
if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();
ciphertext_len += len;
*/

void AESCipher::handleErrors()
{
    ERR_print_errors_fp(stderr);
}

std::expected<Data, int> RSACipher::encrypt(const Data &plaintext)
{
    if (!public_key)
        return std::unexpected(-1);

    RAII_EVP_PKEY_CTX enc_ctx(EVP_PKEY_CTX_new(*public_key, nullptr));
    if (!enc_ctx)
    {
        handleErrors();
        return std::unexpected(-1);
    }
    if (EVP_PKEY_encrypt_init(*enc_ctx) <= 0)
    {
        handleErrors();
        return std::unexpected(-1);
    }
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(*enc_ctx, nullptr, &outlen, plaintext.data(), plaintext.size()) <= 0)
    {
        handleErrors();
        return std::unexpected(-1);
    }
    Data ciphertext(outlen);
    if (EVP_PKEY_encrypt(*enc_ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size()) <= 0)
    {
        handleErrors();
        return std::unexpected(-1);
    }
    return ciphertext;
}

std::expected<Data, int> RSACipher::decrypt(const Data &ciphertext)
{
    if (!private_key)
        return std::unexpected(-1);
    RAII_EVP_PKEY_CTX dec_ctx(EVP_PKEY_CTX_new(*private_key, nullptr));
    if (!dec_ctx)
    {
        handleErrors();
        return std::unexpected(-1);
    }
    if (EVP_PKEY_decrypt_init(*dec_ctx) <= 0)
    {
        handleErrors();
        return std::unexpected(-1);
    }
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(*dec_ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0)
    {
        handleErrors();
        return std::unexpected(-1);
    }
    Data plaintext(outlen);
    if (EVP_PKEY_decrypt(*dec_ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0)
    {
        handleErrors();
        return std::unexpected(-1);
    }
    return plaintext;
}

bool RSACipher::loadPublicKey(const std::filesystem::path &pubkey_path)
{
    auto fp = RAII_File(fopen(pubkey_path.c_str(), "r"));
    if (!fp)
        return false;
    EVP_PKEY *key = PEM_read_PUBKEY(*fp, nullptr, nullptr, nullptr);
    if (!key)
        return false;
    public_key = key;
    return true;
}

bool RSACipher::loadPrivateKey(const std::filesystem::path &privkey_path)
{
    auto fp = RAII_File(fopen(privkey_path.c_str(), "r"));
    if (!fp)
        return false;
    EVP_PKEY *key = PEM_read_PrivateKey(*fp, nullptr, nullptr, nullptr);
    if (!key)
        return false;
    private_key = key;
    return true;
}
