#include <gtest/gtest.h>
#include <algorithm>
#include "cipher.h"

TEST(AESTest, InitEncrypt) {
    AESCipher cipher;
    constexpr IV iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,  0x0F};
    constexpr KEY key = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
               0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,  0x1F};
    auto result = cipher.init(iv, key, AESCipher::OperationMode::Encrypt);
    EXPECT_TRUE(result.has_value()) << "Cipher initialization failed";
    EXPECT_EQ(result.value(), BLOCK_SIZE) << "Cipher block size should be 16 bytes";
}

TEST(AESTest, InitDecrypt) {
    AESCipher cipher;
    constexpr IV iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,  0x0F};
    constexpr KEY key = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
               0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,  0x1F};
    auto result = cipher.init(iv, key, AESCipher::OperationMode::Decrypt);
    EXPECT_TRUE(result.has_value()) << "Cipher initialization failed";
    EXPECT_EQ(result.value(), BLOCK_SIZE) << "Cipher block size should be 16 bytes";
}

TEST(AESTest, Encrypt_Decrypt_SmallData) {
    AESCipher encipher;
    constexpr IV iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,  0x0F};
    constexpr KEY key = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
               0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,  0x1F};
    
    ASSERT_TRUE(encipher.init(iv, key, AESCipher::OperationMode::Encrypt).has_value()) << "Cipher initialization failed";


    Data plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    Data encrypted(BLOCK_SIZE);
    auto encryptedResult = encipher.encryptBlock(plaintext.begin(), plaintext.end(), encrypted.begin(), encrypted.end());
    ASSERT_TRUE(encryptedResult.has_value()) << "Encryption failed: " << encryptedResult.error();
    ASSERT_EQ(encryptedResult.value(), encrypted.begin()) << "No data expected here";

    encryptedResult = encipher.encryptFinalize(encrypted.begin(), encrypted.end());
    ASSERT_TRUE(encryptedResult.has_value()) << "Encryption failed: " << encryptedResult.error();

    AESCipher decipher;
    ASSERT_TRUE(decipher.init(iv, key, AESCipher::OperationMode::Decrypt).has_value()) << "Cipher initialization failed";

    Data decrypted(BLOCK_SIZE);
    auto decryptedResult = decipher.decryptBlock(encrypted.begin(), encrypted.end(), decrypted.begin(), decrypted.end());
    ASSERT_TRUE(decryptedResult.has_value()) << "Decryption failed: " << decryptedResult.error();
    ASSERT_EQ(decryptedResult.value(), decrypted.begin()) << "No data expected here";
    decryptedResult = decipher.decryptFinalize(decrypted.begin(), decrypted.end());
    ASSERT_TRUE(decryptedResult.has_value()) << "Decryption failed: " << decryptedResult.error();
    
    Data decryptedFinal{decrypted.begin(), decryptedResult.value()};
    EXPECT_EQ(plaintext.size(), decryptedFinal.size()) << "Decrypted data size does not match original plaintext size";
    EXPECT_EQ(plaintext, decryptedFinal) << "Decrypted data does not match original plaintext";
}


TEST(AESTest, Encrypt_Decrypt_LargeData) {
    AESCipher encipher;

    constexpr IV iv = {0x70, 0x61, 0x52, 0x43, 0x34, 0x25, 0x16, 0x07,
             0xF8, 0xE9, 0xDA, 0xCB, 0xBC, 0xAD, 0x7E,  0x7F};
    constexpr KEY key = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
               0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,  0x1F};
    
    ASSERT_TRUE(encipher.init(iv, key, AESCipher::OperationMode::Encrypt).has_value()) << "Cipher initialization failed";
   
    constexpr size_t BlockCount = 56789;
    Data big_plaintext(BLOCK_SIZE * BlockCount + 3); //Not divisible by BLOCK_SIZE
    std::generate(big_plaintext.begin(), big_plaintext.end(), []() { return static_cast<unsigned char>(std::rand() % 256); });
    Data encrypted(BLOCK_SIZE * BlockCount + 2 * BLOCK_SIZE); // +BLOCK_SIZE for padding
    Data decrypted(BLOCK_SIZE * BlockCount + 2 * BLOCK_SIZE); // +BLOCK_SIZE for padding

    auto encryptedResult = encipher.encrypt(big_plaintext.begin(), big_plaintext.end(), encrypted.begin(), encrypted.end());
    ASSERT_TRUE(encryptedResult.has_value()) << "Encryption failed: " << encryptedResult.error();
    auto encStart = encryptedResult.value();

    encryptedResult = encipher.encryptFinalize(encStart, encrypted.end());
    ASSERT_TRUE(encryptedResult.has_value()) << "Encryption failed: " << encryptedResult.error();
    auto encEnd = encryptedResult.value();
    //std::cout << "Encrypted size: " << encEnd - encStart << std::endl;
    
    AESCipher decipher;
    ASSERT_TRUE(decipher.init(iv, key, AESCipher::OperationMode::Decrypt).has_value()) << "Cipher initialization failed";

    auto decryptedResult = decipher.decrypt(encrypted.begin(), encEnd, decrypted.begin(), decrypted.end());
    ASSERT_TRUE(decryptedResult.has_value()) << "Decryption failed: " << decryptedResult.error();
    auto decStart = decryptedResult.value();

    decryptedResult = decipher.decryptFinalize(decStart, decrypted.end());
    ASSERT_TRUE(decryptedResult.has_value()) << "Decryption failed: " << decryptedResult.error();
    decStart = decrypted.begin();
    auto decEnd = decryptedResult.value();
    //std::cout << "Decrypted size: " << decEnd - decStart << std::endl;
    ASSERT_GE(decEnd - decStart, big_plaintext.size()) << "Decrypted data size does not match original plaintext size";
    ASSERT_TRUE(std::equal(decStart, decEnd, big_plaintext.begin())) << "Decrypted data does not match original plaintext";
}