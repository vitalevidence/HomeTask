#pragma once
#include "common.h"
#include <string>
#include <fstream>
#include <ctime>
#include "cipher.h"
#include <optional>
#include <iostream>

struct ServerContext
{
    bool is_authenticated = false; // Authentication status of the server context
    std::time_t last_access_time;  // Last access time for the server context
    std::string filename;          // File to be sent or received
    std::fstream file_stream;      // File stream for reading or writing
    IV iv;                         // Initialization vector for encryption
    KEY key;                       // Key for encryption
    SEED seed_data;                // Seed data for the session

    void updateAccessTime()
    {
        last_access_time = std::time(nullptr);
    }

    void setFileData(const std::string &new_filename)
    {
        if (new_filename.size() < sizeof(file_size) + 1)
        {
            throw std::invalid_argument("Filename is too short to contain file size.");
        }
        memcpy(&file_size, new_filename.data(), sizeof(file_size)); // Copy file size from the string
        filename =std::string(new_filename.begin() + sizeof(file_size), new_filename.end());
        file_stream.open(filename, std::ios::out | std::ios::binary);
        if (!file_stream.is_open())
        {
            throw std::runtime_error("Failed to open file: " + filename);
        }
        std::cout << "Opened " << filename << " expected " << file_size << " bytes" << std::endl;
        updateAccessTime();
    }

    void resumeFile(const std::string &new_filename)
    {
        filename = new_filename;
        file_stream.open(filename, std::ios::app | std::ios::binary);
        if (!file_stream.is_open())
        {
            throw std::runtime_error("Failed to open file: " + filename);
        }
        updateAccessTime();
    }

    void writeFileBlock(const Data &block, bool last_block = false)
    {
        if (!file_stream.is_open())
        {
            throw std::runtime_error("File stream is not open for writing.");
        }
        if (aes_cipher)
        {
            auto decrypted_block = aes_cipher->decrypt(block.begin(), block.end(), decBuffer.begin(), decBuffer.end());
            if (!decrypted_block)
            {
                std::cerr << "Failed to decrypt block: " << block.end() - block.begin() << " " << decBuffer.end() - decBuffer.begin() << std::endl;
                throw std::runtime_error("Failed to decrypt block: " + std::to_string(decrypted_block.error()));
            }
            if(last_block){
                decrypted_block = aes_cipher->decryptFinalize(*decrypted_block, decBuffer.end());
                if (!decrypted_block)
                {
                std::cerr << "Failed to decrypt last block: " << std::endl;
                    throw std::runtime_error("Failed to deencrypt last block: " + std::to_string(decrypted_block.error()));
                }
            }
            auto left = std::min(file_size, (decltype(file_size))(decrypted_block.value() - decBuffer.begin()));
            //std::cout << "Written " << left << " bytes" << std::endl;
            file_stream.write(reinterpret_cast<const char *>(&(*decBuffer.begin())), left);
            file_size -= left;
            
        }
        else
        {
            // If no AES cipher is set, write the block directly
            file_stream.write(reinterpret_cast<const char *>(block.data()), block.size());
        }
        // file_stream.write(reinterpret_cast<const char*>(block.data()), block.size());
        if (!file_stream)
        {
            throw std::runtime_error("Failed to write to file: " + filename);
        }
        updateAccessTime();
    }

    void closeFile()
    {
        if (file_stream.is_open())
        {
            file_stream.close();
        }
        updateAccessTime();
    }

    void setIV_KEY(const IV &iv, const KEY &key)
    {
        aes_cipher.emplace(); // Initialize the AES cipher
        auto init_result = aes_cipher->init(iv, key, AESCipher::OperationMode::Decrypt);
        if (!init_result)
        {
            throw std::runtime_error("Failed to initialize AES cipher: " + std::to_string(init_result.error()));
        }
        decBuffer.resize(BUFFER_SIZE + BLOCK_SIZE); // Alloc decryption buffer
        updateAccessTime();
    }

    ServerContext() : last_access_time(std::time(nullptr)), file_stream{}
    {
        // Initialize the file stream to an empty state
    }

    ServerContext(const ServerContext &) = delete;            // Disable copy constructor
    ServerContext &operator=(const ServerContext &) = delete; // Disable copy assignment
    ServerContext(ServerContext &&) = default;                // Enable move constructor
    ServerContext &operator=(ServerContext &&) = default;     // Enable move assignment

    ~ServerContext()
    {
        closeFile(); // Ensure the file stream is closed when the context is destroyed
    }

private:
    std::optional<AESCipher> aes_cipher;  // Optional AES cipher for encryption/decryption
    std::vector<unsigned char> decBuffer; // Buffer for decrypted data
    uint32_t file_size = 0; // Size of the file being processed
};