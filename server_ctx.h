#pragma once
#include "common.h"
#include <string>
#include <fstream>
#include <ctime>
#include "cipher.h"
#include <optional>

struct ServerContext {
    bool is_authenticated = false; // Authentication status of the server context
    std::time_t last_access_time; // Last access time for the server context
    std::string filename; // File to be sent or received
    std::fstream file_stream; // File stream for reading or writing
    IV iv; // Initialization vector for encryption
    KEY key; // Key for encryption
    SEED seed_data; // Seed data for the session

    void updateAccessTime() {
        last_access_time = std::time(nullptr);
    }

    void setFilename(const std::string & new_filename) {
        filename = new_filename;
        file_stream.open(filename, std::ios::out | std::ios::binary);
        if (!file_stream.is_open()) {
            throw std::runtime_error("Failed to open file: " + filename);
        }
        updateAccessTime(); 
    }

    void resumeFile(const std::string & new_filename) {
        filename = new_filename;
        file_stream.open(filename, std::ios::app | std::ios::binary);
        if (!file_stream.is_open()) {
            throw std::runtime_error("Failed to open file: " + filename);
        }
        updateAccessTime(); 
    }

    void writeFileBlock(const Data & block) {
        if (!file_stream.is_open()) {
            throw std::runtime_error("File stream is not open for writing.");
        }
        file_stream.write(reinterpret_cast<const char*>(block.data()), block.size());
        if (!file_stream) {
            throw std::runtime_error("Failed to write to file: " + filename);
        }
        updateAccessTime(); 
    }

    void closeFile() {
        if (file_stream.is_open()) {
            file_stream.close();
        }
        updateAccessTime(); 
    }

    void setIV_KEY(const IV & iv, const KEY & key) {
        aes_cipher.emplace(); // Initialize the AES cipher
        auto init_result = aes_cipher->init(iv, key, AESCipher::OperationMode::Decrypt);
        if (!init_result) {
            throw std::runtime_error("Failed to initialize AES cipher: " + std::to_string(init_result.error()));
        }
        updateAccessTime(); 
    }


    ServerContext() : last_access_time(std::time(nullptr)), file_stream{}{
        // Initialize the file stream to an empty state
    }

    ServerContext(const ServerContext&) = delete; // Disable copy constructor
    ServerContext& operator=(const ServerContext&) = delete; // Disable copy assignment
    ServerContext(ServerContext&&) = default; // Enable move constructor
    ServerContext& operator=(ServerContext&&) = default; // Enable move assignment

    ~ServerContext() {
        closeFile(); // Ensure the file stream is closed when the context is destroyed
    }
    private:
      std::optional<AESCipher> aes_cipher; // Optional AES cipher for encryption/decryption
};