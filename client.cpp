#include <fstream>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <algorithm>


#include "command.h"
#include "common.h"
#include "server_ctx.h"
#include "client.h"

// TCP client: sends a file to the server
ErrorCode run_client(const std::string_view & server_ip, const std::string_view & filename, uint16_t PORT, RSACipher & rsa) {
    sockaddr_in serv_addr;

    auto sock = RAII_Socket(socket(AF_INET, SOCK_STREAM, 0));
    if (*sock < 0) {
        std::cerr << "Socket creation error";
        return ErrorCode::Network;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip.data(), &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported";
        return ErrorCode::Network;
    }

    if (connect(*sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed";
        return ErrorCode::Network;
    }

    //Receive SEED command
    Data seed_data;
    {
        auto maybe_seed = WaitPacket(*sock, Command::Type::SEED);
        if (!maybe_seed) {
            std::cerr << "Failed to receive SEED command: " << maybe_seed.error() << std::endl;
            return ErrorCode::Authentication;
        }
        seed_data = *maybe_seed;
        if( seed_data.size() < 16) {
            std::cerr << "Invalid SEED command size: " << seed_data.size() << std::endl;
            return ErrorCode::Authentication;
        }
    }

    {    // Send Hello message
        auto msgHello = toData(HelloMessage);
        for(size_t i = 0; i < msgHello.size(); ++i) {
            msgHello[i] ^= seed_data[i % seed_data.size()]; // XOR with SEED
        }

        auto encrypted_Hello = rsa.encrypt(msgHello);
        if (!encrypted_Hello) {
            std::cerr << "Failed to encrypt Hello message: " << encrypted_Hello.error() << std::endl;
            return ErrorCode::AES;
        }
        
        Command hello_cmd(Command::Type::HELLO, *encrypted_Hello);
        if(!sendCommandWaitAck(*sock, hello_cmd)) {
            std::cerr << "Failed to send Hello command" << std::endl;
            return ErrorCode::Authentication;
        }
    }

    IV iv;
    KEY key;
    { // Send IV and Key
        Data iv_key(IV_SIZE + KEY_SIZE);
        std::generate(iv_key.begin(), iv_key.end(), []() { return static_cast<unsigned char>(std::rand() % 256); });
        std::copy(iv_key.begin(), iv_key.begin() + IV_SIZE, iv.begin());
        std::copy(iv_key.begin() + IV_SIZE, iv_key.end(), key.begin());
        auto encrypted_iv_key = rsa.encrypt(iv_key);
        if (!encrypted_iv_key) {
            std::cerr << "Failed to encrypt IV_KEY: " << encrypted_iv_key.error() << std::endl;
            return ErrorCode::AES;
        }

        Command iv_key_cmd(Command::Type::IV_KEY, *encrypted_iv_key);
        if(!sendCommandWaitAck(*sock, iv_key_cmd)) {
            std::cerr << "Failed to send IV_KEY command" << std::endl;
            return ErrorCode::Authentication;
        }
    
    }

    AESCipher aes_cipher;
    auto init_result = aes_cipher.init(iv, key, AESCipher::OperationMode::Encrypt);
    if (!init_result) {
        std::cerr << "Failed to initialize AES cipher: " << init_result.error() << std::endl;
        return ErrorCode::AES;
    }

    std::ifstream infile(filename.data(), std::ios::binary);
    if (!infile) {
        std::cerr << "Failed to open input file " << filename << std::endl;
        return ErrorCode::IO;
    }

    const uint32_t file_size = std::filesystem::file_size(filename);//Size stored in 4 bytes!
    std::string fileDataStr{"1234received_file"};
    memcpy(fileDataStr.data(), &file_size, sizeof(file_size)); 
    Command begin_cmd(Command::Type::BEGIN_FILE, fileDataStr);
    if(!sendCommandWaitAck(*sock, begin_cmd))
    {
        std::cerr << "Failed to send BEGIN_FILE command" << std::endl;
        return ErrorCode::Network;
    }
    std::vector<unsigned char> encBuffer(BUFFER_SIZE - 1);
    constexpr size_t FileBlockSize = ((BUFFER_SIZE - 1) / BLOCK_SIZE - 1) * BLOCK_SIZE; 
    std::vector<unsigned char> buffer(FileBlockSize);
    while (infile) {
        infile.read(reinterpret_cast<char*>(buffer.data()), FileBlockSize); //Dont't forget 1 byte for command type
        auto bytes = infile.gcount();
        if (bytes > 0) {
            auto endEnc = aes_cipher.encrypt(buffer.begin(), buffer.begin() + bytes, encBuffer.begin(), encBuffer.end());
            if (!endEnc) {
                std::cerr << "Failed to encrypt: " << endEnc.error() << std::endl;
                return ErrorCode::AES;
            }

            if(!infile){ //Last block
                endEnc = aes_cipher.encryptFinalize(*endEnc, encBuffer.end());
                if (!endEnc) {
                    std::cerr << "Failed to finalize encryption: " << endEnc.error() << std::endl;
                    return ErrorCode::AES;
                }
                //std::cout << "Last block size: " << (*endEnc - encBuffer.begin()) << std::endl;
            }

            Command cmd(infile ? Command::Type::FILE_BLOCK : Command::Type::LAST_FILE_BLOCK, std::move(std::vector<unsigned char>(encBuffer.begin(), *endEnc)));
            if(!sendCommandWaitAck(*sock, cmd)){
                std::cerr << "Failed to send FILE_BLOCK command" << std::endl;
                return ErrorCode::Network;
            }
        }
    }
    std::cout << "File sent"<< std::endl;
    infile.close();
    return ErrorCode::Success;
}

