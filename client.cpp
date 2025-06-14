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

    /*
    auto opts = fcntl(sock,F_GETFL);
    if (opts < 0) {
        std::cerr << "fcntl(F_GETFL)";
        return;
    }
    std::cout << "Socket options: " << opts << std::endl;
    opts = (opts && !O_NONBLOCK);
    std::cout << "Socket options: " << opts << std::endl;
    if (fcntl(sock,F_SETFL,opts) < 0) {
        std::cerr <<"fcntl(F_SETFL)";
        return;
    }
*/
    {    // Send Hello message
        auto encrypted_Hello = rsa.encrypt(toData(HelloMessage));
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
    { // Send IV and Key
        Data iv_key(IV_SIZE + KEY_SIZE);
        std::generate(iv_key.begin(), iv_key.end(), []() { return static_cast<unsigned char>(std::rand() % 256); });   
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

    std::ifstream infile(filename.data(), std::ios::binary);
    if (!infile) {
        std::cerr << "Failed to open input file " << filename << std::endl;
        return ErrorCode::IO;
    }

    Command begin_cmd(Command::Type::BEGIN_FILE, std::string_view("received_file"));
    if(!sendCommandWaitAck(*sock, begin_cmd))
    {
        std::cerr << "Failed to send BEGIN_FILE command" << std::endl;
        return ErrorCode::Network;
    }
    PacketBuffer buffer;
    constexpr size_t FileBlockSize = ((buffer.size() - 1) / BLOCK_SIZE - 1) * BLOCK_SIZE; 
    while (infile) {
        infile.read(reinterpret_cast<char*>(buffer.data()), FileBlockSize); //Dont't forget 1 byte for command type
        std::streamsize bytes = infile.gcount();
        if (bytes > 0) {
            Command cmd(Command::Type::FILE_BLOCK, std::vector<unsigned char>(buffer.data(), buffer.data() + bytes));
            if(!sendCommandWaitAck(*sock, cmd)){
                std::cerr << "Failed to send FILE_BLOCK command" << std::endl;
                return ErrorCode::Network;
            }
        }
    }
    Command end_cmd(Command::Type::END_FILE);
    sendCommandWaitAck(*sock, end_cmd);
    std::cout << "File sent"<< std::endl;
    infile.close();
    return ErrorCode::Success;
}

