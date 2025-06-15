#include <fstream>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <set>
#include <algorithm>

#include "command.h"
#include "common.h"
#include "server_ctx.h"
#include "server.h"

bool ProcessIV_KEY(const Data &data, RSACipher & rsa, ServerContext &server_ctx)
{
    auto decrypted_data = rsa.decrypt(data);

    if (!decrypted_data)
    {
        std::cerr << "Failed to decrypt Hello." << std::endl;
        return false;
    }
    if (decrypted_data->size() < IV_SIZE + KEY_SIZE) {
        std::cerr << "Invalid IV_KEY command size: " << decrypted_data->size() << std::endl;
        return false;
    }

    IV iv; 
    std::copy(decrypted_data->begin(), decrypted_data->begin() + IV_SIZE, iv.begin());
    KEY key;
    std::copy(decrypted_data->begin() + IV_SIZE, decrypted_data->begin() + IV_SIZE + KEY_SIZE, key.begin());

    server_ctx.setIV_KEY(iv, key);
    std::cout << "IV_KEY command processed successfully." << std::endl;
    return true;
}

bool SendSeed(ServerContext &server_ctx, int sock)
{
    auto & seed_data = server_ctx.seed_data;
    std::generate(seed_data.begin(), seed_data.end(), []() { return static_cast<unsigned char>(std::rand() % 256); });
    
    Command seed_cmd(Command::Type::SEED, seed_data);
    if (!sendCommand(sock, seed_cmd)) {
        std::cerr << "Failed to send SEED command" << std::endl;
        return false;
    }
    return true;
}

bool CheckAutentication(const Command &cmd, RSACipher & rsa, ServerContext &server_ctx)
{
    if (server_ctx.is_authenticated){
        return true; // Already authenticated, no need to check again
    }

    //If we not autenticated, only one command is expected
    if (cmd.type() == Command::Type::HELLO)
    {
        auto decrypted_msg = rsa.decrypt(cmd.asData());

        if (!decrypted_msg)
        {
            std::cerr << "Failed to decrypt Hello." << std::endl;
            return false;
        }

        const auto & seed_data = server_ctx.seed_data;
        auto maybeHello = *decrypted_msg;
        for(size_t i = 0; i < HelloMessage.size(); ++i) {
            maybeHello[i] ^= seed_data[i % seed_data.size()]; // XOR with SEED
        }

        if (memcmp(maybeHello.data(), HelloMessage.data(), HelloMessage.size()) != 0)
        {
            std::cerr << "Encrypted Hello message " << cmd.asData() << std::endl;
            std::cerr << "Decrypted key does not match original session key." << std::endl;
            return false;
        }
        server_ctx.is_authenticated = true;
        std::cout << "Client authenticated successfully." << std::endl;
        return true;
    }

    std::cerr << "Received command before authentication\n";
    return false;
}

bool ProcessCommand(const Command &cmd, ServerContext &server_ctx, RSACipher & rsa)
{
    if (!CheckAutentication(cmd, rsa, server_ctx))
        return false;

    switch (cmd.type())
    {
    case Command::Type::IV_KEY:
        std::cout << "Received IV_KEY command with data size: " << cmd.asData().size() << std::endl;
        if(!ProcessIV_KEY(cmd.asData(), rsa, server_ctx))
            return false;
        break;
    case Command::Type::BEGIN_FILE:
        std::cout << "Received BEGIN_FILE command with filedata: " << cmd.asString() << std::endl;
        server_ctx.setFileData(cmd.asString());
        break;
    case Command::Type::RESUME_FILE:
        std::cout << "Received RESUME_FILE command with filename: " << cmd.asString() << std::endl;
        server_ctx.resumeFile(cmd.asString());
        break;
    case Command::Type::FILE_BLOCK:
        //std::cout << "Received FILE_BLOCK command with data size: " << cmd.asData().size() << std::endl;
        server_ctx.writeFileBlock(cmd.asData());
        break;
    case Command::Type::LAST_FILE_BLOCK:
        std::cout << "Received LAST_FILE_BLOCK command  with data size: " << cmd.asData().size() << std::endl;
        server_ctx.writeFileBlock(cmd.asData(), true);
        server_ctx.closeFile();
        break;
    case Command::Type::HELLO:
        std::cout << "Received HELLO command" << std::endl;
        // This command is already handled in CheckAutentication but need to send ACK
        break;
    default:
        std::cerr << "Unknown/unexpected command type received\n";
        return false; 
    }
    return true;
}

ErrorCode run_multiple_server_poll(uint16_t PORT, RSACipher & rsa, const std::filesystem::path & path)
{
    sockaddr_in address;
    int addrlen = sizeof(address);

    auto server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        std::cerr <<"socket failed" << std::endl;
        return ErrorCode::Network;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        std::cerr <<"bind failed"<< std::endl;
        close(server_fd);
        return ErrorCode::Network;
    }
    if (listen(server_fd, 10) < 0) {
        std::cerr << "listen" << strerror(errno) << " " << errno << std::endl;
        close(server_fd);
        return ErrorCode::Network;
    }
    std::cout << "Server (poll) listening on port " << PORT << std::endl;

    std::vector<ServerContext> contexts;//reserve(1024); // One context per fd
    std::vector<pollfd> fds;
    fds.push_back({server_fd, POLLIN, 0});
    contexts.emplace_back(path); // Add a default ServerContext for the server socket

    for(;;) {
        int ret = poll(fds.data(), fds.size(), -1);//TODO timeout?
        if(errno == EINTR){
            //std::cout << " nReceived Ctrl-C (SIGINT), shutting down gracefully..." << std::endl;
            break;
        }
        if (ret < 0) {
            std::cerr << "poll " << strerror(errno) << " " << errno << std::endl;
            break;
        }

        std::set<int> to_remove;
        for (size_t i = 0; i < fds.size(); ++i) {
            if (fds[i].revents & POLLIN) {
                if (fds[i].fd == server_fd) {
                    int new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
                    if (new_socket < 0) {
                        std::cerr << "accept" << strerror(errno) << " " << errno << std::endl;
                        continue;
                    }
                    fds.push_back({new_socket, POLLIN, 0});
                    contexts.emplace_back(path); // Add a new ServerContext for the new socket
                    std::cout << "New connection accepted on fd: " << new_socket << std::endl;
                    SendSeed(contexts.back(), new_socket);
                    continue;
                }

                PacketBuffer buffer;
                auto bytes_read = read(fds[i].fd, buffer.data(), buffer.size());
                if (bytes_read <= 0) {
                    close(fds[i].fd);
                    to_remove.insert(i);
                    continue;
                }
                try {
                    Command cmd(bytes_read, buffer);
                    if(ProcessCommand(cmd, contexts[i], rsa)) {
                        static Command ack(Command::Type::ACK);
                        sendCommand(fds[i].fd, ack);
                    } 
                    else {
                        std::cerr << "Failed to process command on fd: " << fds[i].fd << std::endl;
                        static Command error_cmd(Command::Type::ERROR, std::string_view("Failed to process command"));
                        sendCommand(fds[i].fd, error_cmd);
                        close(fds[i].fd);
                        to_remove.insert(i);
                    }
                } catch (std::exception &e) {
                    std::cerr << "Server exception: " << e.what() << std::endl;
                    close(fds[i].fd);
                    to_remove.insert(i);
                }               
            }
        }

        for(auto index:to_remove) {
            fds.erase(fds.begin() + index);
            contexts.erase(contexts.begin() + index);
        }
    }
    close(server_fd);
    return ErrorCode::Success;
}
