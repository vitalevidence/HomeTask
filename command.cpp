#include "command.h"
#include <stdexcept>
#include <iostream>
#include <sys/socket.h>
#include <cstring>
#include <unistd.h>
#include <poll.h>

Command::Command(size_t size, const PacketBuffer & data){
    if (size < sizeof(Type)) {
        //throw std::invalid_argument("Data size is too small to contain Command type");
        std::cerr << "Data size is too small to contain Command type" << std::endl;
        type_ = Type::NONE;
        return;
    }

    type_ = static_cast<Type>(data[0]);
    if(type_ <= Type::NONE || type_ >= Type::LAST) {
        std::cerr << "Invalid Command type: " << static_cast<int>(type_) << std::endl;
        //throw std::invalid_argument("Invalid Command type");
    }

    std::cout << "Command "<< size << " " << data.size() << " " << (int)data[0]<< std::endl;

    data_ = std::vector<unsigned char>(data.begin() + sizeof(Type), data.begin() + size);
    if (data_.size() != size - sizeof(Type)) {
        //throw std::invalid_argument("Data size does not match specified size");
    }
}

std::string Command::asString() const{
    std::string result{data_.begin(), data_.end()};
    result.push_back('\0'); 
    return result;
}

bool sendCommand(int sock, const Command & cmd) {
    std::cout << "Sending command of type: " << static_cast<int>(cmd.type()) << " with size: " << cmd.size() << std::endl;
    PacketBuffer buffer;
    //memset(buffer.data(), 0, buffer.size()); 
    buffer[0] = static_cast<unsigned char>(cmd.type());
    const auto & data = cmd.asData();
    if(!data.empty()){
        //memccpy(buffer.begin() + 1, data.data(), data.size(), buffer.size() - 1);
        std::copy(data.begin(), data.end(), buffer.begin() + 1);
    }

    auto bytes_sent = send(sock, buffer.data(), cmd.size(), 0);
    if (bytes_sent != cmd.size()) {
        std::cerr << "Failed to send command: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

std::expected<Data, int> WaitPacket(int sock, Command::Type type) 
{
    std::array<pollfd, 1> fds = {{sock, POLLIN, 0}};
    int ret = poll(fds.data(), fds.size(), 1000);//Configure timeout
    if (ret < 0) {
        std::cerr << "poll " << strerror(errno) << std::endl;
        return std::unexpected(-1);
    }
    if (ret == 0) {
        std::cerr << "poll timeout" << std::endl;
        return std::unexpected(-1);
    }

    if (!(fds[0].revents & POLLIN)) {
        std::cerr << "No data available for reading" << std::endl;
        return std::unexpected(-1);
    }

    PacketBuffer buffer;
    ssize_t bytes_read;
    bytes_read = read(sock, buffer.data(), buffer.size());
    std::cout << "Reading from socket, bytes read: " << bytes_read << std::endl;
    if(bytes_read < 0) {
        std::cerr << "Failed to read from socket: " << strerror(errno) << std::endl;
        return std::unexpected(-1);
    }
    //std::cout << "1Reading from socket, bytes read: " << bytes_read << std::endl;

    Command command(bytes_read, buffer);
    if(command.type() == type) {
        std::cout << "Received command type: " << static_cast<int>(command.type()) << std::endl;
        return command.asData();
    }
    switch(command.type())
    {
        case Command::Type::ERROR:
            std::cerr << "Received ERROR command: " << command.asString() << std::endl;
            return std::unexpected(-1);
        default:
            std::cerr << "Received unexpected command type: " << static_cast<int>(command.type()) << std::endl;
            return std::unexpected(-1);
    }
}

bool sendCommandWaitAck(int sock, const Command & cmd){
    if (!sendCommand(sock, cmd)) {
        std::cerr << "Failed to send command" << std::endl;
        return false;
    }
    if (!WaitPacket(sock, Command::Type::ACK)) {
        std::cerr << "Failed to receive ACK" << std::endl;
        return false;
    }
    return true;
}
