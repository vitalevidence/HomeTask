#pragma once
#include <vector>
#include <string_view>
#include <cstdint>
#include <string>
#include <iostream>
#include "common.h"
#include <expected>

#pragma pack(push, 1) // Ensure 1-byte alignment for the Command struct
struct Command {
    enum class Type: uint8_t {
        NONE,
        SEED,
        HELLO,
        IV_KEY,
        BEGIN_FILE,
        RESUME_FILE,
        FILE_BLOCK,
        END_FILE,
        ERROR,
        ACK,
        EXIT,
        
        LAST
    };

    ssize_t size() const {
        return sizeof(Type) + data_.size();
    }

    auto type() const {
        return type_;
    }

    Command(Type type): type_(type){}
    
    Command(Type type, std::vector<unsigned char> && data)
        : type_(type), data_(std::move(data)){}

    Command(Type type, const std::vector<unsigned char> & data)
        : type_(type), data_(data){}

    template<size_t Sz>
    Command(Type type, const std::array<unsigned char, Sz> & data)
        : type_(type), data_(data.begin(), data.end()){}

    Command(Type type, const std::string_view & str)
    : type_(type), data_(str.begin(), str.end()){}

    Command(Type type, const std::string & str)
    : type_(type), data_(str.begin(), str.end()){}

    Command(size_t size, const PacketBuffer & data);
    
    std::string asString() const;
    
    const Data& asData() const {
        return data_;
    }
private:
    Type type_ = Type::NONE;
    std::vector<unsigned char> data_; 
};
#pragma pack(pop) 

bool sendCommand(int sock, const Command & cmd);

std::expected<Data, int> WaitPacket(int sock, Command::Type type);

bool sendCommandWaitAck(int sock, const Command & cmd);
