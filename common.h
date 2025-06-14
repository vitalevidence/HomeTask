#pragma once
#include <stddef.h>
#include <cstdint>
#include <unistd.h>
#include <array>
#include <vector>
#include <string_view>

constexpr size_t BUFFER_SIZE = 1490; //Fit MTU size for network packets
using PacketBuffer = std::array<unsigned char, BUFFER_SIZE>;

constexpr static size_t BLOCK_SIZE = 16; // AES block size in bytes
constexpr static size_t KEY_SIZE = 16;   // AES key size in bytes (128 bits)
constexpr static size_t IV_SIZE = 16;    // AES IV size in bytes (128 bits)

using IV = std::array<unsigned char, IV_SIZE>;
using KEY = std::array<unsigned char, KEY_SIZE>;

using Data = std::vector<unsigned char>;

enum class ErrorCode{
    Success = 0,
    Network = 1,
    Authentication = 2,
    IO = 3,
    RSA_Key = 4,
    AES = 5,
};

constexpr std::string_view HelloMessage{"Hello"};

Data toData(const std::string_view & str);

#include <iomanip>
#include <clocale>

/*std::ostream& operator<<(std::ostream& os, const std::vector<unsigned char>& data) {
    os << std::hex << std::setfill('0');
    for (unsigned char byte : data) {
        os << std::setw(2) << static_cast<int>(byte);
    }
    os << std::dec;
    return os;
}
    */

std::ostream& operator<<(std::ostream& os, const std::vector<unsigned char>& data);

template <typename T, auto Deleter> 
    requires(std::is_invocable_v<decltype(Deleter), T>)
class RAII1 {
public:
    RAII1() : value_{} {}

    explicit RAII1(T value) : value_(value) {}
    
    RAII1& operator =(T value) {
        Deleter(value_);
        value_ = value;
        return *this;
    }

    ~RAII1() {
        Deleter(value_);
    }

    RAII1(const RAII1&) = delete; 
    RAII1& operator=(const RAII1&) = delete; 

    RAII1(RAII1&& other){
        value_ = other.value_;
        other.value_ = T{}; 
    }

    RAII1& operator=(RAII1&& other){
        if (this != &other) {
            value_ = other.value_;
            other.value_ = T{}; 
        }
        return *this;
    }

    template<typename C=T> typename std::enable_if_t<std::is_integral_v<C>, const C&> 
    operator*() const { return value_; }

    template<typename C=T> typename std::enable_if_t<std::is_pointer_v<C>, C> 
    operator*() const { return value_; }

    operator bool() const { return value_ != T{}; }
    
    //template<typename C=T> typename std::enable_if_t<std::is_pointer_v<C>, C> 
    //get() const { return ptr_.get(); }
    //T* operator->() const { return ptr_.get(); }
private:
    T value_;
};

using RAII_File = RAII1<FILE*, std::fclose>;

using RAII_Socket = RAII1<int, &close>;

