#include "common.h"

std::ostream& operator<<(std::ostream& os, const std::vector<unsigned char>& data) {
    for (auto byte : data) {
        os << (std::isprint(byte) ? (char)byte : '.');
    }
    return os;
}

Data toData(const std::string_view & str){
    return Data(str.begin(), str.end());
}
