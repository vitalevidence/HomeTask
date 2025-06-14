#include <iostream>
#include "client.h"
#include "cipher.h"
#include <ctime>
#include "common.h"
int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <host> <port> <path-to-file>";
        return 1;
    }
    auto host = std::string_view{argv[1]};
    uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));
    auto file = std::string_view{argv[3]};

    RSACipher rsa;    
    if (!rsa.loadPublicKey("./public.pem")) {
        std::cerr << "Failed to read public key from PEM file." << std::endl;
        return (int)ErrorCode::RSA_Key;
    }

    std::srand(std::time({}));
    std::vector<unsigned char> session_key(IV_SIZE);

    return (int)run_client(host, file, port, rsa);
}