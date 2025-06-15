#include <iostream>
#include "server.h"
#include "common.h"
#include "cipher.h"

#include <csignal>
#include <atomic>

void signal_handler(int signum) {
    if (signum == SIGINT) {
        std::cout << "\nReceived Ctrl-C (SIGINT), shutting down gracefully..." << std::endl;
    }
}


int main(int argc, char* argv[]) {
    if (argc != 5 || std::string(argv[1]) != "--listen" || std::string(argv[3]) != "--out") {
        std::cerr << "Usage: " << argv[0] << " --listen <port> --out <path>" << std::endl;
        return 1;
    }
    uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));
    //auto path = std::string_view{argv[4]};

    std::signal(SIGINT, signal_handler);

    RSACipher rsa;
    if (!rsa.loadPrivateKey("./private.pem")) {
        std::cerr << "Failed to read private key from PEM file." << std::endl;
        return (int)ErrorCode::RSA_Key;
    }
    
    return static_cast<int>(run_multiple_server_poll(port, rsa));
}

