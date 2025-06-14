
#pragma once
#include <cstdint>
#include "cipher.h"

ErrorCode run_client(const std::string_view &server_ip, const std::string_view &filename, uint16_t PORT, RSACipher & rsa);
