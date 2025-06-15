
#pragma once
#include <cstdint>
#include "cipher.h"

ErrorCode run_client(const std::string_view &server_ip, const std::filesystem::path & filepath, const std::string &out_filename, uint16_t PORT, RSACipher & rsa);
