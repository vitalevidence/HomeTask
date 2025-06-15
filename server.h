#pragma once
#include <cstdint>
#include "cipher.h"
#include <filesystem>

ErrorCode run_multiple_server_poll(uint16_t PORT, RSACipher & rsa, const std::filesystem::path & path);
