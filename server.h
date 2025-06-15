#pragma once
#include <cstdint>
#include "cipher.h"

ErrorCode run_multiple_server_poll(uint16_t PORT, RSACipher & rsa);
