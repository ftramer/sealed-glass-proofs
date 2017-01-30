#pragma once

#include "keys.h"

int encrypt_input(byte* input, size_t len_in, key_msg* key_msg, byte* m_cipher, uint8_t* commit);