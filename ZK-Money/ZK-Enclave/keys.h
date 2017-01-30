#pragma once

#include "sgx_tcrypto.h"

#define AES_KEY_SIZE 16

typedef unsigned char byte;

// key message sent by the host
typedef struct {
	byte k[AES_KEY_SIZE];
} key_msg;


// crypto keys to use
typedef struct {
	sgx_aes_ctr_128bit_key_t k;
} crypto_keys;