#pragma once

#include "sgx_tcrypto.h"

typedef unsigned char byte;

#define AES_KEY_SIZE 16
#define AES_KEY_SIZE_BITS (AES_KEY_SIZE * 8)
#define AES_IV_SIZE 16
#define MAX_PEM_SIZE 2000

typedef struct {
	byte k[AES_KEY_SIZE];
} crypto_keys;

typedef struct {
	sgx_aes_ctr_128bit_key_t k;
} key_msg;