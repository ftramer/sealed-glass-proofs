#pragma once

#include "ZK-Enclave.h"
#include "keys.h"

#include "sgx_tcrypto.h"

#define HASH_SIZE 32		// hash digest size in bytes
#define CIPHER_SIZE 1024	// max RSA ciphertext size in bytes

// enclave outputs
typedef struct{
	void* ptr;
	size_t size;
} output_field_t;

// crypto context
typedef struct {
	crypto_keys keys;
} crypto_t;

int hash_output(output_field_t* output_fields, size_t num_fields, sgx_sha256_hash_t* hash);
int init_rng(crypto_t* ctx);
int encrypt_message(crypto_t* ctx, byte* input, size_t len_in, byte* cipher);
int decrypt_message(crypto_t* ctx, byte* input, size_t len_in, byte* output);
int sgx_mbedtls_random(void *data, unsigned char *output, size_t len, size_t *olen);