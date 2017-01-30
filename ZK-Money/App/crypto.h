#pragma once

#include "mbedtls\entropy.h"
#include "mbedtls\ctr_drbg.h"
#include "mbedtls\rsa.h"
#include "mbedtls\pk.h"
#include "mbedtls\sha256.h"
#include "keys.h"

typedef struct{
	void* ptr;
	size_t size;
} output_field_t;

typedef struct {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context rng;
	crypto_keys keys;
} crypto_t;

int hash_output(output_field_t* output_fields, size_t num_fields, byte hash[32]);
int init_rng(crypto_t* ctx);
int gen_aes_key(crypto_t* ctx);