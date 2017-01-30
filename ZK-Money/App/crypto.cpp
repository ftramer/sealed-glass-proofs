#include "crypto.h"
#include "sgx_trts.h"
#include "string.h"

// RSA parameters
#define EXPONENT 65537
#define KEY_LEN 2048

/*
 *  Hash of enclave outputs
 */
int hash_output(output_field_t* output_fields, size_t num_fields, byte* hash) {

	// hash of a single payload
	if (num_fields == 1) {
		output_field_t p = output_fields[0];
		mbedtls_sha256((const unsigned char*) p.ptr, p.size, hash, 0);
		return 0;
	}
	
	// iterative hash of multiple payloads
	mbedtls_sha256_context sha_ctx;
	mbedtls_sha256_init(&sha_ctx);
	mbedtls_sha256_starts(&sha_ctx, 0);

	for (int i = 0; i < num_fields; i++) {
		output_field_t p = output_fields[i];
		mbedtls_sha256_update(&sha_ctx, (const unsigned char*) p.ptr, p.size);
	}

	mbedtls_sha256_finish(&sha_ctx, hash);
	return 0;
}

/*
 * Initialize the host's RNG
 */
int init_rng(crypto_t* ctx) {
	int ret;
	
	// SGX Entropy Source
	mbedtls_entropy_init(&ctx->entropy);

	if ((ret = mbedtls_ctr_drbg_seed(&ctx->rng, mbedtls_entropy_func, &ctx->entropy, NULL, NULL)) != 0) {
		return ret;
	}

	// PRNG
    mbedtls_ctr_drbg_init(&ctx->rng);
	if ((ret =  mbedtls_ctr_drbg_seed(&ctx->rng, mbedtls_entropy_func, &ctx->entropy, NULL, NULL)) != 0) {
		return ret;
	}
	mbedtls_ctr_drbg_set_prediction_resistance(&ctx->rng, MBEDTLS_CTR_DRBG_PR_ON);

	return 0;
}

/*
 * Generate an AES key
 */
int gen_aes_key(crypto_t* ctx) {
	int ret = 0;

	if((ret = mbedtls_ctr_drbg_random(&ctx->rng, ctx->keys.k, AES_KEY_SIZE)) != 0) {
		return ret;
	}

	return 0;
}