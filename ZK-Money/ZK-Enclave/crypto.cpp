#include "crypto.h"
#include "sgx_trts.h"
#include "string.h"
#include "sgx_tcrypto.h"

/*
 * Hashes all of the enclave's outputs
 */
int hash_output(output_field_t* output_fields, size_t num_fields, sgx_sha256_hash_t* hash) {
	int ret;

	// hash of a single payload
	if (num_fields == 1) {
		output_field_t p = output_fields[0];
		return sgx_sha256_msg((const uint8_t*) p.ptr, p.size, hash);
	}

	// iterative hash of multiple payloads
	sgx_sha_state_handle_t sha_sh;
	ret = sgx_sha256_init(&sha_sh);

	for (size_t i = 0; i < num_fields; i++) {
		output_field_t p = output_fields[i];
		ret |= sgx_sha256_update((const uint8_t*) p.ptr, p.size, sha_sh);
	}

	ret |= sgx_sha256_get_hash(sha_sh, hash);
	ret |= sgx_sha256_close(sha_sh);
	return ret;
}

/*
 * Encrypts a message under a symmetric key
 */
int encrypt_message(crypto_t* ctx, byte* input, size_t len_in, byte* cipher) {

	// encrypt using AES CTR mode
	uint8_t ctr[16] = {0};

	return sgx_aes_ctr_encrypt(&ctx->keys.k, input, len_in, ctr, 1, cipher);
}

/*
 * Decrypts a message under a symmetric key
 */
int decrypt_message(crypto_t* ctx, byte* input, size_t len_in, byte* output) {

	uint8_t ctr[16] = {0};
	return sgx_aes_ctr_decrypt(&ctx->keys.k, input, len_in, ctr, 1, output);
}