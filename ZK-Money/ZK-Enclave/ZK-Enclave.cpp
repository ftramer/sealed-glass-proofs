#include "ZK-Enclave_t.h"
#include "ZK-Enclave.h"

#include "Prog.h"

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_tcrypto.h"

#include "string.h"

#include "crypto.h"
#include "assert.h"

/*
 *  Runs an arbitrary program and attests the obtained output and the hash of the input
 */
int run_encrypt_attest(byte* input, size_t len_in, byte* output, size_t len_out,
					   key_msg* key_msg, byte* m_cipher, uint8_t* commit,
					   sgx_target_info_t* quote_enc_info, sgx_report_t* report){
	
	int ret = 0;
	assert(len_in >= sizeof (uint8_t));
	assert(len_out >= sizeof (uint8_t));

	// run the main program to completion
	ret = run(input, len_in, output, len_out);

	if (ret != RUN_SUCCESS) {
		return ret;
	}

	// encrypt the input with a 2-share symmetric key
	if ((ret = encrypt_input(input, len_in, key_msg, m_cipher, commit)) != SGX_SUCCESS) {
		return ret;
	}

	/* ATTESTATION */
	output_field_t output_fields[3] = {
		{output, len_out},	// Program Output
		{m_cipher, len_in}, // ENC_{k} (input)
		{commit, HASH_SIZE}, // H(k1) => "commitment" to k
	};
	sgx_sha256_hash_t data_hash;
	ret = hash_output(output_fields, 3, &data_hash);

	// create report
	sgx_report_data_t data;
	memset(&data.d, 0, sizeof data.d);
	memcpy(&data.d, data_hash, sizeof data_hash);
    ret |= sgx_create_report(quote_enc_info, &data, report);
    return ret;
}

/*
 *  Encrypts a given input under a symmetric key and commits the key.
 */
int encrypt_input(byte* input, size_t len_in, key_msg* key_msg, byte* m_cipher, uint8_t* commit) {
	
	int ret;

	// extract crypto keys
	crypto_t ctx;
	memcpy(ctx.keys.k, key_msg->k, sizeof (ctx.keys.k));

	// commit the key
	if ((ret = sgx_sha256_msg((const uint8_t*) ctx.keys.k, sizeof (ctx.keys.k), (sgx_sha256_hash_t*) commit)) != 0){
		return ret;
	}

	// encrypt the input under a symmetric key
	if ((ret = encrypt_message(&ctx, input, len_in, m_cipher)) != 0) {
		return ret;
	}

	return 0;
}

int decrypt_exploit(key_msg* key_msg, byte* input, size_t len_in, byte* output) {
	int ret;

	// extract crypto keys
	crypto_t ctx;
	memcpy(ctx.keys.k, key_msg->k, sizeof (ctx.keys.k));

	// encrypt the input under a symmetric key
	if ((ret = decrypt_message(&ctx, input, len_in, output)) != 0) {
		return ret;
	}

	return 0;
}