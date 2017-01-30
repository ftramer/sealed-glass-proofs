#include "ZK-Enclave_u.h"

#include "App.h"
#include "Log.h"
#include "Utils.h"

#include "sgx_uae_service.h"
#include "sgx_report.h"
#include "sgx_trts.h"
#include "sgx_quote.h"
#include "sgx_utils.h"
#include "sgx_urts.h"
#include "sgx_tcrypto.h"

#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <time.h>
#include <chrono>

#include "mbedtls\sha256.h"
#include "mbedtls\entropy.h"
#include "mbedtls\ctr_drbg.h"
#include "mbedtls\rsa.h"
#include "crypto.h"
#include "query_parser.h"

#define MAX_SIZE 2048


void prepare_sql_exploit(char* input, int* len) {
	/*
	 * Exploit input
	 */
	std::string user = " ' OR '1' = '1'; --";
	std::string pswd = "1234";

	std::string user_enc = urlencode(user);
	std::string pswd_enc = urlencode(pswd);

	std::stringstream body_ss;
	body_ss << "username=" << user_enc << "&password=" << pswd_enc;
	std::string body = body_ss.str();

	std::stringstream post_msg;
	post_msg <<	"POST /login HTTP/1.1\r\n"
				"Accept: */*\r\n"
				"Content-Type: application/x-www-form-urlencoded\r\n"
				"Content-Length: " << body.length() << "\r\n"
				"\r\n"
				<< body;
	
	std::string temp = post_msg.str();
	memcpy(input, temp.c_str(), temp.length());
	*len = temp.length();
}

void prepare_frankencert(char* input, int* len) {
	std::ifstream file("../DiffTesting/data/test.crt");
    std::stringstream buffer;

    buffer << file.rdbuf();
    std::string str = buffer.str();
	file.close();
	/*
	 * Date is BEFORE the certificate's validity period.
	 * In older versions of PolarSSL (now mbedTLS) the certificate was accepted.
	 */
	tm time;
	time.tm_year = 2016 - 1900;
	time.tm_mon = 1;
	time.tm_mday = 1;
	time.tm_hour = 0;
	time.tm_min = 0;
	time.tm_sec = 0;
	time_t time_str = mktime(&time);

	memcpy(input, &time_str, sizeof(time_str));
	memcpy(input+sizeof(time_str), str.c_str(), str.length());
	*len = sizeof(time_str) + str.length();
}

void prepare_dummy(char* input, int* len) {
	*len = 1;
}


int main() 
{ 
	sgx_enclave_id_t eid=0; 
	int	ret;
	sgx_launch_token_t token = {0}; 
	const sgx_spid_t spid = {0};
	int updated = 0;

	// Create the Enclave
	if ((ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL)) != SGX_SUCCESS) { 
		printf("App: error %#x, failed to create enclave.\n", ret);
		return -1; 
	} 
	printf("Enclave creation success!\n");

	sgx_target_info_t quote_enc_info;
    sgx_epid_group_id_t p_gid;
    sgx_report_t report;
    sgx_init_quote(&quote_enc_info, &p_gid);
	
	int int_ret;
	int input_len;
	char input[MAX_SIZE] = {'\0'};
	prepare_frankencert(input, &input_len);
	//prepare_sql_exploit(input, &input_len);
	//prepare_dummy(input, &input_len);
	int output;

	assert (input_len < MAX_SIZE);

	/*
	 * Crypto inputs
	 */
	crypto_t crypto;
	if ((ret = init_rng(&crypto)) != 0) {
		printf("Error %#x on init RNG.\n", ret);
		goto error;
	}
	
	if ((ret = gen_aes_key(&crypto)) != 0) {
		printf("Error %#x on generating keys.\n", ret);
		goto error;
	}
    
	// encapsulate all crypto keys in a message for the enclave
	key_msg key_msg;
	memcpy(key_msg.k, crypto.keys.k, sizeof (key_msg.k));

	// ask enclave to encrypt input and hash keys
	byte m_cipher[MAX_SIZE]={'\0'};
	sgx_sha256_hash_t commit;

	auto t1 = std::chrono::high_resolution_clock::now();
    
	/*
	 * Run an enclaved program on a given input
	 */
	if ((ret = run_encrypt_attest(eid, &int_ret, (byte*) input, input_len, (byte*) &output, sizeof (output), 
			&key_msg, m_cipher, (byte*) &commit, &quote_enc_info, &report)) != SGX_SUCCESS) {
		printf("Error %#x on call to run_and_attest.\n", ret);
		goto error;
	}

	printf("run_and_attest returned %d.\n", int_ret);

	if (int_ret != SGX_SUCCESS) {
        print_error_message(ret);
		goto error;
    }
	if (output == TRUE) {
		printf("Exploit succeeded!\n");
	} else {
		printf("Exploit failed!\n");
	}
	
	// Generate Attestation to be sent to buyer
	uint32_t quote_size;
	if ((ret = sgx_get_quote_size(NULL, &quote_size)) != SGX_SUCCESS) {
		printf("Error %#x on call to sgx_get_quote_size.\n", ret);
		goto error;
	}

	sgx_quote_t* quote = (sgx_quote_t*) malloc(quote_size);
	if ((ret = sgx_get_quote(&report, SGX_LINKABLE_SIGNATURE, &spid, NULL, NULL, 0, NULL, quote, quote_size)) != SGX_SUCCESS) {
		printf("Error %#x on call to sgx_get_quote.\n", ret);
		goto error;
	}
	free(quote);

	auto t2 = std::chrono::high_resolution_clock::now();
    printf("exploit computation took %d ms\n", std::chrono::duration_cast<std::chrono::milliseconds>(t2-t1).count());

	/*
	 * Buyer Verification Code (To be factored out)
	 */

	// verify report data hash
	output_field_t outputs[3] = {
		{&output, sizeof (output)},
		{m_cipher, input_len},
		{commit, sizeof (commit)}
	};

	printf("Proof size: %d + %d Bytes\n",input_len, quote_size + sizeof (output) + sizeof (commit));

	verify_report(outputs, 3, report.body.report_data.d);

	// verify the key commitment
	byte key_commit[SGX_HASH_SIZE];
	mbedtls_sha256((const byte*) crypto.keys.k, sizeof (crypto.keys.k), key_commit, 0);
	if (memcmp(key_commit, commit, sizeof (key_commit)) != 0) {
		printf("Key commitment does not check out!\n", ret);
		goto error;
	}

	// decrypt the exploit input
	byte plain[MAX_SIZE];
	if ((ret = decrypt_exploit(eid, &int_ret, &key_msg, m_cipher, input_len, plain)) != SGX_SUCCESS) {
		printf("Error %#x on AES decryption.\n", ret);
		goto error;
	}

	printf("decrypt_exploit returned %d.\n", int_ret);

	if (memcmp(plain, input, input_len) != 0) {
		printf("Exploit decryption failed!\n", ret);
		goto error;
	}

	// Destroy the enclave when all Enclave calls finished. 
	if(SGX_SUCCESS != sgx_destroy_enclave(eid)) 
		return -1;
	
	printf("Enclave destruction success!\n");
	ret = 0;
	goto finish;

error:
	sgx_destroy_enclave(eid);
	ret = -1;
	goto finish;

finish:
	printf("Enter a character before exit ...\n");
	fflush(stdout);
    getchar();

	return ret;
}

void verify_report(output_field_t* output_fields, size_t num_fields, uint8_t* digest) {

	byte hash[32];
	hash_output(output_fields, num_fields, hash);

	dump_buf("Report Digest:", digest, SGX_HASH_SIZE);
	dump_buf("Computed Hash:", hash, SGX_HASH_SIZE);
	if (memcmp(hash, digest, SGX_HASH_SIZE) == 0) {
		printf ("Report is Valid!\n");
	} else {
		printf ("Report is Not Valid!\n");
	}
}