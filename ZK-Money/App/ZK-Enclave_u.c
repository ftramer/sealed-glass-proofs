#include "ZK-Enclave_u.h"

typedef struct ms_run_encrypt_attest_t {
	int ms_retval;
	byte* ms_input;
	size_t ms_len_in;
	byte* ms_output;
	size_t ms_len_out;
	key_msg* ms_key_msg;
	byte* ms_m_cipher;
	byte* ms_commit;
	sgx_target_info_t* ms_quote_enc_info;
	sgx_report_t* ms_report;
} ms_run_encrypt_attest_t;

typedef struct ms_decrypt_exploit_t {
	int ms_retval;
	key_msg* ms_key_msg;
	byte* ms_input;
	size_t ms_len_in;
	byte* ms_output;
} ms_decrypt_exploit_t;

static const struct {
	size_t nr_ocall;
	void * func_addr[1];
} ocall_table_ZK_Enclave = {
	0,
	{ NULL },
};

sgx_status_t run_encrypt_attest(sgx_enclave_id_t eid, int* retval, byte* input, size_t len_in, byte* output, size_t len_out, key_msg* key_msg, byte* m_cipher, byte* commit, sgx_target_info_t* quote_enc_info, sgx_report_t* report)
{
	sgx_status_t status;
	ms_run_encrypt_attest_t ms;
	ms.ms_input = input;
	ms.ms_len_in = len_in;
	ms.ms_output = output;
	ms.ms_len_out = len_out;
	ms.ms_key_msg = key_msg;
	ms.ms_m_cipher = m_cipher;
	ms.ms_commit = commit;
	ms.ms_quote_enc_info = quote_enc_info;
	ms.ms_report = report;
	status = sgx_ecall(eid, 0, &ocall_table_ZK_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t decrypt_exploit(sgx_enclave_id_t eid, int* retval, key_msg* key_msg, byte* input, size_t len_in, byte* output)
{
	sgx_status_t status;
	ms_decrypt_exploit_t ms;
	ms.ms_key_msg = key_msg;
	ms.ms_input = input;
	ms.ms_len_in = len_in;
	ms.ms_output = output;
	status = sgx_ecall(eid, 1, &ocall_table_ZK_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

