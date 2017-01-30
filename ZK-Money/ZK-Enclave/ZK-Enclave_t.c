#include "ZK-Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

/* sgx_ocfree() just restores the original outside stack pointer. */
#define OCALLOC(val, type, len) do {	\
	void* __tmp = sgx_ocalloc(len);	\
	if (__tmp == NULL) {	\
		sgx_ocfree();	\
		return SGX_ERROR_UNEXPECTED;\
	}			\
	(val) = (type)__tmp;	\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_run_encrypt_attest(void* pms)
{
	ms_run_encrypt_attest_t* ms = SGX_CAST(ms_run_encrypt_attest_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	byte* _tmp_input = ms->ms_input;
	size_t _tmp_len_in = ms->ms_len_in;
	size_t _len_input = _tmp_len_in;
	byte* _in_input = NULL;
	byte* _tmp_output = ms->ms_output;
	size_t _tmp_len_out = ms->ms_len_out;
	size_t _len_output = _tmp_len_out;
	byte* _in_output = NULL;
	key_msg* _tmp_key_msg = ms->ms_key_msg;
	size_t _len_key_msg = sizeof(*_tmp_key_msg);
	key_msg* _in_key_msg = NULL;
	byte* _tmp_m_cipher = ms->ms_m_cipher;
	size_t _len_m_cipher = _tmp_len_in;
	byte* _in_m_cipher = NULL;
	byte* _tmp_commit = ms->ms_commit;
	size_t _len_commit = 32;
	byte* _in_commit = NULL;
	sgx_target_info_t* _tmp_quote_enc_info = ms->ms_quote_enc_info;
	size_t _len_quote_enc_info = sizeof(*_tmp_quote_enc_info);
	sgx_target_info_t* _in_quote_enc_info = NULL;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(*_tmp_report);
	sgx_report_t* _in_report = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_run_encrypt_attest_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);
	CHECK_UNIQUE_POINTER(_tmp_output, _len_output);
	CHECK_UNIQUE_POINTER(_tmp_key_msg, _len_key_msg);
	CHECK_UNIQUE_POINTER(_tmp_m_cipher, _len_m_cipher);
	CHECK_UNIQUE_POINTER(_tmp_commit, _len_commit);
	CHECK_UNIQUE_POINTER(_tmp_quote_enc_info, _len_quote_enc_info);
	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);

	if (_tmp_input != NULL) {
		_in_input = (byte*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	if (_tmp_output != NULL) {
		if ((_in_output = (byte*)malloc(_len_output)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output, 0, _len_output);
	}
	if (_tmp_key_msg != NULL) {
		_in_key_msg = (key_msg*)malloc(_len_key_msg);
		if (_in_key_msg == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_key_msg, _tmp_key_msg, _len_key_msg);
	}
	if (_tmp_m_cipher != NULL) {
		if ((_in_m_cipher = (byte*)malloc(_len_m_cipher)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_m_cipher, 0, _len_m_cipher);
	}
	if (_tmp_commit != NULL) {
		if ((_in_commit = (byte*)malloc(_len_commit)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_commit, 0, _len_commit);
	}
	if (_tmp_quote_enc_info != NULL) {
		_in_quote_enc_info = (sgx_target_info_t*)malloc(_len_quote_enc_info);
		if (_in_quote_enc_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_quote_enc_info, _tmp_quote_enc_info, _len_quote_enc_info);
	}
	if (_tmp_report != NULL) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}
	ms->ms_retval = run_encrypt_attest(_in_input, _tmp_len_in, _in_output, _tmp_len_out, _in_key_msg, _in_m_cipher, _in_commit, _in_quote_enc_info, _in_report);
err:
	if (_in_input) free(_in_input);
	if (_in_output) {
		memcpy(_tmp_output, _in_output, _len_output);
		free(_in_output);
	}
	if (_in_key_msg) free(_in_key_msg);
	if (_in_m_cipher) {
		memcpy(_tmp_m_cipher, _in_m_cipher, _len_m_cipher);
		free(_in_m_cipher);
	}
	if (_in_commit) {
		memcpy(_tmp_commit, _in_commit, _len_commit);
		free(_in_commit);
	}
	if (_in_quote_enc_info) free(_in_quote_enc_info);
	if (_in_report) {
		memcpy(_tmp_report, _in_report, _len_report);
		free(_in_report);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_decrypt_exploit(void* pms)
{
	ms_decrypt_exploit_t* ms = SGX_CAST(ms_decrypt_exploit_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	key_msg* _tmp_key_msg = ms->ms_key_msg;
	size_t _len_key_msg = sizeof(*_tmp_key_msg);
	key_msg* _in_key_msg = NULL;
	byte* _tmp_input = ms->ms_input;
	size_t _tmp_len_in = ms->ms_len_in;
	size_t _len_input = _tmp_len_in;
	byte* _in_input = NULL;
	byte* _tmp_output = ms->ms_output;
	size_t _len_output = _tmp_len_in;
	byte* _in_output = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_decrypt_exploit_t));
	CHECK_UNIQUE_POINTER(_tmp_key_msg, _len_key_msg);
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);
	CHECK_UNIQUE_POINTER(_tmp_output, _len_output);

	if (_tmp_key_msg != NULL) {
		_in_key_msg = (key_msg*)malloc(_len_key_msg);
		if (_in_key_msg == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_key_msg, _tmp_key_msg, _len_key_msg);
	}
	if (_tmp_input != NULL) {
		_in_input = (byte*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	if (_tmp_output != NULL) {
		if ((_in_output = (byte*)malloc(_len_output)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output, 0, _len_output);
	}
	ms->ms_retval = decrypt_exploit(_in_key_msg, _in_input, _tmp_len_in, _in_output);
err:
	if (_in_key_msg) free(_in_key_msg);
	if (_in_input) free(_in_input);
	if (_in_output) {
		memcpy(_tmp_output, _in_output, _len_output);
		free(_in_output);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_run_encrypt_attest, 0},
		{(void*)(uintptr_t)sgx_decrypt_exploit, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


#ifdef _MSC_VER
#pragma warning(pop)
#endif
