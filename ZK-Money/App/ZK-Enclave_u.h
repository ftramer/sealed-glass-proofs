#ifndef ZK_ENCLAVE_U_H__
#define ZK_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_report.h"
#include "keys.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t run_encrypt_attest(sgx_enclave_id_t eid, int* retval, byte* input, size_t len_in, byte* output, size_t len_out, key_msg* key_msg, byte* m_cipher, byte* commit, sgx_target_info_t* quote_enc_info, sgx_report_t* report);
sgx_status_t decrypt_exploit(sgx_enclave_id_t eid, int* retval, key_msg* key_msg, byte* input, size_t len_in, byte* output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
