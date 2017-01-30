#ifndef OPENSSLTIME_T_H__
#define OPENSSLTIME_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "time.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif



sgx_status_t SGX_CDECL time(time_t* retval, time_t* t);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
