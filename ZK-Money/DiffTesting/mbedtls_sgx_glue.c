#include<stdarg.h>
#include<stdio.h>
#include "sgx_trts.h"
#include "mbedtls\x509.h"
#include "time.h"

int printf(const char *fmt, ...)
{
    int ret = 0;
    return ret;
}

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen )
{
    int ret;
    sgx_status_t st = sgx_read_rand(output, len);
    (void*) data;
    if (st != SGX_SUCCESS) {
        printf("hardware_poll fails with %d\n", st);
        *olen = -1;
        ret = -1;
    }
    else {
        *olen = len;
        ret = 0;
    }

    return ret;
}