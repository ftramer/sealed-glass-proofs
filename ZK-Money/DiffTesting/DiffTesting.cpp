#include "Prog.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509.h>
#include <time.h>
#include "openssltime_t.h"
#include "TimeUtils.h"
#include "string.h"

#define EXPLOIT_SUCCESS TRUE
#define EXPLOIT_FAILURE FALSE

time_t dummy_time = 0;

int verify_openssl(X509 *cert) {
	X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;

	store = X509_STORE_new();
    assert (store != NULL);

    ctx = X509_STORE_CTX_new();
    assert (ctx != NULL);

	assert (X509_STORE_add_cert(store, cert));
	assert (X509_STORE_CTX_init(ctx, store, cert, NULL));
    
    int ret = X509_verify_cert(ctx);

	if (ret == 1) {
		return 0;
	} else {
		return -1;
	}
}

int verify_mbedtls(mbedtls_x509_crt* cert) {
	uint32_t flags;
	return mbedtls_x509_crt_verify(cert, cert, NULL, NULL, &flags, NULL, NULL);
}

sgx_status_t time(time_t* retval, time_t* t) {
	*retval = dummy_time;
	return (sgx_status_t) 0;
}

int x509_get_current_time(mbedtls_x509_time *now) {
	tm temp;
	assert (__offtime(&dummy_time, 0, &temp) != 0);
	now->year = temp.tm_year + 1900;
    now->mon  = temp.tm_mon + 1;
    now->day  = temp.tm_mday;
    now->hour = temp.tm_hour;
    now->min  = temp.tm_min;
    now->sec  = temp.tm_sec;
	return 0;
}

int run(unsigned char* input, size_t len_in, unsigned char* output, size_t len_out) {
	
	assert (len_in > sizeof(time_t));
	memcpy(&dummy_time, input, sizeof(time_t));
	input += sizeof(time_t);
	len_in -= sizeof(time_t);

	BIO *bio;
	X509 *openssl_cert;
	bio = BIO_new(BIO_s_mem());
	assert (BIO_write(bio, (const void*) input, len_in) == len_in);
	openssl_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	
	int res1 = verify_openssl(openssl_cert);

	mbedtls_x509_crt mbedtls_cert;
	mbedtls_x509_crt_init(&mbedtls_cert);
	mbedtls_x509_crt_parse(&mbedtls_cert, input, len_in + 1);
	
	int res2 = verify_mbedtls(&mbedtls_cert);

	int res = EXPLOIT_FAILURE;
	if ((res1 == 0) ^ (res2 == 0)) {
		res = EXPLOIT_SUCCESS;	
	}

	memcpy(output, &res, sizeof(res));

	return RUN_SUCCESS;
}