/*
 * Generic Interface for a program to be run in the enclave
 * A enclave library defining the 'run' function must be statically linked.
 */

#define RUN_SUCCESS 0
#define RUN_ERROR 1

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 1
#endif

int run(unsigned char* input, size_t len_in, unsigned char* output, size_t len_out);
