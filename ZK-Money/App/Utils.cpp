#include "Utils.h"
#include "App.h"


/* Check error conditions for loading enclave */
void print_error_message(int ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

void hexdump(const char* title, void const * data, unsigned int len)
{
    unsigned int i;
    unsigned int r,c;
    
    if (!data)
	return;

    printf("%s\n", title);
    
    for (r=0,i=0; r<(len/16+(len%16!=0)); r++,i+=16)
    {
        printf("0x%04X:   ",i); /* location of first byte in line */
	
        for (c=i; c<i+8; c++) /* left half of hex dump */
	    if (c<len)
        	printf("%02X ",((unsigned char const *)data)[c]);
	    else
		printf("   "); /* pad if short line */
	
	printf("  ");
	
	for (c=i+8; c<i+16; c++) /* right half of hex dump */
	    if (c<len)
		printf("%02X ",((unsigned char const *)data)[c]);
	    else
		printf("   "); /* pad if short line */
	
	printf("   ");
	
	for (c=i; c<i+16; c++) /* ASCII dump */
	    if (c<len)
		if (((unsigned char const *)data)[c]>=32 &&
		    ((unsigned char const *)data)[c]<127)
		    printf("%c",((char const *)data)[c]);
		else
		    printf("."); /* put this for non-printables */
	    else
		printf(" "); /* pad if short line */
	
	printf("\n");
    }
}

void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    hexdump(title, buf, len);
}