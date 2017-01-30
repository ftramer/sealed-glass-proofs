#pragma once

#include "sgx_error.h"

void print_error_message(int ret);

void hexdump(const char* title, void const * data, unsigned int len);
void dump_buf( const char *title, unsigned char *buf, size_t len );