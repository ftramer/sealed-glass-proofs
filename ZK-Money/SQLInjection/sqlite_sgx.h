#pragma once

#include "sqlite.h"

// memory buffer for dynamic allocations in sqlite
static unsigned char mem[(1 << 18)];

// define a dummy file system for SGX
static sqlite3_vfs dummy_vfs;

int randomness(sqlite3_vfs*, int nByte, char *zOut);
int init_db(sqlite3** db);