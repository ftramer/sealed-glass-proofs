#include "sqlite.h"
#include "sgx_trts.h"
#include "sqlite_sgx.h"

// SGX random source for sqlite
int randomness(sqlite3_vfs*, int nByte, char *zOut) {
	if (sgx_read_rand((unsigned char*) zOut, nByte) == SGX_SUCCESS) {
		return nByte;
	}
	return 0;
}

// initialize a database in memory
int init_db(sqlite3** db) {
	dummy_vfs.iVersion = 3;
	dummy_vfs.zName = "dummyVFS";
	dummy_vfs.xRandomness = randomness;
	
	int ret = 0;
	// give sqlite a big heap to work with
	if ((ret = sqlite3_config(SQLITE_CONFIG_HEAP, mem, sizeof (mem), 512)) != SQLITE_OK) {
		return ret;
	}

	if ((ret = sqlite3_vfs_register(&dummy_vfs, 1)) != SQLITE_OK) {
		return ret;
	}

	// create a database in RAM
	int rc;
	rc = sqlite3_open(":memory:", db);

	if (rc) {
		const char* err = sqlite3_errmsg(*db);
		return rc;
	}

	return SQLITE_OK;
}