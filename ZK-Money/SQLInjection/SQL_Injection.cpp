#include "Prog.h"

#include "sqlite.h"
#include "sqlite_sgx.h"
#include <string>
#include "assert.h"
#include "sgx_trts.h"

#include "exploit/http_parser.h"
#include "exploit/simple_parser.h"
#include "exploit/query_parser.h"

using namespace proxygen;

#define LOGIN_PATH "/login"
#define USERNAME "username"
#define PASSWORD "password"

#define USER "Alice"
#define MAX_STR_LEN 40	// size of max string

#define LOGIN_SUCCESS TRUE
#define LOGIN_FAILURE FALSE

static std::string s = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static size_t stringLen = s.size();

int rand_pswd(unsigned char* pswd, size_t len) {
	int ret;

	if ((ret = sgx_read_rand(pswd, len)) != SGX_SUCCESS) {
		return ret;
	}

	for (size_t i=0; i<len; i++) {
		pswd[i] = s[pswd[i] % stringLen];
	}

	return SGX_SUCCESS;
}

int populate_db_random(sqlite3* db) {
	int ret;
	char* err = 0;

	/* CREATE TABLE statement */
	char* sql = "CREATE TABLE USERS("  \
			"ID INT PRIMARY KEY     NOT NULL," \
			"USERNAME       TEXT    NOT NULL UNIQUE," \
			"PASSWORD       TEXT    NOT NULL);";

	/* Execute CREATE TABLE statement */
	if ((ret = sqlite3_exec(db, sql, NULL, 0, &err)) != SQLITE_OK) {
		sqlite3_free(err);
		return ret;
	}

	unsigned char pswd[MAX_STR_LEN + 1] = {'\0'};
	
	// create a random password
	if (ret = (rand_pswd(pswd, MAX_STR_LEN) != SGX_SUCCESS)) {
		return ret;
	}

	/* INSERT statement */
	sql = sqlite3_mprintf("INSERT INTO USERS (ID,USERNAME,PASSWORD) "  \
				"VALUES (%d, '%s', '%s'); ", 1, USER, pswd);

	/* Execute INSERT statement */
	if ((ret = sqlite3_exec(db, sql, NULL, 0, &err)) != SQLITE_OK) {
		sqlite3_free(err);
		sqlite3_free(sql);
		return ret;
	}

	sqlite3_free(sql);
	return SQLITE_OK;
}

int erase_table(sqlite3* db) {
	int ret;
	char* err = 0;

	/* CREATE TABLE statement */
	char* sql = "DROP TABLE USERS;";

	/* Execute DELETE TABLE statement */
	if ((ret = sqlite3_exec(db, sql, NULL, 0, &err)) != SQLITE_OK) {
		sqlite3_free(err);
		return ret;
	}

	return SQLITE_OK;
}

int successful_login(void *data, int argc, char **argv, char **azColName){
	*((int*) data) = LOGIN_SUCCESS;
	return SQLITE_OK;
}

int login(const char* user, const char* pswd, sqlite3* db, int* res_login) {
	char * err;
	int ret;

	/*
	 * TODO
	 * Password should ideally be salted and hashed
	 */

	/* 
	 * SQL Injection
	 * Changing the %s wildcard to %q (or using a prepared statement would remove the bug)
	 */
	char* sql = sqlite3_mprintf("SELECT * from USERS where USERNAME='%s' AND PASSWORD='%s' LIMIT 1", user, pswd);

	/* 
	 * Execute SELECT statement. 
	 * If a matching record is found, the callback sets 'res_login = LOGIN_SUCCESS'
	 */
	if ((ret = sqlite3_exec(db, sql, successful_login, res_login, &err)) != SQLITE_OK) {
		sqlite3_free(err);
		sqlite3_free(sql);
		return ret;
	}

	sqlite3_free(sql);
	return SQLITE_OK;
}

int parse_input(char* post_msg, size_t len_in, key_value_map& map) {
	http_parser_settings settings;
	http_parser parser;
	message msg = {};

	parser_init(&parser, &settings);
	parser.data = &msg;

	int nparsed = http_parser_execute(&parser, &settings, post_msg, len_in);

	if (nparsed != len_in) {
		return -1;
	}

	if (http_parser_execute(&parser, &settings, 0, 0) != 0) {
		return -1;
	}

	if (strncmp(msg.request_uri, LOGIN_PATH, sizeof (LOGIN_PATH)) != 0) {
		return -1;
	}
	
	parse_url(msg.body, map);

	return 0;
}

int run(unsigned char* input, size_t len_in, unsigned char* output, size_t len_out) {
	
	char *err = 0;
	sqlite3* db;

	// initialize the db and populate with randomly chosen users
	if (init_db(&db) != SQLITE_OK) {
		return RUN_ERROR;
	}
	
	key_value_map m;
	parse_input((char*) input, len_in, m);
	
	if (m.count(USERNAME) == 0 || m.count(PASSWORD) == 0) {
		return RUN_ERROR;
	}

	int res_login = LOGIN_FAILURE;

	for (int i=0; i<10000; i++){
		if (populate_db_random(db) != SQLITE_OK) {
			return RUN_ERROR;
		}
	
		if (login(m[USERNAME].c_str(), m[PASSWORD].c_str(), db, &res_login) != SQLITE_OK) {
			return RUN_ERROR;
		}

		if (erase_table(db) != SQLITE_OK) {
			return RUN_ERROR;
		}
	}

	// close the database connection
	if (sqlite3_close(db) != SQLITE_OK) {
		return RUN_ERROR;
	}
	
	// the output is the result of the login attempt
	memcpy(output, &res_login, sizeof (res_login));
	return RUN_SUCCESS;
}