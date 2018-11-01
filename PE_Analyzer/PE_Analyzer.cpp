// PE_Analyzer.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
	if (IsValidPeFile(argv[1]))
	{
		_tprintf(_T("\n\n%s is a valid PE file ...\n\n"), argv[1]);

		ParseDosHeader(argv[1]);

		ParseNtFileHeader(argv[1]);

		ParseNtOptionalHeader(argv[1]);

		ParseSectionTable(argv[1]);

		ParseDataDirectory(argv[1]);
	}
	else
	{
		_tprintf(_T("%s is not a valid PE file ...\n"), argv[1]);
	}
	return 0;
}

