#include "stdafx.h"

TCHAR*	DataDirectoryName[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {
	_T("Export Directory"), _T("Import Directory"), _T("Resource Directory"), _T("Exception Directory"),
	_T("Security Directory"), _T("Base Relocation Table"), _T("Debug Directory"),
	_T("X86 usage"), _T("Architecture Specific Data"), _T("RVA of GP"),
	_T("TLS Directory"), _T("Load Configuration Directory"),
	_T("Bound Import Directory in headers"), _T("Import Address Table"),
	_T("Delay Load Import Descriptors"), _T("COM Runtime descriptor")
};

BOOL	IsValidPeFile(WCHAR	*pwszPeFilePath)
{
	IMAGE_DOS_HEADER		dosHeader;
	ULONG					ulNtSignature;
	HANDLE					hPeFile = INVALID_HANDLE_VALUE;
	BOOL					bRet;
	DWORD					dwBytesRead;


	hPeFile = CreateFileW(pwszPeFilePath, 
						  GENERIC_READ,
						  FILE_SHARE_READ,
						  NULL,
						  OPEN_EXISTING,
						  FILE_ATTRIBUTE_NORMAL,
						  NULL);

	if (hPeFile == NULL)
	{
		_tprintf(_T("failed to CreateFileW %s : %d\n"), pwszPeFilePath, GetLastError());
		return 1;
	}

	bRet = ReadFile(hPeFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_DOS_HEADER : %d\n"), GetLastError());
		return 1;
	}

	SetFilePointer(hPeFile, dosHeader.e_lfanew, NULL, FILE_BEGIN);

	bRet = ReadFile(hPeFile, &ulNtSignature, sizeof(ULONG), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_NT_SIGNATURE : %d\n"), GetLastError());
		return 1;
	}

	if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE && ulNtSignature == IMAGE_NT_SIGNATURE)
	{
		return TRUE;
	}

	CloseHandle(hPeFile);

	return FALSE;
}

void	ParseDosHeader(WCHAR *pwszPeFilePath)
{
	IMAGE_DOS_HEADER		dosHeader;
	HANDLE					hPeFile = INVALID_HANDLE_VALUE;
	BOOL					bRet;
	DWORD					dwBytesRead;


	hPeFile = CreateFileW(pwszPeFilePath, 
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hPeFile == NULL)
	{
		_tprintf(_T("failed to CreateFileW %s : %d\n"), pwszPeFilePath, GetLastError());
		return ;
	}

	bRet = ReadFile(hPeFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_DOS_HEADER : %d\n"), GetLastError());
		return ;
	}

	_tprintf(_T("******** DOS Header Information *******\n"));
	_tprintf(_T("\t Magic number : 0x%x\n"), dosHeader.e_magic);
	_tprintf(_T("\t Bytes on last page of file : 0x%x\n"), dosHeader.e_cblp);
	_tprintf(_T("\t Pages in file : 0x%x\n"), dosHeader.e_cp);
	_tprintf(_T("\t Relocations : 0x%x\n"), dosHeader.e_crlc);
	_tprintf(_T("\t Size of header in paragraphs : 0x%x\n"), dosHeader.e_cparhdr);
	_tprintf(_T("\t Minimum extra paragraphs needed : 0x%x\n"), dosHeader.e_minalloc);
	_tprintf(_T("\t Maximum extra paragraphs needed : 0x%x\n"), dosHeader.e_maxalloc);
	_tprintf(_T("\t Initial SS value : 0x%x\n"), dosHeader.e_ss);
	_tprintf(_T("\t Initial SP value : 0x%x\n"), dosHeader.e_sp);
	_tprintf(_T("\t Checksum : 0x%x\n"), dosHeader.e_csum);
	_tprintf(_T("\t Initial IP value : 0x%x\n"), dosHeader.e_ip);
	_tprintf(_T("\t Initial CS value : 0x%x\n"), dosHeader.e_cs);
	_tprintf(_T("\t File address of relocation table : 0x%x\n"), dosHeader.e_lfarlc);
	_tprintf(_T("\t Overlay number : 0x%x\n"), dosHeader.e_ovno);
	_tprintf(_T("\t OEM identifier : 0x%x\n"), dosHeader.e_oemid);
	_tprintf(_T("\t OEM information : 0x%x\n"), dosHeader.e_oeminfo);
	_tprintf(_T("\t File address of new exe header : 0x%x\n"), dosHeader.e_lfanew);
	_tprintf(_T("\n\n\n"));

	CloseHandle(hPeFile);
}

void	ParseNtFileHeader(WCHAR *pwszPeFilePath)
{
	IMAGE_DOS_HEADER		dosHeader;
	IMAGE_FILE_HEADER		fileHeader;
	HANDLE					hPeFile = INVALID_HANDLE_VALUE;
	BOOL					bRet;
	DWORD					dwBytesRead;


	hPeFile = CreateFileW(pwszPeFilePath, 
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hPeFile == NULL)
	{
		_tprintf(_T("failed to CreateFileW %s : %d\n"), pwszPeFilePath, GetLastError());
		return ;
	}

	bRet = ReadFile(hPeFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_DOS_HEADER : %d\n"), GetLastError());
		return ;
	}

	SetFilePointer(hPeFile, dosHeader.e_lfanew+sizeof(IMAGE_NT_SIGNATURE), NULL, FILE_BEGIN);

	bRet = ReadFile(hPeFile, &fileHeader, sizeof(IMAGE_FILE_HEADER), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_FILE_HEADER : %d\n"), GetLastError());
		return ;
	}

	_tprintf(_T("******** NT File Header Information *******\n"));
	_tprintf(_T("\t Machine : 0x%x\n"), fileHeader.Machine);
	_tprintf(_T("\t NumberOfSections : 0x%x\n"), fileHeader.NumberOfSections);
	_tprintf(_T("\t TimeDateStamp : 0x%x\n"), fileHeader.TimeDateStamp);
	_tprintf(_T("\t PointerToSymbolTable : 0x%x\n"), fileHeader.PointerToSymbolTable);
	_tprintf(_T("\t NumberOfSymbols : 0x%x\n"), fileHeader.NumberOfSymbols);
	_tprintf(_T("\t SizeOfOptionalHeader : 0x%x\n"), fileHeader.SizeOfOptionalHeader);
	_tprintf(_T("\t Characteristics : 0x%x\n"), fileHeader.Characteristics);
	_tprintf(_T("\n\n\n"));

	CloseHandle(hPeFile);
}

void	ParseNtOptionalHeader(WCHAR *pwszPeFilePath)
{
	IMAGE_DOS_HEADER		dosHeader;
	IMAGE_OPTIONAL_HEADER32	optionalHeader;
	HANDLE					hPeFile = INVALID_HANDLE_VALUE;
	BOOL					bRet;
	DWORD					dwBytesRead;


	hPeFile = CreateFileW(pwszPeFilePath, 
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hPeFile == NULL)
	{
		_tprintf(_T("failed to CreateFileW %s : %d\n"), pwszPeFilePath, GetLastError());
		return ;
	}

	bRet = ReadFile(hPeFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_DOS_HEADER : %d\n"), GetLastError());
		return ;
	}

	SetFilePointer(hPeFile, dosHeader.e_lfanew+sizeof(IMAGE_NT_SIGNATURE)+sizeof(IMAGE_FILE_HEADER), NULL, FILE_BEGIN);

	bRet = ReadFile(hPeFile, &optionalHeader, sizeof(IMAGE_OPTIONAL_HEADER32), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_FILE_HEADER : %d\n"), GetLastError());
		return ;
	}

	_tprintf(_T("******** NT Optional Header Information *******\n"));
	_tprintf(_T("\t Magic : 0x%x\n"), optionalHeader.Magic);
	_tprintf(_T("\t MajorLinkerVersion : 0x%x\n"), optionalHeader.MajorLinkerVersion);
	_tprintf(_T("\t MinorLinkerVersion : 0x%x\n"), optionalHeader.MinorLinkerVersion);
	_tprintf(_T("\t SizeOfCode : 0x%x\n"), optionalHeader.SizeOfCode);
	_tprintf(_T("\t SizeOfInitializedData : 0x%x\n"), optionalHeader.SizeOfInitializedData);
	_tprintf(_T("\t SizeOfUninitializedData : 0x%x\n"), optionalHeader.SizeOfUninitializedData);
	_tprintf(_T("\t AddressOfEntryPoint : 0x%x\n"), optionalHeader.AddressOfEntryPoint);
	_tprintf(_T("\t BaseOfCode : 0x%x\n"), optionalHeader.BaseOfCode);
	_tprintf(_T("\t BaseOfData :0x%x\n"), optionalHeader.BaseOfData);
	_tprintf(_T("\t ImageBase : 0x%x\n"), optionalHeader.ImageBase);
	_tprintf(_T("\t SectionAlignment : 0x%x\n"), optionalHeader.SectionAlignment);
	_tprintf(_T("\t FileAlignment : 0x%x\n"), optionalHeader.FileAlignment);
	_tprintf(_T("\t MajorOperationSystemVersion : 0x%x\n"), optionalHeader.MajorOperatingSystemVersion);
	_tprintf(_T("\t MinorOperationSystemVersion : 0x%x\n"), optionalHeader.MinorOperatingSystemVersion);
	_tprintf(_T("\t MajorImageVersion : 0x%x\n"), optionalHeader.MajorImageVersion);
	_tprintf(_T("\t MinorImageVersion : 0x%x\n"), optionalHeader.MinorImageVersion);
	_tprintf(_T("\t MajorSubsystemVersion : 0x%x\n"), optionalHeader.MajorSubsystemVersion);
	_tprintf(_T("\t MinorSubsystemVersion : 0x%x\n"), optionalHeader.MinorSubsystemVersion);
	_tprintf(_T("\t Win32VersionValue : 0x%x\n"), optionalHeader.Win32VersionValue);
	_tprintf(_T("\t SizeOfImage : 0x%x\n"), optionalHeader.SizeOfImage);
	_tprintf(_T("\t SizeOfHeaders : 0x%x\n"), optionalHeader.SizeOfHeaders);
	_tprintf(_T("\t CheckSum : 0x%x\n"), optionalHeader.CheckSum);
	_tprintf(_T("\t Subsystem : 0x%x\n"), optionalHeader.Subsystem);
	_tprintf(_T("\t DllCharacteristic : 0x%x\n"), optionalHeader.DllCharacteristics);
	_tprintf(_T("\t SizeOfStackReserve : 0x%x\n"), optionalHeader.SizeOfStackReserve);
	_tprintf(_T("\t SizeOfStackCommit : 0x%x\n"), optionalHeader.SizeOfStackCommit);
	_tprintf(_T("\t SizeOfHeapReserve : 0x%x\n"), optionalHeader.SizeOfHeapReserve);
	_tprintf(_T("\t SizeOfHeapCommit : 0x%x\n"), optionalHeader.SizeOfHeapCommit);
	_tprintf(_T("\t LoaderFlags : 0x%x\n"), optionalHeader.LoaderFlags);
	_tprintf(_T("\t NumberOfRvaAndSizes : 0x%x\n"), optionalHeader.NumberOfRvaAndSizes);
	_tprintf(_T("\n\n\n"));

	CloseHandle(hPeFile);
}

DWORD	GetSectionTableAddress(WCHAR *pwszPeFilePath)
{
	IMAGE_DOS_HEADER		dosHeader;
	IMAGE_FILE_HEADER		fileHeader;
	HANDLE					hPeFile = INVALID_HANDLE_VALUE;
	BOOL					bRet;
	DWORD					dwBytesRead;


	hPeFile = CreateFileW(pwszPeFilePath, 
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hPeFile == NULL)
	{
		_tprintf(_T("failed to CreateFileW %s : %d\n"), pwszPeFilePath, GetLastError());
		return -1;
	}

	bRet = ReadFile(hPeFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_DOS_HEADER : %d\n"), GetLastError());
		return -1;
	}

	SetFilePointer(hPeFile, dosHeader.e_lfanew+sizeof(IMAGE_NT_SIGNATURE), NULL, FILE_BEGIN);

	bRet = ReadFile(hPeFile, &fileHeader, sizeof(fileHeader), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_FILE_HEADER : %d\n"), GetLastError());
		return -1;
	}

	CloseHandle(hPeFile);

	return dosHeader.e_lfanew+sizeof(IMAGE_NT_SIGNATURE)+IMAGE_SIZEOF_FILE_HEADER+fileHeader.SizeOfOptionalHeader;
}

void	ParseSectionTable(WCHAR *pwszPeFilePath)
{
	HANDLE					hPeFile = INVALID_HANDLE_VALUE;
	DWORD					dwBytesRead;
	BOOL					bRet;
	IMAGE_DOS_HEADER		dosHeader;
	IMAGE_FILE_HEADER		fileHeader;
	IMAGE_SECTION_HEADER	sectionHeader;
	ULONG					ulIndex;

	hPeFile = CreateFileW(pwszPeFilePath, 
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hPeFile == NULL)
	{
		_tprintf(_T("failed to CreateFileW %s : %d\n"), pwszPeFilePath, GetLastError());
		return ;
	}

	bRet = ReadFile(hPeFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_DOS_HEADER : %d\n"), GetLastError());
		return ;
	}

	SetFilePointer(hPeFile, dosHeader.e_lfanew+sizeof(IMAGE_NT_SIGNATURE), NULL, FILE_BEGIN);

	bRet = ReadFile(hPeFile, &fileHeader, sizeof(fileHeader), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_FILE_HEADER : %d\n"), GetLastError());
		return ;
	}

	SetFilePointer(hPeFile, 
				   dosHeader.e_lfanew+sizeof(IMAGE_NT_SIGNATURE)+IMAGE_SIZEOF_FILE_HEADER+fileHeader.SizeOfOptionalHeader, 
				   NULL, 
				   FILE_BEGIN);

	_tprintf(_T("******** Section Table Information *******\n"));
	
	for (ulIndex = 0; ulIndex<fileHeader.NumberOfSections; ulIndex++)
	{
		bRet = ReadFile(hPeFile, &sectionHeader, IMAGE_SIZEOF_SECTION_HEADER, &dwBytesRead, NULL);
		printf("SectionName : %s\n", sectionHeader.Name);
		_tprintf(_T("PhysicalAddress : 0x%x\n"), sectionHeader.Misc);
		_tprintf(_T("VirtualAddress : 0x%x\n"), sectionHeader.VirtualAddress);
		_tprintf(_T("SizeOfRawData : 0x%x\n"), sectionHeader.SizeOfRawData);
		_tprintf(_T("PonterToRawData : 0x%x\n"), sectionHeader.PointerToRawData);
		_tprintf(_T("PointerToRelocations : 0x%x\n"), sectionHeader.PointerToRelocations);
		_tprintf(_T("PointerToLinenumbers : 0x%x\n"), sectionHeader.PointerToLinenumbers);
		_tprintf(_T("NumberOfRelocations : 0x%x\n"), sectionHeader.NumberOfRelocations);
		_tprintf(_T("NumberOfLinenumbers : 0x%x\n"), sectionHeader.NumberOfLinenumbers);
		_tprintf(_T("Characteristics : 0x%x\n\n"), sectionHeader.Characteristics);
	}
	
}

void	ParseDataDirectory(WCHAR *pwszPeFilePath)
{
	HANDLE					hPeFile = INVALID_HANDLE_VALUE;
	DWORD					dwBytesRead;
	BOOL					bRet;
	IMAGE_DOS_HEADER		dosHeader;
	IMAGE_FILE_HEADER		fileHeader;
	IMAGE_DATA_DIRECTORY	DataDirectoryEntry;
	ULONG					ulIndex;

	hPeFile = CreateFileW(pwszPeFilePath, 
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hPeFile == NULL)
	{
		_tprintf(_T("failed to CreateFileW %s : %d\n"), pwszPeFilePath, GetLastError());
		return ;
	}

	bRet = ReadFile(hPeFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_DOS_HEADER : %d\n"), GetLastError());
		return ;
	}

	SetFilePointer(hPeFile, dosHeader.e_lfanew+sizeof(IMAGE_NT_SIGNATURE), NULL, FILE_BEGIN);

	bRet = ReadFile(hPeFile, &fileHeader, sizeof(fileHeader), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_FILE_HEADER : %d\n"), GetLastError());
		return ;
	}

	SetFilePointer(hPeFile,
		dosHeader.e_lfanew+sizeof(IMAGE_NT_SIGNATURE)+IMAGE_SIZEOF_FILE_HEADER+fileHeader.SizeOfOptionalHeader-sizeof(IMAGE_DATA_DIRECTORY)*IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
		NULL,
		FILE_BEGIN);

	_tprintf(_T("******** Data Directory Information *******\n"));

	for (ulIndex = 0; ulIndex<IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ulIndex++)
	{
		bRet = ReadFile(hPeFile, &DataDirectoryEntry, sizeof(IMAGE_DATA_DIRECTORY), &dwBytesRead, NULL);
		_tprintf(_T("%s:	VirtualAddress = 0x%08x	Size = 0x%08x\n"), DataDirectoryName[ulIndex], DataDirectoryEntry.VirtualAddress, DataDirectoryEntry.Size);
	}
}

DWORD	GetImageImportDescriptorOffset(WCHAR *pwszPeFilePath, DWORD dwImportDescRva, DWORD *pdwIdataRva)
{
	HANDLE					hPeFile = INVALID_HANDLE_VALUE;
	DWORD					dwBytesRead;
	BOOL					bRet;
	IMAGE_DOS_HEADER		dosHeader;
	IMAGE_FILE_HEADER		fileHeader;
	IMAGE_SECTION_HEADER	sectionHeader;
	ULONG					ulIndex;

	hPeFile = CreateFileW(pwszPeFilePath, 
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hPeFile == NULL)
	{
		_tprintf(_T("failed to CreateFileW %s : %d\n"), pwszPeFilePath, GetLastError());
		return ;
	}

	bRet = ReadFile(hPeFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_DOS_HEADER : %d\n"), GetLastError());
		return ;
	}

	SetFilePointer(hPeFile, dosHeader.e_lfanew+sizeof(IMAGE_NT_SIGNATURE), NULL, FILE_BEGIN);

	bRet = ReadFile(hPeFile, &fileHeader, sizeof(fileHeader), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_FILE_HEADER : %d\n"), GetLastError());
		return ;
	}

	SetFilePointer(hPeFile, 
		dosHeader.e_lfanew+sizeof(IMAGE_NT_SIGNATURE)+IMAGE_SIZEOF_FILE_HEADER+fileHeader.SizeOfOptionalHeader, 
		NULL, 
		FILE_BEGIN);

	for (ulIndex = 0; ulIndex<fileHeader.NumberOfSections; ulIndex++)
	{
		bRet = ReadFile(hPeFile, &sectionHeader, IMAGE_SIZEOF_SECTION_HEADER, &dwBytesRead, NULL);
		
		if (dwImportDescRva>=sectionHeader.VirtualAddress && dwImportDescRva<sectionHeader.VirtualAddress+sectionHeader.Misc)
		{
			*pdwIdataRva = sectionHeader.VirtualAddress;
			return dwImportDescRva-sectionHeader.VirtualAddress+sectionHeader.PointerToRawData;
		}
	}

	return 0;
}

void	ListImportFunctions(WCHAR *pwszPeFilePath)
{
	HANDLE					hPeFile = INVALID_HANDLE_VALUE;
	DWORD					dwBytesRead;
	BOOL					bRet;
	IMAGE_DOS_HEADER		dosHeader;
	IMAGE_FILE_HEADER		fileHeader;
	IMAGE_DATA_DIRECTORY	DataDirectoryEntry;
	ULONG					ulIndex;
	DWORD					dwImportDescOffset;
	DWORD					dwIdataRva;
	IMAGE_IMPORT_DESCRIPTOR	ImportDescriptor;

	hPeFile = CreateFileW(pwszPeFilePath, 
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hPeFile == NULL)
	{
		_tprintf(_T("failed to CreateFileW %s : %d\n"), pwszPeFilePath, GetLastError());
		return ;
	}

	bRet = ReadFile(hPeFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_DOS_HEADER : %d\n"), GetLastError());
		return ;
	}

	SetFilePointer(hPeFile, dosHeader.e_lfanew+sizeof(IMAGE_NT_SIGNATURE), NULL, FILE_BEGIN);

	bRet = ReadFile(hPeFile, &fileHeader, sizeof(fileHeader), &dwBytesRead, NULL);

	if (!bRet)
	{
		_tprintf(_T("failed to ReadFile IMAGE_FILE_HEADER : %d\n"), GetLastError());
		return ;
	}

	SetFilePointer(hPeFile,
		dosHeader.e_lfanew+sizeof(IMAGE_NT_SIGNATURE)+IMAGE_SIZEOF_FILE_HEADER+fileHeader.SizeOfOptionalHeader-sizeof(IMAGE_DATA_DIRECTORY)*IMAGE_NUMBEROF_DIRECTORY_ENTRIES+sizeof(IMAGE_DATA_DIRECTORY),
		NULL,
		FILE_BEGIN);

	bRet = ReadFile(hPeFile, &DataDirectoryEntry, sizeof(IMAGE_DATA_DIRECTORY), &dwBytesRead, NULL);

	dwImportDescOffset = GetImageImportDescriptorOffset(pwszPeFilePath, DataDirectoryEntry.VirtualAddress, &dwIdataRva);

	SetFilePointer(hPeFile, dwImportDescOffset, NULL, FILE_BEGIN);

	for (ulIndex = 0; ulIndex<DataDirectoryEntry.Size/sizeof(IMAGE_IMPORT_DESCRIPTOR); ulIndex++)
	{
		ReadFile(hPeFile, &ImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), &dwBytesRead, NULL);
	}
}