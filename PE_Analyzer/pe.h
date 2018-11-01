#ifndef _PE_H_
#define _PE_H_

#define		RVA_2_DISKOFFSET(rva, va_base, disk_base)		(rva-va_base+disk_base)

BOOL		IsValidPeFile(WCHAR	*pwszPeFilePath);

void		ParseDosHeader(WCHAR *pwszPeFilePath);

void		ParseNtFileHeader(WCHAR *pwszPeFilePath);

void		ParseNtOptionalHeader(WCHAR *pwszPeFilePath);

DWORD		GetSectionTableAddress(WCHAR *pwszPeFilePath);

void		ParseSectionTable(WCHAR *pwszPeFilePath);

void		ParseDataDirectory(WCHAR *pwszPeFilePath);

DWORD		GetImageImportDescriptorOffset(WCHAR *pwszPeFilePath, DWORD dwImportDescRva);

void		ListImportFunctions(WCHAR *pwszPeFilePath);


#endif
