#pragma once
#include <Windows.h>
#include <fstream>
#include <winnt.h>

class Parse
{
public:

	IMAGE_DOS_HEADER* pDosHeader;
	IMAGE_NT_HEADERS* pNtHeader;
	IMAGE_FILE_HEADER* pFileHeader;
	IMAGE_OPTIONAL_HEADER* pOptionalHeader;

	const char* filePath;	
	PBYTE pFile;

	bool IsFileValid();
	void GetFileInfo();
private:	
	void GetFileHeaderInfo();
	void GetDosHeaderInfo();
	void GetOptionalHeaderInfo();
	void ParsePESections();
	void ParsePEImports();
};

