#include "parse.h"
#include "fort/fort.h"
#pragma warning(disable : 4996)

bool Parse::IsFileValid()
{	
	// checking disk for file
	if (!GetFileAttributesA(this->filePath))
	{
		printf("[-] No file on disk\n");
		return false;
	}
		
	std::ifstream File(this->filePath, std::ios::binary | std::ios::ate);
	auto fileSize = File.tellg();

	// can file be opened 
	if (File.fail())
	{
		printf("[-] Faild to open file: %X\n", (DWORD)File.rdstate());
		File.close();
		return false;
	}

	// creating new byte array equal to size of file (tellg = length of input stream)
	this->pFile = new BYTE[static_cast<UINT_PTR>(fileSize)];
	if (!pFile)
	{
		printf("[-] Can't create byte array\n");
		delete[] pFile;
		File.close();
		return false;
	}

	// get to the start of file
	File.seekg(0, std::ios::beg);
	// read from beginning of file to the end
	File.read(reinterpret_cast<char*>(pFile), fileSize);
	// close open handle 
	File.close();

	return true;
}

void Parse::GetFileInfo()
{
	// checking supplied file
	this->IsFileValid();

	// getting dos header struct
	this->pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pFile);

	// final checks MZ header
	if (this->pDosHeader->e_magic != 0x5A4D)
	{
		printf("[-] Invalid filetype\n");
	}
	
	// getting NT_Header 
	this->pNtHeader = (IMAGE_NT_HEADERS*)(pFile + pDosHeader->e_lfanew);
	// getting file header from nt header
	this->pFileHeader = (IMAGE_FILE_HEADER*)(&pNtHeader->FileHeader);
	// getting optional header from nt header
	this->pOptionalHeader = (IMAGE_OPTIONAL_HEADER*)(&pNtHeader->OptionalHeader);

	this->GetFileHeaderInfo();

}


void Parse::GetFileHeaderInfo()
{
	printf("\n File Header \n");
	ft_table_t* table = ft_create_table();	
	/* Set "header" type for the first row */
	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	
	int iArchType = 32;
	time_t time = this->pFileHeader->TimeDateStamp;

	if (this->pFileHeader->Machine != 0x014c)
		iArchType = 64;

	const char* cCharacteristicsBitArray[] = { 
		"0x0001 Relocation info stripped from file.\n", 
		"0x0002 File is executable.\n",
		"0x0004 Line nunbers stripped from file.\n",
		"0x0008 Local symbols stripped from file.\n",
		"0x0010 Aggressively trim working set\n", 
		"0x0020 App can handle >2gb addresses\n",
		"0x0080 Bytes of machine word are reversed.\n",
		"0x0100 32 bit word machine.\n",
		"0x0200 Debugging info stripped from file in .DBG file\n",
		"0x0400 If Image is on removable media, copy and run from the swap file.\n",
		"0x0800 If Image is on Net, copy and run from the swap file.\n",
		"0x1000 System File.\n",
		"0x2000 File is a DLL.\n",
		"0x4000 File should only be run on a UP machine\n",
		"0x8000 Bytes of machine word are reversed.\n"};

	std::string sBitsSetString = "";
	// checking characteristics via bitwise
	// checking which bits are set 0-15
	for (int i = 0; i < 16; i++)
	{
		bool set = false;
		// if bit is set add to string
		if (this->pFileHeader->Characteristics & (1 << i))
		{
			sBitsSetString += cCharacteristicsBitArray[i];
		}
	}

	ft_write_ln(table, "#", "Offset", "Name", "value");	
	ft_printf_ln(table, "%d | %s | %s | %x (%d Bit)", 1, "0x0", "Machine Number", this->pFileHeader->Machine, iArchType);
	ft_printf_ln(table, "%d | %s | %s | %d", 2, "0x2", "No Of Sections", this->pFileHeader->NumberOfSections);
	ft_printf_ln(table, "%d | %s | %s | %s", 3, "0x4", "Time Date Stamp", ctime(&time));
	ft_printf_ln(table, "%d | %s | %s | %x", 4, "0x8", "Pointer To Symbols Table", this->pFileHeader->PointerToSymbolTable);
	ft_printf_ln(table, "%d | %s | %s | %d", 5, "0x12", "Number Of Symbols", this->pFileHeader->NumberOfSymbols);
	ft_printf_ln(table, "%d | %s | %s | %x", 6, "0x14", "Size Of Optional Header", this->pFileHeader->SizeOfOptionalHeader);
	ft_printf_ln(table, "%d | %s | %s | %x \n%s", 7, "0x16", "Characteristics", this->pFileHeader->Characteristics, sBitsSetString.c_str());

	printf("%s\n", ft_to_string(table));
	ft_destroy_table(table);
}