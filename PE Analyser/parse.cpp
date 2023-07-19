#include "parse.h"
#include "fort/fort.h"
#include <string>
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

	// printing header info
	this->GetDosHeaderInfo();
	this->GetFileHeaderInfo();
	this->GetOptionalHeaderInfo();
	this->ParsePESections();
	this->ParsePEImports();

}

void Parse::GetDosHeaderInfo()
{
	printf("\n");
	printf(R"(
----------------------------------------------------------------------------------------------------------	
  _____   ____   _____   _    _ ______          _____  ______ _____  
 |  __ \ / __ \ / ____| | |  | |  ____|   /\   |  __ \|  ____|  __ \ 
 | |  | | |  | | (___   | |__| | |__     /  \  | |  | | |__  | |__) |
 | |  | | |  | |\___ \  |  __  |  __|   / /\ \ | |  | |  __| |  _  / 
 | |__| | |__| |____) | | |  | | |____ / ____ \| |__| | |____| | \ \ 
 |_____/ \____/|_____/  |_|  |_|______/_/    \_\_____/|______|_|  \_\
                                                                                                                                       
----------------------------------------------------------------------------------------------------------	
	)");
	printf("\n");

	std::string sReservedWordsStr1 = "";
	std::string sReservedWordsStr2 = "";
	for (short i = 0; i < 10; i++)
	{
		if (i < 4)
		{
			sReservedWordsStr2 += std::to_string(this->pDosHeader->e_res[i]) + ",";
		}
		
		sReservedWordsStr1 +=  std::to_string(this->pDosHeader->e_res2[i]) + ",";
	}

	ft_table_t* table = ft_create_table();
	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);

	ft_write_ln(table, "#", "Offset", "Name", "value");
	ft_printf_ln(table, "%d | %X | %s | %X", 1, (DWORD)this->pDosHeader - (DWORD)this->pFile, "Magic Number", this->pDosHeader->e_magic);
	ft_printf_ln(table, "%d | %X | %s | %X", 2, (DWORD)this->pDosHeader + 2 - (DWORD)this->pFile, "Bytes On Last Page Of File", this->pDosHeader->e_cblp);
	ft_printf_ln(table, "%d | %X | %s | %d", 3, (DWORD)this->pDosHeader + 4 - (DWORD)this->pFile, "Pages In File", this->pDosHeader->e_cp);
	ft_printf_ln(table, "%d | %X | %s | %X", 4, (DWORD)this->pDosHeader + 6 - (DWORD)this->pFile, "Relocations", this->pDosHeader->e_crlc);
	ft_printf_ln(table, "%d | %X | %s | %X", 5, (DWORD)this->pDosHeader + 8 - (DWORD)this->pFile, "Size of header in paragraphs", this->pDosHeader->e_cparhdr);
	ft_printf_ln(table, "%d | %X | %s | %X", 6, (DWORD)this->pDosHeader + 10 - (DWORD)this->pFile, "Min extra paragraphs needed", this->pDosHeader->e_minalloc);
	ft_printf_ln(table, "%d | %X | %s | %X", 7, (DWORD)this->pDosHeader + 12 - (DWORD)this->pFile, "Max extra paragraphs needed", this->pDosHeader->e_maxalloc);
	ft_printf_ln(table, "%d | %X | %s | %X", 8, (DWORD)this->pDosHeader + 14 - (DWORD)this->pFile, "Initial relative ss value", this->pDosHeader->e_ss);
	ft_printf_ln(table, "%d | %X | %s | %X", 9, (DWORD)this->pDosHeader + 16 - (DWORD)this->pFile, "Initial sp value", this->pDosHeader->e_sp);
	ft_printf_ln(table, "%d | %X | %s | %X", 10, (DWORD)this->pDosHeader + 18 - (DWORD)this->pFile, "Checksum", this->pDosHeader->e_csum);
	ft_printf_ln(table, "%d | %X | %s | %X", 11, (DWORD)this->pDosHeader + 20 - (DWORD)this->pFile, "Initial IP value", this->pDosHeader->e_ip);
	ft_printf_ln(table, "%d | %X | %s | %X", 12, (DWORD)this->pDosHeader + 22 - (DWORD)this->pFile, "Initial relative CS value", this->pDosHeader->e_cs);
	ft_printf_ln(table, "%d | %X | %s | %X", 13, (DWORD)this->pDosHeader + 24 - (DWORD)this->pFile, "File address of relocation table", this->pDosHeader->e_lfarlc);
	ft_printf_ln(table, "%d | %X | %s | %X", 14, (DWORD)this->pDosHeader + 26 - (DWORD)this->pFile, "Overlay number", this->pDosHeader->e_ovno);
	ft_printf_ln(table, "%d | %X | %s | %s", 15, (DWORD)this->pDosHeader + 28 - (DWORD)this->pFile, "Reserved words", sReservedWordsStr2.c_str());
	ft_printf_ln(table, "%d | %X | %s | %X", 16, (DWORD)this->pDosHeader + 36 - (DWORD)this->pFile, "OEM identifier (for e_oeminfo)", this->pDosHeader->e_oemid);
	ft_printf_ln(table, "%d | %X | %s | %X", 17, (DWORD)this->pDosHeader + 38 - (DWORD)this->pFile, "OEM information", this->pDosHeader->e_oeminfo);
	ft_printf_ln(table, "%d | %X | %s | %s", 18, (DWORD)this->pDosHeader + 40 - (DWORD)this->pFile, "Reserved words", sReservedWordsStr1.c_str());
	ft_printf_ln(table, "%d | %X | %s | %X", 19, (DWORD)this->pDosHeader + 60 - (DWORD)this->pFile, "File address of new exe header", this->pDosHeader->e_lfanew);


	printf("%s\n", ft_to_string(table));
	ft_destroy_table(table);
}

void Parse::GetFileHeaderInfo()
{
	printf("\n");
	printf(R"(
----------------------------------------------------------------------------------------------------------	
 ______ _ _        _    _                _           
 |  ____(_) |      | |  | |              | |          
 | |__   _| | ___  | |__| | ___  __ _  __| | ___ _ __ 
 |  __| | | |/ _ \ |  __  |/ _ \/ _` |/ _` |/ _ \ '__|
 | |    | | |  __/ | |  | |  __/ (_| | (_| |  __/ |   
 |_|    |_|_|\___| |_|  |_|\___|\__,_|\__,_|\___|_|   
                                                                           
----------------------------------------------------------------------------------------------------------	
	)");
	printf("\n");
	printf("[+] NT Header Signature: %X\n", this->pNtHeader->Signature);
	ft_table_t* table = ft_create_table();	
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
	ft_printf_ln(table, "%d | %X | %s | %X (%d Bit)", 1, (DWORD)this->pFileHeader - (DWORD)this->pFile, "Machine Number", this->pFileHeader->Machine, iArchType);
	ft_printf_ln(table, "%d | %X | %s | %d", 2, (DWORD)this->pFileHeader + 2 - (DWORD)this->pFile, "No Of Sections", this->pFileHeader->NumberOfSections);
	ft_printf_ln(table, "%d | %X | %s | %s", 3, (DWORD)this->pFileHeader + 4 - (DWORD)this->pFile, "Time Date Stamp", ctime(&time));
	ft_printf_ln(table, "%d | %X | %s | %X", 4, (DWORD)this->pFileHeader + 8 - (DWORD)this->pFile, "Pointer To Symbols Table", this->pFileHeader->PointerToSymbolTable);
	ft_printf_ln(table, "%d | %X | %s | %d", 5, (DWORD)this->pFileHeader + 12 - (DWORD)this->pFile, "Number Of Symbols", this->pFileHeader->NumberOfSymbols);
	ft_printf_ln(table, "%d | %X | %s | %X", 6, (DWORD)this->pFileHeader + 16 - (DWORD)this->pFile, "Size Of Optional Header", this->pFileHeader->SizeOfOptionalHeader);
	ft_printf_ln(table, "%d | %X | %s | %X \n%s", 7, (DWORD)this->pFileHeader + 18 - (DWORD)this->pFile, "Characteristics", this->pFileHeader->Characteristics, sBitsSetString.c_str());

	printf("%s\n", ft_to_string(table));
	ft_destroy_table(table);
}

// TODO UPDATE PARAMS FOR PE32+ AS TYPES ARE DIFFERENT
void Parse::GetOptionalHeaderInfo()
{
	printf("\n");
	printf(R"(
----------------------------------------------------------------------------------------------------------	
   ____        _   _                   _   _    _                _           
  / __ \      | | (_)                 | | | |  | |              | |          
 | |  | |_ __ | |_ _  ___  _ __   __ _| | | |__| | ___  __ _  __| | ___ _ __ 
 | |  | | '_ \| __| |/ _ \| '_ \ / _` | | |  __  |/ _ \/ _` |/ _` |/ _ \ '__|
 | |__| | |_) | |_| | (_) | | | | (_| | | | |  | |  __/ (_| | (_| |  __/ |   
  \____/| .__/ \__|_|\___/|_| |_|\__,_|_| |_|  |_|\___|\__,_|\__,_|\___|_|   
        | |                                                                  
        |_|    
                                                                           
----------------------------------------------------------------------------------------------------------	
	)");
	printf("\n");

	ft_table_t* table = ft_create_table();
	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);

	ft_write_ln(table, "#", "Offset", "Name", "value");
	ft_printf_ln(table, "%d | %X | %s | %X", 1, (DWORD)this->pOptionalHeader - (DWORD)this->pFile, "Magic", this->pOptionalHeader->Magic);
	ft_printf_ln(table, "%d | %X | %s | %X", 2, (DWORD)this->pOptionalHeader + 2 - (DWORD)this->pFile, "Major Linker Version", this->pOptionalHeader->MajorLinkerVersion);
	ft_printf_ln(table, "%d | %X | %s | %X", 3, (DWORD)this->pOptionalHeader + 3 - (DWORD)this->pFile, "Minor Linker Version", this->pOptionalHeader->MinorLinkerVersion);
	ft_printf_ln(table, "%d | %X | %s | %X", 4, (DWORD)this->pOptionalHeader + 4 - (DWORD)this->pFile, "Size Of CodeS", this->pOptionalHeader->SizeOfCode);
	ft_printf_ln(table, "%d | %X | %s | %X", 5, (DWORD)this->pOptionalHeader + 8 - (DWORD)this->pFile, "Size Of Initialised Data", this->pOptionalHeader->SizeOfInitializedData);
	ft_printf_ln(table, "%d | %X | %s | %X", 6, (DWORD)this->pOptionalHeader + 12 - (DWORD)this->pFile, "Size Of Uninitialised Data", this->pOptionalHeader->SizeOfUninitializedData);
	ft_printf_ln(table, "%d | %X | %s | %X", 7, (DWORD)this->pOptionalHeader + 16 - (DWORD)this->pFile, "Address Of Entry Point", this->pOptionalHeader->AddressOfEntryPoint);
	ft_printf_ln(table, "%d | %X | %s | %X", 8, (DWORD)this->pOptionalHeader + 20 - (DWORD)this->pFile, "Base Of Code", this->pOptionalHeader->BaseOfCode);
	ft_printf_ln(table, "%d | %X | %s | %X", 9, (DWORD)this->pOptionalHeader + 24 - (DWORD)this->pFile, "Image Base", this->pOptionalHeader->ImageBase);
	ft_printf_ln(table, "%d | %X | %s | %X", 10, (DWORD)this->pOptionalHeader + 28 - (DWORD)this->pFile, "Section Alignment", this->pOptionalHeader->SectionAlignment);


	printf("%s\n", ft_to_string(table));
	ft_destroy_table(table);
}

// TODO FIX INCORRECT SECTIONS??? 
// TODO GET ADDRESS OF IMPORT TABLE FROM IDATA SECTION 
void Parse::ParsePESections()
{	
	printf("\n");
	printf(R"(
----------------------------------------------------------------------------------------------------------	
   _____           _   _                 
  / ____|         | | (_)                
 | (___   ___  ___| |_ _  ___  _ __  ___ 
  \___ \ / _ \/ __| __| |/ _ \| '_ \/ __|
  ____) |  __/ (__| |_| | (_) | | | \__ \
 |_____/ \___|\___|\__|_|\___/|_| |_|___/
                                                                           
----------------------------------------------------------------------------------------------------------	
	)");
	printf("\n");

	// section headers located directly after nt header struct
	IMAGE_SECTION_HEADER* pSectionHeader = (IMAGE_SECTION_HEADER*)(this->pNtHeader + 1);
	for (int i = 0; i < this->pNtHeader->FileHeader.NumberOfSections; i++)
	{				
		// KEEP FOR X64 CHECKING CANT FIGURE THIS OUT YET
		/*PVOID pOffsetOfHeader = (PVOID)(pFile + this->pDosHeader->e_lfanew + sizeof(this->pNtHeader) + (i * sizeof(IMAGE_SECTION_HEADER)));
		PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)pOffsetOfHeader;*/
		
		printf("\nName: %s\n", pSectionHeader[i].Name);

		ft_table_t* table = ft_create_table();
		ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);

		ft_write_ln(table, "#", "Name", "value");
		ft_printf_ln(table, "%d | %s | %X", 1, "Virtual Size", pSectionHeader[i].Misc.VirtualSize);
		ft_printf_ln(table, "%d | %s | %X", 3, "Virtual Address", pSectionHeader[i].VirtualAddress);
		ft_printf_ln(table, "%d | %s | %X", 4, "Size Of Raw Data", pSectionHeader[i].SizeOfRawData);
		ft_printf_ln(table, "%d | %s | %X", 5, "Ptr To Raw Data", pSectionHeader[i].PointerToRawData);
		ft_printf_ln(table, "%d | %s | %X", 6, "Ptr To Relocations", pSectionHeader[i].PointerToRelocations);
		ft_printf_ln(table, "%d | %s | %X", 7, "Ptr to Line Numbers", pSectionHeader[i].PointerToLinenumbers);
		ft_printf_ln(table, "%d | %s | %X", 8, "Number Of  Relocations", pSectionHeader[i].NumberOfRelocations);
		ft_printf_ln(table, "%d | %s | %X", 9, "Number Of Line Numbers", pSectionHeader[i].NumberOfLinenumbers);
		ft_printf_ln(table, "%d | %s | %X", 11, "Characteristics", pSectionHeader[i].Characteristics);

		BYTE name[8] = ".idata";
		if (!memcmp(&name, &pSectionHeader[i].Name, sizeof(name)))
		{
			printf("Found Import Directory\n");
			this->pImportDirectoryTable = (IMAGE_IMPORT_DESCRIPTOR*)(this->pFile + pSectionHeader[i].VirtualAddress);
		}

		printf("%s\n", ft_to_string(table));
		ft_destroy_table(table);

	}
}

void Parse::ParsePEImports()
{
	printf("Address of import dir %X\n", this->pImportDirectoryTable);
	//this->pImportDirectoryTable = (IMAGE_IMPORT_DESCRIPTOR*)(this->pFile + this->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	printf("Base addr: %X, \nAddress of import dir %X",this->pFile, this->pImportDirectoryTable);

	int i = 0;

	//IMAGE_THUNK_DATA* pIltPtr = (IMAGE_THUNK_DATA*)(this->pFile + this->pImportDirectoryTable->OriginalFirstThunk);
	//IMAGE_THUNK_DATA* pIatPtr = (IMAGE_THUNK_DATA*)(this->pFile + this->pImportDirectoryTable->FirstThunk);

	while (this->pImportDirectoryTable[0].Characteristics)
	{

	}
}
