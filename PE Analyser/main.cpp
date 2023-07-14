#include <Windows.h>
#include <iostream>
#include <fstream>
#include "parse.h"

int main()
{
	printf(R"(
 _____  ______                        _                     
 |  __ \|  ____|     /\               | |                    
 | |__) | |__       /  \   _ __   __ _| |_   _ ___  ___ _ __ 
 |  ___/|  __|     / /\ \ | '_ \ / _` | | | | / __|/ _ \ '__|
 | |    | |____   / ____ \| | | | (_| | | |_| \__ \  __/ |   
 |_|    |______| /_/    \_\_| |_|\__,_|_|\__, |___/\___|_|   
                                          __/ |              
                                         |___/   
------------------------------------------------------------------------------	
	)");

	const char* dllPath = "";

	PBYTE pFile;
	PBYTE pBaseAddress;



	Parse parse;
	parse.filePath = "";

	parse.GetFileInfo();

	return 0;
}