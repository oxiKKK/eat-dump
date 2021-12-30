#include <iostream>
#include <Windows.h>

#define ADDR "0x%08X"

bool check_dos_header_magic( uint16_t magic )
{
	if (magic != IMAGE_DOS_SIGNATURE || !magic)
		return false;

	return true;
}

bool check_nt_header_magic( uint16_t magic )
{
	if (magic != IMAGE_NT_SIGNATURE || !magic)
		return false;

	return true;
}

void process_exports( uint8_t* base, PIMAGE_DATA_DIRECTORY edd )
{
	printf( "\nProcessing exports:\n" );

	if (!edd->Size)
	{
		printf( "  No exports\n" );
		return;
	}

	auto image_export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + edd->VirtualAddress);

	printf( "Export dir at " ADDR "\n", image_export_dir );

	const uint32_t number_of_names = image_export_dir->NumberOfNames;
	const uint32_t number_of_functions = image_export_dir->NumberOfFunctions;
	if (!number_of_names || !number_of_functions)
	{
		printf( "  No functions\n" );
		return;
	}

	uint32_t* paddr_functions = reinterpret_cast<uint32_t*>(base + image_export_dir->AddressOfFunctions);
	uint32_t* paddr_names = reinterpret_cast<uint32_t*>(base + image_export_dir->AddressOfNames);
	uint16_t* paddr_ordinals = reinterpret_cast<uint16_t*>(base + image_export_dir->AddressOfNameOrdinals);

	printf( "Functions at: " ADDR "\n", paddr_functions );
	printf( "    Names at: " ADDR "\n", paddr_names );
	printf( " Ordinals at: " ADDR "\n", paddr_ordinals );

	printf("\n");
	printf(" ordinal address    function name\n");
	for (uint32_t i = 0; i < number_of_names; i++)
	{
		const char* name = reinterpret_cast<const char*>(base + paddr_names[i]);
		const uint32_t* paddr = reinterpret_cast<uint32_t*>(base + paddr_functions[paddr_ordinals[i]]);

		printf( "  %6hu " ADDR " %s\n", paddr_ordinals[i], paddr, name );

		if (!strcmp( name, "RtlGetVersion" ))
		{
			printf( "\n" );
			printf( "Found RtlGetVersion at " ADDR, "\n", paddr );
			printf( "\n" );
			printf( "\n" );
			printf( "--- System information ---\n" );

			OSVERSIONINFOA ver{};
			ver.dwOSVersionInfoSize = sizeof( OSVERSIONINFOA );

			(reinterpret_cast<NTSTATUS(__stdcall*)(POSVERSIONINFOA)>(paddr))(&ver);

			printf( "System version:\n  %02d.%02d.%02d.%02d\n", 
					ver.dwMajorVersion, 
					ver.dwMinorVersion, 
					ver.dwBuildNumber, 
					ver.dwPlatformId );

			printf( "\n" );

			break;
		}
	}
}

int main()
{
	const char* pszlibname = "ntdll.dll";
	auto ke32 = LoadLibraryA( pszlibname );

	if (!ke32)
	{
		printf( "Error: Couldn't load %s\n", pszlibname );
		return 1;
	}

	printf( "ke32 at " ADDR "\n", ke32 );

	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(ke32);

	uint16_t wDOSMagic = dos_header->e_magic;
	if (!check_dos_header_magic( wDOSMagic ))
	{
		printf( "Error: Invalid DOS magic %hu\n", wDOSMagic );
		return false;
	}

	const auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>((uint8_t*)ke32 + dos_header->e_lfanew);
	printf( "NT header at " ADDR ".\n", nt_header );

	uint16_t wNTMagic = nt_header->Signature;
	if (!check_nt_header_magic( wNTMagic ))
	{
		printf( "Error: Invalid NT magic %hu\n", wNTMagic );
		return false;
	}

	const auto optional_header = &nt_header->OptionalHeader;

	auto exports_data_dir = &optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	process_exports( (uint8_t*)ke32, exports_data_dir );

	printf( "Success\n" );
	system( "pause" );
	return 0;
}
