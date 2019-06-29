#pragma once
#include "memory.h"
#include "virtual_memory.h"

#pragma comment( lib, "ntdll.lib" )

/*
#define EPROCESS_DIRECTORYTABLE_OFFSET		0x028	// [+0x028] _EPROCESS.DirectoryTableBase
#define EPROCESS_UNIQUEPROCESSID_OFFSET		0x2E0	// [+0x2E0]	_EPROCESS.UniqueProcessId
#define EPROCESS_ACTIVEPROCESSLINK_OFFSET	0x2E8	// [+0x2E8] _EPROCESS.ActiveProcessLinks	
#define EPROCESS_VIRTUALSIZE				0x338	// [+0x338] _EPROCESS.VirtualSize
#define EPROCESS_SECTIONBASE				0x3C0	// [+0x3C0] _EPROCESS.SectionBaseAddress
#define EPROCESS_IMAGEFILENAME				0x450	// [+0x450] _EPROCESS.ImageFileName [15]
#define EPROCESS_PS_PROTECTION				0x6ca	// [+0x6ca] _EPROCESS.Protection
#define EPROCESS_TOKEN						0x358   // [+0x358] _EPROCESS.Token
*/




struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX //
{
	PVOID Object; //
	ULONG UniqueProcessId; //
	ULONG HandleValue; //
	ULONG GrantedAccess; //
	USHORT CreatorBackTraceIndex; //
	USHORT ObjectTypeIndex; //
	ULONG HandleAttributes; //
	ULONG Reserved; //
};

struct SYSTEM_HANDLE_INFORMATION_EX //
{
	ULONG NumberOfHandles; //
	ULONG Reserved; //
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1]; //
};

uintptr_t find_kprocess(HANDLE driver, const char* image_name, uintptr_t& virtual_size, uintptr_t& directory_base);
uintptr_t find_kprocess(HANDLE driver, const char* image_name, DWORD pid, uintptr_t& virtual_size_out, uintptr_t& directory_base_out);
uintptr_t leak_kprocess(HANDLE driver, uintptr_t pml4);
bool leak_kernel_pointers(std::vector<uintptr_t>& pointers);

