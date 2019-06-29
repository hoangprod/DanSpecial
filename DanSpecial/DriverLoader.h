#pragma once
#include "NtDefines.h"
#include "GigaBYTEs.h"
#pragma comment(lib, "Shlwapi.lib")

#define STATUS_SUCCESS 0
#define NtCurrentProcess() ( HANDLE(-1) )
#define SeLoadDriverPrivilege 10ull
#define SystemModuleInformation 0xBull
#define AdjustCurrentProcess 0ull

static NTSTATUS Dl_RemoveDriverFromRegistry(const wchar_t* DriverName)
{
	NTSTATUS Status = STATUS_SUCCESS;

	std::wstring RegistryPath = std::wstring(L"System\\CurrentControlSet\\Services\\") + DriverName;

	Status = RegDeleteKeyW(HKEY_LOCAL_MACHINE,
		RegistryPath.c_str());
	if (!Status || Status == ERROR_FILE_NOT_FOUND)
		return STATUS_SUCCESS;

	Status = SHDeleteKeyW(HKEY_LOCAL_MACHINE,
		RegistryPath.c_str());
	if (!Status || Status == ERROR_FILE_NOT_FOUND)
		return STATUS_SUCCESS;

	Status = RegDeleteKeyW(HKEY_LOCAL_MACHINE,
		RegistryPath.c_str());
	if (!Status || Status == ERROR_FILE_NOT_FOUND)
		return STATUS_SUCCESS;

	return Status;
}

static NTSTATUS Dl_TryOpenServiceKey(const wchar_t* DriverName)
{
	std::wstring RegistryPath = std::wstring(L"System\\CurrentControlSet\\Services\\") + DriverName;
	HKEY Key;
	NTSTATUS Result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
		RegistryPath.c_str(),
		0,
		KEY_ALL_ACCESS,
		&Key);
	RegCloseKey(Key);
	return Result;
}

static NTSTATUS Dl_AddServiceToRegistery(const wchar_t* DriverName)
{
	NTSTATUS Status = STATUS_SUCCESS;

	std::wstring RegistryPath = std::wstring(L"System\\CurrentControlSet\\Services\\") + DriverName;

	Dl_RemoveDriverFromRegistry(DriverName);

	HKEY Key;
	Status = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
		RegistryPath.c_str(),
		0,
		NULL,
		0,
		KEY_ALL_ACCESS,
		NULL,
		&Key,
		0);

	if (Status)
		return Status;

	const auto RegWriteString = [=](const wchar_t* Name, const std::wstring& Data) -> NTSTATUS
	{
		return RegSetValueExW(Key,
			Name,
			0,
			REG_EXPAND_SZ,
			(PBYTE)Data.c_str(),
			Data.size() * sizeof(wchar_t));
	};
	const auto RegWriteDWORD = [=](const wchar_t* Name, DWORD Data) -> NTSTATUS
	{
		return RegSetValueExW(Key,
			Name,
			0,
			REG_DWORD,
			(PBYTE)&Data,
			sizeof(DWORD));
	};

	Status |= RegWriteString(L"ImagePath", std::wstring(L"\\SystemRoot\\System32\\drivers\\") + DriverName + L".sys");
	Status |= RegWriteDWORD(L"Type", 1);
	Status |= RegWriteDWORD(L"ErrorControl", 1);
	Status |= RegWriteDWORD(L"Start", 3);

	if (Status)
	{
		RegCloseKey(Key);
		Dl_RemoveDriverFromRegistry(DriverName);
		return Status;
	}


	RegCloseKey(Key);
	return STATUS_SUCCESS;
}

static std::wstring Cl_GetDriverPath()
{
	wchar_t SystemDirectory[2048];
	GetSystemDirectoryW(SystemDirectory, 2048);

	std::wstring DriverPath = SystemDirectory;
	DriverPath += L"\\drivers\\";

	return DriverPath;
}

static NTSTATUS Dl_UnloadDriver(const wchar_t* DriverName)
{
	if (!AcquirePrivilege(SeLoadDriverPrivilege, AdjustCurrentProcess))
		return 1;

	if (Dl_TryOpenServiceKey(DriverName) == 2)
		Dl_AddServiceToRegistery(DriverName);
	std::wstring SourceRegistry = std::wstring(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + DriverName;

	UNICODE_STRING SourceRegistryUnicode = { 0 };
	SourceRegistryUnicode.Buffer = (wchar_t*)SourceRegistry.c_str();
	SourceRegistryUnicode.Length = (SourceRegistry.size()) * 2;
	SourceRegistryUnicode.MaximumLength = (SourceRegistry.size() + 1) * 2;

	NTSTATUS Status = NtUnloadDriver(&SourceRegistryUnicode);

	printf("[+] NtUnloadDriver(%ls) returned %08x\n", SourceRegistry.c_str(), Status);

	Dl_RemoveDriverFromRegistry(DriverName);

	return Status;
}


static NTSTATUS Dl_LoadDriver(const wchar_t* DriverName)
{
	if (!AcquirePrivilege(SeLoadDriverPrivilege, AdjustCurrentProcess))
		return 1;

	if (Dl_AddServiceToRegistery(DriverName))
		return 2;

	std::wstring SourceRegistry = std::wstring(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + DriverName;

	UNICODE_STRING SourceRegistryUnicode = { 0 };
	SourceRegistryUnicode.Buffer = (wchar_t*)SourceRegistry.c_str();
	SourceRegistryUnicode.Length = (SourceRegistry.size()) * 2;
	SourceRegistryUnicode.MaximumLength = (SourceRegistry.size() + 1) * 2;

	NTSTATUS Status = NtLoadDriver(&SourceRegistryUnicode);

	printf("[+] NtLoadDriver(%ls) returned %08x\n", SourceRegistry.c_str(), Status);

	// Driver already loaded i think
	if (Status && Status != 0xc000010e)
	{
		Dl_UnloadDriver(DriverName);
		Dl_RemoveDriverFromRegistry(DriverName);
		Dl_LoadDriver(DriverName);
	}
	else if (Status == 0 || Status == 0xc000010e)
	{
		Status = 0;
	}

	return Status;
}

bool fileExists(std::wstring fileName)
{
	std::ifstream infile(fileName);
	return infile.good();
}

static BOOL LoadDriver()
{
	std::wstring GigabyteDriverName = L"gpcidrv64";
	std::wstring DriverPath = Cl_GetDriverPath() + GigabyteDriverName + L".sys";


	// Terrible idea, does not actually check if file exist, only if we have permission.
	if (!fileExists(DriverPath))
	{
		std::ofstream file(DriverPath, std::ios::binary);

		if (!file.good())
		{
			return false;
		}

		file.write((char*)rawData, sizeof(rawData));
		file.close();
	}

	// No permission or write driver to system folder gone wrong
	if (Dl_LoadDriver(GigabyteDriverName.c_str()))
	{
		printf("[+] Failed to load driver!\n");
		return false;
	}

	return true;

}

static HANDLE Dl_OpenDevice(std::string DriverName)
{
	char CompleteDeviceName[128];
	sprintf_s(CompleteDeviceName, "\\\\.\\%s", DriverName.data());

	HANDLE DeviceHandle = CreateFileA
	(
		CompleteDeviceName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (DeviceHandle == INVALID_HANDLE_VALUE)
		DeviceHandle = 0;

	printf("[+] CreateFileA(%s) returned %08x\n", CompleteDeviceName, DeviceHandle);

	return DeviceHandle;
}