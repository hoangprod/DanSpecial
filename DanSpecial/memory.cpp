#include "pch.h"
#include "memory.h"

#pragma pack ( push, 1 )
typedef struct _GIOMAP
{
	unsigned long	interface_type;
	unsigned long	bus;
	uintptr_t		physical_address;
	unsigned long	io_space;
	unsigned long	size;
} GIOMAP;
#pragma pack ( pop )


uintptr_t map_physical(HANDLE driver, uintptr_t physical_address, unsigned long size)
{
	GIOMAP in_buffer = { 0, 0, physical_address, 0, size };
	uintptr_t out_buffer[2] = { 0 };

	unsigned long returned = 0;

	DeviceIoControl(driver, 0xC3502004, reinterpret_cast<LPVOID>(&in_buffer), sizeof(in_buffer),
		reinterpret_cast<LPVOID>(out_buffer), sizeof(out_buffer), &returned, NULL);

	return out_buffer[0];
}

uintptr_t unmap_physical(HANDLE driver, uintptr_t address)
{
	uintptr_t in_buffer = address;
	uintptr_t out_buffer[2] = { 0 };

	unsigned long returned = 0;

	DeviceIoControl(driver, 0xC3502008, reinterpret_cast<LPVOID>(&in_buffer), sizeof(in_buffer),
		reinterpret_cast<LPVOID>(out_buffer), sizeof(out_buffer), &returned, NULL);

	return out_buffer[0];
}

uintptr_t find_directory_base(HANDLE driver)
{
	for (int i = 0; i < 10; i++)
	{
		uintptr_t lpBuffer = map_physical(driver, i * 0x10000, 0x10000);

		for (int uOffset = 0; uOffset < 0x10000; uOffset += 0x1000)
		{

			if (0x00000001000600E9 ^ (0xffffffffffff00ff & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset)))
				continue;
			if (0xfffff80000000000 ^ (0xfffff80000000000 & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0x70)))
				continue;
			if (0xffffff0000000fff & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0xa0))
				continue;

			return *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0xa0);
		}

		unmap_physical(driver, lpBuffer);
	}

	return NULL;
}

bool read_physical_memory(HANDLE driver, uintptr_t physical_address, void* output, unsigned long size)
{
	uintptr_t virtual_address = map_physical(driver, physical_address, size);

	if (!virtual_address)
		return false;

	memcpy(output, reinterpret_cast<LPCVOID>(virtual_address), size);
	unmap_physical(driver, virtual_address);
	return true;
}

bool write_physical_memory(HANDLE driver, uintptr_t physical_address, void* data, unsigned long size)
{
	if (!data)
		return false;

	uintptr_t virtual_address = map_physical(driver, physical_address, size);

	if (!virtual_address)
		return false;

	memcpy(reinterpret_cast<LPVOID>(virtual_address), reinterpret_cast<LPCVOID>(data), size);
	unmap_physical(driver, virtual_address);
	return true;
}
