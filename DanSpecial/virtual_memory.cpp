#include "pch.h"
#include "virtual_memory.h"

bool read_virtual_memory(HANDLE driver, uintptr_t pml4, uintptr_t address, LPVOID output, unsigned long size)
{
	if (!address)
		return false;

	if (!size)
		return false;

	uintptr_t physical_address = convert_virtual_address(driver, pml4, address);

	if (!physical_address)
		return false;

	read_physical_memory(driver, physical_address, output, size);
	return true;
}

bool write_virtual_memory(HANDLE driver, uintptr_t pml4, uintptr_t address, LPVOID data, unsigned long size)
{
	uintptr_t physical_address = convert_virtual_address(driver, pml4, address);

	if (!physical_address)
		return false;

	write_physical_memory(driver, physical_address, data, size);

	return true;
}

uintptr_t convert_virtual_address(HANDLE driver, uintptr_t directory_table_base, uintptr_t virtual_address)
{
	uintptr_t va = virtual_address;

	unsigned short PML4 = (unsigned short)((va >> 39) & 0x1FF);
	uintptr_t PML4E = 0;
	read_physical_memory(driver, (directory_table_base + PML4 * sizeof(uintptr_t)), &PML4E, sizeof(PML4E));

	unsigned short DirectoryPtr = (unsigned short)((va >> 30) & 0x1FF);
	uintptr_t PDPTE = 0;
	read_physical_memory(driver, ((PML4E & 0xFFFFFFFFFF000) + DirectoryPtr * sizeof(uintptr_t)), &PDPTE, sizeof(PDPTE));

	if ((PDPTE & (1 << 7)) != 0)
		return (PDPTE & 0xFFFFFC0000000) + (va & 0x3FFFFFFF);

	unsigned short Directory = (unsigned short)((va >> 21) & 0x1FF);

	uintptr_t PDE = 0;
	read_physical_memory(driver, ((PDPTE & 0xFFFFFFFFFF000) + Directory * sizeof(uintptr_t)), &PDE, sizeof(PDE));

	if (PDE == 0)
		return 0;

	if ((PDE & (1 << 7)) != 0)
	{
		return (PDE & 0xFFFFFFFE00000) + (va & 0x1FFFFF);
	}

	unsigned short Table = (unsigned short)((va >> 12) & 0x1FF); //<! Page Table Index
	uintptr_t PTE = 0;

	read_physical_memory(driver, ((PDE & 0xFFFFFFFFFF000) + Table * sizeof(uintptr_t)), &PTE, sizeof(PTE));

	if (PTE == 0)
		return 0;

	return (PTE & 0xFFFFFFFFFF000) + (va & 0xFFF);
}
