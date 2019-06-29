#pragma once
#include "memory.h"

bool read_virtual_memory(HANDLE driver, uintptr_t pml4, uintptr_t address, LPVOID output, unsigned long size);
bool write_virtual_memory(HANDLE driver, uintptr_t pml4, uintptr_t address, LPVOID data, unsigned long size);
uintptr_t convert_virtual_address(HANDLE driver, uintptr_t directory_table_base, uintptr_t virtual_address);

template<typename T>
T read_virtual_memory(HANDLE driver, uintptr_t pml4, UINT_PTR address)
{
	T buffer;

	if (!read_virtual_memory(driver, pml4, address, &buffer, sizeof(T)))
		return NULL;

	return buffer;
}

template<typename T>
bool write_virtual_memory(HANDLE driver, uintptr_t pml4, uintptr_t address, T* buffer)
{
	return write_virtual_memory(driver, pml4, address, buffer, sizeof(T));
}
