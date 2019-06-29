#pragma once

uintptr_t map_physical(HANDLE driver, uintptr_t physical_address, unsigned long size);
uintptr_t unmap_physical(HANDLE driver, uintptr_t address);
uintptr_t find_directory_base(HANDLE driver);
bool read_physical_memory(HANDLE driver, uintptr_t physical_address, void* out, unsigned long size);
bool write_physical_memory(HANDLE driver, uintptr_t physical_address, void* data, unsigned long size);