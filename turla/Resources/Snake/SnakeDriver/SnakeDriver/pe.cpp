#include "pe.hpp"

PVOID find_symbol_address(BYTE* base_address, const char* symbol) {
	auto dos_header = (IMAGE_DOS_HEADER*)base_address;
	auto nt_headers64 = (IMAGE_NT_HEADERS64*)(base_address + dos_header->e_lfanew);
	auto optional_header = (IMAGE_OPTIONAL_HEADER64*)&nt_headers64->OptionalHeader;

	auto export_directory = &optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (0 == export_directory->VirtualAddress) {
		return nullptr;
	}

	auto export_table = (IMAGE_EXPORT_DIRECTORY*)(base_address + export_directory->VirtualAddress);
	for (size_t i = 0; i < export_table->NumberOfNames; i++) {
		auto function_name_offset = *(ULONG*)(base_address + export_table->AddressOfNames + (sizeof(export_table->AddressOfNames) * i));
		auto function_name = (char*)base_address + (size_t)function_name_offset;
		if (0 == strcmp(function_name, symbol)) {
			return base_address + *(ULONG*)(base_address + export_table->AddressOfFunctions + (sizeof(export_table->AddressOfFunctions) * i));
		}
	}
	return nullptr;
}

PVOID get_module_symbol_address(const wchar_t* dll, const char* symbol) {
	// Need to check for 32 bit process.
	PPEB peb = PsGetProcessPeb(PsGetCurrentProcess());
	auto module_entry = (LDR_DATA_TABLE_ENTRY*)((char*)peb->Ldr->InLoadOrderModuleList.Flink);
	do {
		if (nullptr != wcsstr(module_entry->FullDllName.Buffer, dll)) {
			return find_symbol_address((BYTE*)module_entry->DllBase, symbol);
		}
		module_entry = (LDR_DATA_TABLE_ENTRY*)((char*)module_entry->InLoadOrderLinks.Flink);
	} while (module_entry != nullptr);
	return nullptr;
}