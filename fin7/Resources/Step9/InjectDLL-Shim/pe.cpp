#include "pe.h"
#include "windows.h"

#define IMAGE_SIZEOF_BASE_RELOCATION 8

// Memory mapping helper functions

namespace PE
{

	HMODULE GetImageBase(void* funcAddr)
	{
		SIZE_T addr = (funcAddr) ? (SIZE_T)funcAddr : (SIZE_T)&GetImageBase;
		addr &= ~0xffff;
		for (;;)
		{
			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)addr;
			if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
			{

				if (dosHeader->e_lfanew < 0x1000)
				{
					PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS) & ((byte*)addr)[dosHeader->e_lfanew];
					if (header->Signature == IMAGE_NT_SIGNATURE)
						break;
				}
			}
			addr -= 0x10000;
		}
		return (HMODULE)addr;
	}

	HMODULE GetImageBaseProcess()
	{
		return GetModuleHandleA(0);
	}

	DWORD SizeOfImage(HMODULE imageBase)
	{
		return GetOptionalHeader(imageBase)->SizeOfImage;
	}

	void ProcessRelocs(PIMAGE_BASE_RELOCATION reloc, SIZE_T imageBase, SIZE_T delta, DWORD relocSize)
	{
		if (relocSize <= 0) return;
		while (reloc->SizeOfBlock > 0)
		{
			SIZE_T va = imageBase + reloc->VirtualAddress;
			ushort* relInfo = (ushort*)((byte*)reloc + IMAGE_SIZEOF_BASE_RELOCATION);

			for (DWORD i = 0; i < (reloc->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2; i++, relInfo++)
			{
				int type = *relInfo >> 12;
				int offset = *relInfo & 0xfff;

				switch (type)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_HIGHLOW:
				case IMAGE_REL_BASED_DIR64:
					*((SIZE_T*)(va + offset)) += delta;
					break;
				}
			}
			reloc = (PIMAGE_BASE_RELOCATION)(((SIZE_T)reloc) + reloc->SizeOfBlock);
		}
	}

	bool ConvertExeToDll(void* module)
	{
		PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((PUCHAR)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
		headers->FileHeader.Characteristics |= IMAGE_FILE_DLL;
		return true;
	}

	bool IsValid(const void* module)
	{
		if (module == 0) return false;
		char* p = (char*)module;
		if (p[0] == 'M' && p[1] == 'Z')
			return true;
		return false;
	}

}
