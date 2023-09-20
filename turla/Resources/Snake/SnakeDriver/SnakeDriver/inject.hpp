#pragma once
#include <ntdef.h>
#include "common.hpp"

class InjectionLock : public common::QueuedSpinLock {
public:
	UINT64 pid{};
};

using load_library_t = HANDLE(*)(LPCWSTR lpLibFileName);

struct UserApcArgs {
	load_library_t load_library;
	wchar_t        dll_path[256];
};

struct InjectDllArgs {
	size_t  pid;
	wchar_t dll_path[256];
};

NTSTATUS inject_dll(const InjectDllArgs& args, bool force = false);
