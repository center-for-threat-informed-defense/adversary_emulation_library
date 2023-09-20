#include "attach.hpp"

ProcessReference::ProcessReference()
	: m_process(nullptr) {
}

ProcessReference::~ProcessReference() {
	if (nullptr != m_process) {
		ObDereferenceObject(m_process);
		if (m_attach) {
			KeUnstackDetachProcess(m_apc_state);
			ExFreePool(m_apc_state);
		}
	}
}

// This is attaching to the virtual address space of the specified PID.
// Why not put this in the constructor? Maybe because he wants the NTSTATUS back?
NTSTATUS ProcessReference::init(size_t pid, bool attach) {
	auto status = PsLookupProcessByProcessId(
		// PID to handle wtf?
		reinterpret_cast<HANDLE>(pid),
		&m_process
	);
	if (STATUS_SUCCESS != status) {
		return status;
	}

	m_attach = attach;
	if (attach) {
		// Make this a wistd::unique_ptr
		m_apc_state = (KAPC_STATE*)ExAllocatePool(NonPagedPool, sizeof(KAPC_STATE));
		KeStackAttachProcess(m_process, m_apc_state);
	}
	return STATUS_SUCCESS;
}