#pragma once
#include <ntifs.h>

class ProcessReference {
public:
	ProcessReference(ProcessReference const&) = delete;
	ProcessReference& operator =(ProcessReference const&) = delete;
	ProcessReference(ProcessReference&&) = delete;
	ProcessReference& operator=(ProcessReference&&) = delete;

	ProcessReference();
	~ProcessReference();

	NTSTATUS init(size_t pid, bool attach);

private:
	PEPROCESS m_process;
	bool m_attach{};
	KAPC_STATE* m_apc_state{};
};