/*
 * Handle core implant logic
 */

#ifndef SNAKE_USERLAND_CORE_H_
#define SNAKE_USERLAND_CORE_H_

#include <windows.h>
#include <synchapi.h>
#include "comms_http.h"
#include "instruction.h"
#include "logging.h"
#include "usermodule_errors.h"
#include "api_wrappers.h"
#include <vector>

#define COMMS_MODE 1
#define EXECUTION_MODE 2

namespace module_core {

extern std::wstring module_implant_id;
extern LPCSTR kImplantIdBase;

// Core function for the DllMain thread to run
// https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms686736(v=vs.85)
DWORD WINAPI CoreLoop(LPVOID lpParameter);

// Determine if running in comms vs execution mode. Also set user agent string.
DWORD GetModuleModeAndSetUserAgent(ApiWrapperInterface* api_wrapper, DWORD* module_mode);

// Set implant ID
void SetImplantId(ApiWrapperInterface* api_wrapper);

void SavePayloadFromPipeMsg(ApiWrapperInterface* api_wrapper, std::vector<char> msg_data);

} // namespace module_core

#endif
