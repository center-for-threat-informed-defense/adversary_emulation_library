/*
*	Module Name:
*		infinityhook.h
*
*	Abstract:
*		The interface to the infinity hook library.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/

#pragma once

///
/// Structures and typedefs.
///

typedef void (__fastcall* INFINITYHOOKCALLBACK)(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction);

///
/// Forward declarations.
///

#ifdef __cplusplus
extern "C" {  // only need to export C interface if
			  // used by C++ source code
#endif
	NTSTATUS IfhInitialize(
		_In_ INFINITYHOOKCALLBACK InfinityHookCallback);

	void IfhRelease();

#ifdef __cplusplus
}
#endif