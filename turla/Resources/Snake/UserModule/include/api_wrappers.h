/*
 * Provide wrappers for Windows and other API functions
 */

#ifndef SNAKE_USERLAND_WRAPPER_H_
#define SNAKE_USERLAND_WRAPPER_H_

#include <windows.h>
#include <synchapi.h>
#include <WinInet.h>
#include <sddl.h>
#include <aclapi.h>
#include <tlhelp32.h>
#include <filesystem>
#include <vector>
#include <chrono>
#include <thread>
#include "osrng.h"

// Interface for API calls to be wrapped. Will be used in source code and test files.
class ApiWrapperInterface {
public:
    ApiWrapperInterface(){}
    virtual ~ApiWrapperInterface(){}

    // Wrapper for appending data string to file
    virtual void AppendStringWrapper(std::wstring file_path, std::string data) = 0;

    // Wrapper for CloseDesktop function (winuser.h)
    virtual BOOL CloseDesktopWrapper(
        HDESK hDesktop
    ) = 0;

    // Wrapper for CloseHandle (handleapi.h)
    virtual BOOL CloseHandleWrapper(HANDLE hObject) = 0;

    // Wrapper for ConnectNamedPipe (namedpipeapi.h)
    virtual BOOL ConnectNamedPipeWrapper(
        HANDLE       hNamedPipe,
        LPOVERLAPPED lpOverlapped
    ) = 0;

    // Wrapper for ConvertStringSecurityDescriptorToSecurityDescriptor (sddl.h)
    virtual BOOL ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        LPCWSTR              StringSecurityDescriptor,
        DWORD                StringSDRevision,
        PSECURITY_DESCRIPTOR *SecurityDescriptor,
        PULONG               SecurityDescriptorSize
    ) = 0;

    // Wrapper for CreateFile (fileapi.h)
    virtual HANDLE CreateFileWrapper(
        LPCWSTR               lpFileName,
        DWORD                 dwDesiredAccess,
        DWORD                 dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD                 dwCreationDisposition,
        DWORD                 dwFlagsAndAttributes,
        HANDLE                hTemplateFile
    ) = 0;

    // Wrapper for CreateMutex (synchapi.h)
    virtual HANDLE CreateMutexWrapper(
        LPSECURITY_ATTRIBUTES lpMutexAttributes,
        BOOL                  bInitialOwner,
        LPCWSTR               lpName
    ) = 0;

    // Wrapper for CreateNamedPipe (winbase.h)
    virtual HANDLE CreateNamedPipeWrapper(
        LPCWSTR               lpName,
        DWORD                 dwOpenMode,
        DWORD                 dwPipeMode,
        DWORD                 nMaxInstances,
        DWORD                 nOutBufferSize,
        DWORD                 nInBufferSize,
        DWORD                 nDefaultTimeOut,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ) = 0;

    // Wrapper for CreatePipe (namedpipeapi.h)
    virtual BOOL CreatePipeWrapper(
        PHANDLE               hReadPipe,
        PHANDLE               hWritePipe,
        LPSECURITY_ATTRIBUTES lpPipeAttributes,
        DWORD                 nSize
    ) = 0;

    // Wrapper for CreateProcessW (processthreadsapi.h)
    virtual BOOL CreateProcessWrapper(
        LPCWSTR               lpApplicationName,
        LPWSTR                lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCWSTR               lpCurrentDirectory,
        LPSTARTUPINFOW        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    ) = 0;

    // Wrapper for CreateProcessWithTokenW (winbase.h)
    virtual BOOL CreateProcessWithTokenWrapper(
        HANDLE                hToken,
        DWORD                 dwLogonFlags,
        LPCWSTR               lpApplicationName,
        LPWSTR                lpCommandLine,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCWSTR               lpCurrentDirectory,
        LPSTARTUPINFOW        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    ) = 0;

    // Wrapper for CreateThread (processthreadsapi.h)
    virtual HANDLE CreateThreadWrapper(
        LPSECURITY_ATTRIBUTES   lpThreadAttributes,
        SIZE_T                  dwStackSize,
        LPTHREAD_START_ROUTINE  lpStartAddress,
        __drv_aliasesMem LPVOID lpParameter,
         DWORD                   dwCreationFlags,
        LPDWORD                 lpThreadId
    ) = 0;

    // Wrapper for CreateToolhelp32Snapshot (tlhelp32.h)
    virtual HANDLE CreateToolhelp32SnapshotWrapper(
        DWORD dwFlags,
        DWORD th32ProcessID
    ) = 0;

    // Wrapper for getting a string representation of current time
    virtual std::string CurrentUtcTimeWrapper() = 0;

    // Wrapper for DisconnectNamedPipe (namedpipeapi.h)
    virtual BOOL DisconnectNamedPipeWrapper(HANDLE hNamedPipe) = 0;

    // Wrapper for DuplicateTokenEx (securitybaseapi.h)
    virtual BOOL DuplicateTokenExWrapper(
        HANDLE                       hExistingToken,
        DWORD                        dwDesiredAccess,
        LPSECURITY_ATTRIBUTES        lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE                   TokenType,
        PHANDLE                      phNewToken
    ) = 0;

    // Wrapper for FlushFileBuffers (fileapi.h)
    virtual BOOL FlushFileBuffersWrapper(HANDLE hFile) = 0;

    // Wrapper for generating a random IV
    virtual std::vector<CryptoPP::byte> GenerateIvWrapper(size_t size) = 0;

    // Wrapper for GetComputerName (winbase.h)
    virtual BOOL GetComputerNameWrapper(
        LPWSTR  lpBuffer,
        LPDWORD nSize
    ) = 0;

    // Wrapper for GetCurrentThreadId function (processthreadsapi.h)
    virtual DWORD GetCurrentThreadIdWrapper() = 0;

    // Wrapper for getting directory entries for a given dir
    virtual std::vector<std::filesystem::directory_entry> GetDirEntries(std::wstring src) = 0;

    // Wrapper for GetExitCodeProcess (processthreadsapi.h)
    virtual BOOL GetExitCodeProcessWrapper(
        HANDLE  hProcess,
        LPDWORD lpExitCode
    ) = 0;

    // Wrapper for GetFileSize (fileapi.h)
    virtual DWORD GetFileSizeWrapper(
        HANDLE  hFile,
        LPDWORD lpFileSizeHigh
    ) = 0;

    // Wrapper for GetLastError (errhandlingapi.h)
    virtual DWORD GetLastErrorWrapper() = 0;

    // Wrapper for GetModuleFileName (libloaderapi.h)
    virtual DWORD GetModuleFileNameWrapper(
        HMODULE hModule,
        LPWSTR  lpFilename,
        DWORD   nSize
    ) = 0;

    // Wrapper for GetProcessWindowStation function (winuser.h)
    virtual HWINSTA GetProcessWindowStationWrapper() = 0;

    // Wrapper for GetSecurityDescriptorDacl (securitybaseapi.h)
    virtual BOOL GetSecurityDescriptorDaclWrapper(
        PSECURITY_DESCRIPTOR pSecurityDescriptor,
        LPBOOL               lpbDaclPresent,
        PACL                 *pDacl,
        LPBOOL               lpbDaclDefaulted
    ) = 0;

    // Wrapper for GetThreadDesktop function (winuser.h)
    virtual HDESK GetThreadDesktopWrapper(DWORD dwThreadId) = 0;

    // Wrapper for GetTokenInformation (securitybaseapi.h)
    virtual BOOL GetTokenInformationWrapper(
        HANDLE                  TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        LPVOID                  TokenInformation,
        DWORD                   TokenInformationLength,
        PDWORD                  ReturnLength
    ) = 0;

    // Wrapper for GetUserObjectSecurity (winuser.h)
    virtual BOOL GetUserObjectSecurityWrapper(
        HANDLE                hObj,
        PSECURITY_INFORMATION pSIRequested,
        PSECURITY_DESCRIPTOR  pSID,
        DWORD                 nLength,
        LPDWORD               lpnLengthNeeded
    ) = 0;

    // Wrapper for HttpOpenRequest (wininet.h)
    virtual HINTERNET HttpOpenRequestWrapper(
        HINTERNET hConnect,
        LPCWSTR   lpszVerb,
        LPCWSTR   lpszObjectName,
        LPCWSTR   lpszVersion,
        LPCWSTR   lpszReferrer,
        LPCWSTR   *lplpszAcceptTypes,
        DWORD     dwFlags,
        DWORD_PTR dwContext
    ) = 0;

    // Wrapper for HttpQueryInfo (wininet.h)
    virtual BOOL HttpQueryInfoWrapper(
        HINTERNET hRequest,
        DWORD     dwInfoLevel,
        LPVOID    lpBuffer,
        LPDWORD   lpdwBufferLength,
        LPDWORD   lpdwIndex
    ) = 0;

    // Wrapper for HttpSendRequest (wininet.h)
    virtual BOOL HttpSendRequestWrapper(
        HINTERNET hRequest,
        LPCWSTR   lpszHeaders,
        DWORD     dwHeadersLength,
        LPVOID    lpOptional,
        DWORD     dwOptionalLength
    ) = 0;

    // Wrapper for InitializeSecurityDescriptor function (securitybaseapi.h)
    virtual BOOL InitializeSecurityDescriptorWrapper(
        PSECURITY_DESCRIPTOR pSecurityDescriptor,
        DWORD                dwRevision
    ) = 0;

    // Wrapper for InternetCloseHandle (wininet.h)
    virtual BOOL InternetCloseHandleWrapper(HINTERNET hInternet) = 0;

    // Wrapper for InternetConnect (wininet.h)
    virtual HINTERNET InternetConnectWrapper(
        HINTERNET     hInternet,
        LPCWSTR       lpszServerName,
        INTERNET_PORT nServerPort,
        LPCWSTR       lpszUserName,
        LPCWSTR       lpszPassword,
        DWORD         dwService,
        DWORD         dwFlags,
        DWORD_PTR     dwContext
    ) = 0;

    // Wrapper for InternetOpen (wininet.h)
    virtual HINTERNET InternetOpenWrapper(
        LPCWSTR lpszAgent,
        DWORD   dwAccessType,
        LPCWSTR lpszProxy,
        LPCWSTR lpszProxyBypass,
        DWORD   dwFlags
    ) = 0;

    // Wrapper for InternetReadFile (wininet.h)
    virtual BOOL InternetReadFileWrapper(
        HINTERNET hFile,
        LPVOID    lpBuffer,
        DWORD     dwNumberOfBytesToRead,
        LPDWORD   lpdwNumberOfBytesRead
    ) = 0;

    // Wrapper for LocalFree(winbase.h)
    virtual HLOCAL LocalFreeWrapper(HLOCAL hMem) = 0;

    // Wrapper for LookupAccountSidW (winbase.h)
    virtual BOOL LookupAccountSidWrapper(
        LPCWSTR       lpSystemName,
        PSID          Sid,
        LPWSTR        Name,
        LPDWORD       cchName,
        LPWSTR        ReferencedDomainName,
        LPDWORD       cchReferencedDomainName,
        PSID_NAME_USE peUse
    ) = 0;

    // Wrapper for OpenProcess (processthreadsapi.h)
    virtual HANDLE OpenProcessWrapper(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwProcessId
    ) = 0;

    // Wrapper for OpenProcessToken (processthreadsapi.h)
    virtual BOOL OpenProcessTokenWrapper(
        HANDLE  ProcessHandle,
        DWORD   DesiredAccess,
        PHANDLE TokenHandle
    ) = 0;

    virtual BOOL PeekNamedPipeWrapper(
        HANDLE  hNamedPipe,
        LPVOID  lpBuffer,
        DWORD   nBufferSize,
        LPDWORD lpBytesRead,
        LPDWORD lpTotalBytesAvail,
        LPDWORD lpBytesLeftThisMessage
    ) = 0;

    // Wrapper for Process32First (tlhelp32.h)
    virtual BOOL Process32FirstWrapper(
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe
    ) = 0;

    // Wrapper for Process32Next (tlhelp32.h)
    virtual BOOL Process32NextWrapper(
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe
    ) = 0;

    // Wrapper for ReadFile (fileapi.h)
    virtual BOOL ReadFileWrapper(
        HANDLE       hFile,
        LPVOID       lpBuffer,
        DWORD        nNumberOfBytesToRead,
        LPDWORD      lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
    ) = 0;

    // Wrapper for ReleaseMutex (synchapi.h)
    virtual BOOL ReleaseMutexWrapper(HANDLE hMutex) = 0;

    // Wrapper for remove file function (stdio.h)
    virtual int RemoveFileWrapper(LPCWSTR filename) = 0;

    // Wrapper for SetEntriesInAclW function (aclapi.h)
    virtual DWORD SetEntriesInAclWrapper(
        ULONG              cCountOfExplicitEntries,
        PEXPLICIT_ACCESS_W pListOfExplicitEntries,
        PACL               OldAcl,
        PACL               *NewAcl
    ) = 0;

    // Wrapper for SetHandleInformation (handleapi.h)
    virtual BOOL SetHandleInformationWrapper(
        HANDLE hObject,
        DWORD  dwMask,
        DWORD  dwFlags
    ) = 0;

    // Wrapper for SetSecurityDescriptorDacl function (securitybaseapi.h)
    virtual BOOL SetSecurityDescriptorDaclWrapper(
        PSECURITY_DESCRIPTOR pSecurityDescriptor,
        BOOL                 bDaclPresent,
        PACL                 pDacl,
        BOOL                 bDaclDefaulted
    ) = 0;

    // Wrapper for SetUserObjectSecurity function (winuser.h)
    virtual BOOL SetUserObjectSecurityWrapper(
        HANDLE                hObj,
        PSECURITY_INFORMATION pSIRequested,
        PSECURITY_DESCRIPTOR  pSID
    ) = 0;

    // Wrapper for sleep_for function
    virtual void SleepWrapper(DWORD dwMilliseconds) = 0;

    // Wrapper for truncating a file
    virtual void TruncateFileWrapper(std::wstring filename) = 0;

    // Wrapper for WaitForSingleObject (synchapi.h)
    virtual DWORD WaitForSingleObjectWrapper(HANDLE hHandle, DWORD dwMilliseconds) = 0;

    // Wrapper for WriteFile (fileapi.h)
    virtual BOOL WriteFileWrapper(
        HANDLE       hFile,
        LPCVOID      lpBuffer,
        DWORD        nNumberOfBytesToWrite,
        LPDWORD      lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    ) = 0;
};

class ApiWrapper : public ApiWrapperInterface {
public:
    void AppendStringWrapper(std::wstring file_path, std::string data);

    BOOL CloseHandleWrapper(HANDLE hObject);

    BOOL CloseDesktopWrapper(
        HDESK hDesktop
    );

    BOOL ConnectNamedPipeWrapper(
        HANDLE       hNamedPipe,
        LPOVERLAPPED lpOverlapped
    );

    BOOL ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        LPCWSTR              StringSecurityDescriptor,
        DWORD                StringSDRevision,
        PSECURITY_DESCRIPTOR *SecurityDescriptor,
        PULONG               SecurityDescriptorSize
    );

    HANDLE CreateFileWrapper(
        LPCWSTR               lpFileName,
        DWORD                 dwDesiredAccess,
        DWORD                 dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD                 dwCreationDisposition,
        DWORD                 dwFlagsAndAttributes,
        HANDLE                hTemplateFile
    );

    HANDLE CreateMutexWrapper(
        LPSECURITY_ATTRIBUTES lpMutexAttributes,
        BOOL                  bInitialOwner,
        LPCWSTR               lpName
    );

    HANDLE CreateNamedPipeWrapper(
        LPCWSTR               lpName,
        DWORD                 dwOpenMode,
        DWORD                 dwPipeMode,
        DWORD                 nMaxInstances,
        DWORD                 nOutBufferSize,
        DWORD                 nInBufferSize,
        DWORD                 nDefaultTimeOut,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes
    );

    BOOL CreatePipeWrapper(
        PHANDLE               hReadPipe,
        PHANDLE               hWritePipe,
        LPSECURITY_ATTRIBUTES lpPipeAttributes,
        DWORD                 nSize
    );

    BOOL CreateProcessWrapper(
        LPCWSTR               lpApplicationName,
        LPWSTR                lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCWSTR               lpCurrentDirectory,
        LPSTARTUPINFOW        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    );

    BOOL CreateProcessWithTokenWrapper(
        HANDLE                hToken,
        DWORD                 dwLogonFlags,
        LPCWSTR               lpApplicationName,
        LPWSTR                lpCommandLine,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCWSTR               lpCurrentDirectory,
        LPSTARTUPINFOW        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    );

    HANDLE CreateThreadWrapper(
        LPSECURITY_ATTRIBUTES   lpThreadAttributes,
        SIZE_T                  dwStackSize,
        LPTHREAD_START_ROUTINE  lpStartAddress,
        __drv_aliasesMem LPVOID lpParameter,
         DWORD                   dwCreationFlags,
        LPDWORD                 lpThreadId
    );

    HANDLE CreateToolhelp32SnapshotWrapper(
        DWORD dwFlags,
        DWORD th32ProcessID
    );

    std::string CurrentUtcTimeWrapper();

    BOOL DisconnectNamedPipeWrapper(HANDLE hNamedPipe);

    BOOL DuplicateTokenExWrapper(
        HANDLE                       hExistingToken,
        DWORD                        dwDesiredAccess,
        LPSECURITY_ATTRIBUTES        lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE                   TokenType,
        PHANDLE                      phNewToken
    );

    BOOL FlushFileBuffersWrapper(HANDLE hFile);

    std::vector<CryptoPP::byte> GenerateIvWrapper(size_t size);

    BOOL GetComputerNameWrapper(
        LPWSTR  lpBuffer,
        LPDWORD nSize
    );

    DWORD GetCurrentThreadIdWrapper();

    std::vector<std::filesystem::directory_entry> GetDirEntries(std::wstring src);

    BOOL GetExitCodeProcessWrapper(
        HANDLE  hProcess,
        LPDWORD lpExitCode
    );

    DWORD GetFileSizeWrapper(
        HANDLE  hFile,
        LPDWORD lpFileSizeHigh
    );

    DWORD GetLastErrorWrapper();

    DWORD GetModuleFileNameWrapper(
        HMODULE hModule,
        LPWSTR  lpFilename,
        DWORD   nSize
    );

    HWINSTA GetProcessWindowStationWrapper();

    BOOL GetSecurityDescriptorDaclWrapper(
        PSECURITY_DESCRIPTOR pSecurityDescriptor,
        LPBOOL               lpbDaclPresent,
        PACL                 *pDacl,
        LPBOOL               lpbDaclDefaulted
    );

    HDESK GetThreadDesktopWrapper(DWORD dwThreadId);

    BOOL GetTokenInformationWrapper(
        HANDLE                  TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        LPVOID                  TokenInformation,
        DWORD                   TokenInformationLength,
        PDWORD                  ReturnLength
    );

    BOOL GetUserObjectSecurityWrapper(
        HANDLE                hObj,
        PSECURITY_INFORMATION pSIRequested,
        PSECURITY_DESCRIPTOR  pSID,
        DWORD                 nLength,
        LPDWORD               lpnLengthNeeded
    );

    HINTERNET HttpOpenRequestWrapper(
        HINTERNET hConnect,
        LPCWSTR   lpszVerb,
        LPCWSTR   lpszObjectName,
        LPCWSTR   lpszVersion,
        LPCWSTR   lpszReferrer,
        LPCWSTR   *lplpszAcceptTypes,
        DWORD     dwFlags,
        DWORD_PTR dwContext
    );

    BOOL HttpQueryInfoWrapper(
        HINTERNET hRequest,
        DWORD     dwInfoLevel,
        LPVOID    lpBuffer,
        LPDWORD   lpdwBufferLength,
        LPDWORD   lpdwIndex
    );

    BOOL HttpSendRequestWrapper(
        HINTERNET hRequest,
        LPCWSTR   lpszHeaders,
        DWORD     dwHeadersLength,
        LPVOID    lpOptional,
        DWORD     dwOptionalLength
    );

    BOOL InitializeSecurityDescriptorWrapper(
        PSECURITY_DESCRIPTOR pSecurityDescriptor,
        DWORD                dwRevision
    );

    BOOL InternetCloseHandleWrapper(HINTERNET hInternet);

    HINTERNET InternetConnectWrapper(
        HINTERNET     hInternet,
        LPCWSTR       lpszServerName,
        INTERNET_PORT nServerPort,
        LPCWSTR       lpszUserName,
        LPCWSTR       lpszPassword,
        DWORD         dwService,
        DWORD         dwFlags,
        DWORD_PTR     dwContext
    );

    HINTERNET InternetOpenWrapper(
        LPCWSTR lpszAgent,
        DWORD   dwAccessType,
        LPCWSTR lpszProxy,
        LPCWSTR lpszProxyBypass,
        DWORD   dwFlags
    );

    BOOL InternetReadFileWrapper(
        HINTERNET hFile,
        LPVOID    lpBuffer,
        DWORD     dwNumberOfBytesToRead,
        LPDWORD   lpdwNumberOfBytesRead
    );

    HLOCAL LocalFreeWrapper(HLOCAL hMem);

    BOOL LookupAccountSidWrapper(
        LPCWSTR       lpSystemName,
        PSID          Sid,
        LPWSTR        Name,
        LPDWORD       cchName,
        LPWSTR        ReferencedDomainName,
        LPDWORD       cchReferencedDomainName,
        PSID_NAME_USE peUse
    );

    HANDLE OpenProcessWrapper(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwProcessId
    );

    BOOL OpenProcessTokenWrapper(
        HANDLE  ProcessHandle,
        DWORD   DesiredAccess,
        PHANDLE TokenHandle
    );

    BOOL PeekNamedPipeWrapper(
        HANDLE  hNamedPipe,
        LPVOID  lpBuffer,
        DWORD   nBufferSize,
        LPDWORD lpBytesRead,
        LPDWORD lpTotalBytesAvail,
        LPDWORD lpBytesLeftThisMessage
    );

    BOOL Process32FirstWrapper(
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe
    );

    BOOL Process32NextWrapper(
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe
    );

    BOOL ReadFileWrapper(
        HANDLE       hFile,
        LPVOID       lpBuffer,
        DWORD        nNumberOfBytesToRead,
        LPDWORD      lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
    );

    BOOL ReleaseMutexWrapper(HANDLE hMutex);

    int RemoveFileWrapper(LPCWSTR filename);

    DWORD SetEntriesInAclWrapper(
        ULONG              cCountOfExplicitEntries,
        PEXPLICIT_ACCESS_W pListOfExplicitEntries,
        PACL               OldAcl,
        PACL               *NewAcl
    );

    BOOL SetHandleInformationWrapper(
        HANDLE hObject,
        DWORD  dwMask,
        DWORD  dwFlags
    );

    BOOL SetSecurityDescriptorDaclWrapper(
        PSECURITY_DESCRIPTOR pSecurityDescriptor,
        BOOL                 bDaclPresent,
        PACL                 pDacl,
        BOOL                 bDaclDefaulted
    );

    BOOL SetUserObjectSecurityWrapper(
        HANDLE                hObj,
        PSECURITY_INFORMATION pSIRequested,
        PSECURITY_DESCRIPTOR  pSID
    );

    void SleepWrapper(DWORD dwMilliseconds);

    void TruncateFileWrapper(std::wstring filename);

    DWORD WaitForSingleObjectWrapper(HANDLE hHandle, DWORD dwMilliseconds);

    BOOL WriteFileWrapper(
        HANDLE       hFile,
        LPCVOID      lpBuffer,
        DWORD        nNumberOfBytesToWrite,
        LPDWORD      lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    );
};

#endif
