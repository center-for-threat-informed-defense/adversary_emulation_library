/*
 * Provide mock wrappers for Windows and other API functions and other shared test utilities
 */

#ifndef SNAKE_USERLAND_MOCK_WRAPPER_H_
#define SNAKE_USERLAND_MOCK_WRAPPER_H_

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <string>
#include "api_wrappers.h"

// Mock the wrapper functions for unit tests
class MockApiWrapper : public ApiWrapperInterface {
public:
	virtual ~MockApiWrapper(){}

    MOCK_METHOD2(AppendStringWrapper, void(std::wstring file_path, std::string data));
    MOCK_METHOD1(CloseDesktopWrapper, BOOL(HDESK hDesktop));
    MOCK_METHOD1(CloseHandleWrapper, BOOL(HANDLE hObject));
    MOCK_METHOD2(ConnectNamedPipeWrapper, BOOL(
        HANDLE       hNamedPipe,
        LPOVERLAPPED lpOverlapped
    ));
    MOCK_METHOD4(ConvertStringSecurityDescriptorToSecurityDescriptorWrapper, BOOL(
        LPCWSTR              StringSecurityDescriptor,
        DWORD                StringSDRevision,
        PSECURITY_DESCRIPTOR *SecurityDescriptor,
        PULONG               SecurityDescriptorSize
    ));
    MOCK_METHOD7(CreateFileWrapper, HANDLE(
        LPCWSTR               lpFileName,
        DWORD                 dwDesiredAccess,
        DWORD                 dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD                 dwCreationDisposition,
        DWORD                 dwFlagsAndAttributes,
        HANDLE                hTemplateFile
    ));
    MOCK_METHOD3(CreateMutexWrapper, HANDLE(
        LPSECURITY_ATTRIBUTES lpMutexAttributes,
        BOOL                  bInitialOwner,
        LPCWSTR               lpName
    ));
    MOCK_METHOD8(CreateNamedPipeWrapper, HANDLE(
        LPCWSTR               lpName,
        DWORD                 dwOpenMode,
        DWORD                 dwPipeMode,
        DWORD                 nMaxInstances,
        DWORD                 nOutBufferSize,
        DWORD                 nInBufferSize,
        DWORD                 nDefaultTimeOut,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ));
    MOCK_METHOD4(CreatePipeWrapper, BOOL(
        PHANDLE               hReadPipe,
        PHANDLE               hWritePipe,
        LPSECURITY_ATTRIBUTES lpPipeAttributes,
        DWORD                 nSize
    ));
    MOCK_METHOD10(CreateProcessWrapper, BOOL(
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
    ));
    MOCK_METHOD9(CreateProcessWithTokenWrapper, BOOL(
        HANDLE                hToken,
        DWORD                 dwLogonFlags,
        LPCWSTR               lpApplicationName,
        LPWSTR                lpCommandLine,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCWSTR               lpCurrentDirectory,
        LPSTARTUPINFOW        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    ));
    MOCK_METHOD6(CreateThreadWrapper, HANDLE(
        LPSECURITY_ATTRIBUTES   lpThreadAttributes,
        SIZE_T                  dwStackSize,
        LPTHREAD_START_ROUTINE  lpStartAddress,
        __drv_aliasesMem LPVOID lpParameter,
         DWORD                   dwCreationFlags,
        LPDWORD                 lpThreadId
    ));
    MOCK_METHOD2(CreateToolhelp32SnapshotWrapper, HANDLE(
        DWORD dwFlags,
        DWORD th32ProcessID
    ));
    MOCK_METHOD0(CurrentUtcTimeWrapper, std::string(void));
    MOCK_METHOD1(DisconnectNamedPipeWrapper, BOOL(HANDLE hNamedPipe));
    MOCK_METHOD6(DuplicateTokenExWrapper, BOOL(
        HANDLE                       hExistingToken,
        DWORD                        dwDesiredAccess,
        LPSECURITY_ATTRIBUTES        lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE                   TokenType,
        PHANDLE                      phNewToken
    ));
    MOCK_METHOD1(FlushFileBuffersWrapper, BOOL(HANDLE hFile));
    MOCK_METHOD1(GenerateIvWrapper, std::vector<CryptoPP::byte>(size_t size));
    MOCK_METHOD2(GetComputerNameWrapper, BOOL(
        LPWSTR  lpBuffer,
        LPDWORD nSize
    ));
    MOCK_METHOD0(GetCurrentThreadIdWrapper, DWORD());
    MOCK_METHOD1(GetDirEntries, std::vector<std::filesystem::directory_entry>(std::wstring src));
    MOCK_METHOD2(GetExitCodeProcessWrapper, BOOL(
        HANDLE  hProcess,
        LPDWORD lpExitCode
    ));
    MOCK_METHOD2(GetFileSizeWrapper, DWORD(
        HANDLE  hFile,
        LPDWORD lpFileSizeHigh
    ));
    MOCK_METHOD0(GetLastErrorWrapper, DWORD());
    MOCK_METHOD3(GetModuleFileNameWrapper, DWORD(
        HMODULE hModule,
        LPWSTR  lpFilename,
        DWORD   nSize
    ));
    MOCK_METHOD0(GetProcessWindowStationWrapper, HWINSTA());
    MOCK_METHOD4(GetSecurityDescriptorDaclWrapper, BOOL(
        PSECURITY_DESCRIPTOR pSecurityDescriptor,
        LPBOOL               lpbDaclPresent,
        PACL                 *pDacl,
        LPBOOL               lpbDaclDefaulted
    ));
    MOCK_METHOD1(GetThreadDesktopWrapper, HDESK(DWORD dwThreadId));
    MOCK_METHOD5(GetTokenInformationWrapper, BOOL(
        HANDLE                  TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        LPVOID                  TokenInformation,
        DWORD                   TokenInformationLength,
        PDWORD                  ReturnLength
    ));
    MOCK_METHOD5(GetUserObjectSecurityWrapper, BOOL(
        HANDLE                hObj,
        PSECURITY_INFORMATION pSIRequested,
        PSECURITY_DESCRIPTOR  pSID,
        DWORD                 nLength,
        LPDWORD               lpnLengthNeeded
    ));
    MOCK_METHOD8(HttpOpenRequestWrapper, HINTERNET(
        HINTERNET hConnect,
        LPCWSTR   lpszVerb,
        LPCWSTR   lpszObjectName,
        LPCWSTR   lpszVersion,
        LPCWSTR   lpszReferrer,
        LPCWSTR   *lplpszAcceptTypes,
        DWORD     dwFlags,
        DWORD_PTR dwContext
    ));
    MOCK_METHOD5(HttpQueryInfoWrapper, BOOL(
        HINTERNET hRequest,
        DWORD     dwInfoLevel,
        LPVOID    lpBuffer,
        LPDWORD   lpdwBufferLength,
        LPDWORD   lpdwIndex
    ));
    MOCK_METHOD5(HttpSendRequestWrapper, BOOL(
        HINTERNET hRequest,
        LPCWSTR   lpszHeaders,
        DWORD     dwHeadersLength,
        LPVOID    lpOptional,
        DWORD     dwOptionalLength
    ));
    MOCK_METHOD2(InitializeSecurityDescriptorWrapper, BOOL(
        PSECURITY_DESCRIPTOR pSecurityDescriptor,
        DWORD                dwRevision
    ));
    MOCK_METHOD1(InternetCloseHandleWrapper, BOOL(HINTERNET hInternet));
    MOCK_METHOD8(InternetConnectWrapper, HINTERNET(
        HINTERNET     hInternet,
        LPCWSTR       lpszServerName,
        INTERNET_PORT nServerPort,
        LPCWSTR       lpszUserName,
        LPCWSTR       lpszPassword,
        DWORD         dwService,
        DWORD         dwFlags,
        DWORD_PTR     dwContext
    ));
    MOCK_METHOD5(InternetOpenWrapper, HINTERNET(
        LPCWSTR lpszAgent,
        DWORD   dwAccessType,
        LPCWSTR lpszProxy,
        LPCWSTR lpszProxyBypass,
        DWORD   dwFlags
    ));
    MOCK_METHOD4(InternetReadFileWrapper, BOOL(
        HINTERNET hFile,
        LPVOID    lpBuffer,
        DWORD     dwNumberOfBytesToRead,
        LPDWORD   lpdwNumberOfBytesRead
    ));
    MOCK_METHOD1(LocalFreeWrapper, HLOCAL(HLOCAL hMem));
    MOCK_METHOD7(LookupAccountSidWrapper, BOOL(
        LPCWSTR       lpSystemName,
        PSID          Sid,
        LPWSTR        Name,
        LPDWORD       cchName,
        LPWSTR        ReferencedDomainName,
        LPDWORD       cchReferencedDomainName,
        PSID_NAME_USE peUse
    ));
    MOCK_METHOD3(OpenProcessWrapper, HANDLE(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwProcessId
    ));
    MOCK_METHOD3(OpenProcessTokenWrapper, BOOL(
        HANDLE  ProcessHandle,
        DWORD   DesiredAccess,
        PHANDLE TokenHandle
    ));
    MOCK_METHOD6(PeekNamedPipeWrapper, BOOL(
        HANDLE  hNamedPipe,
        LPVOID  lpBuffer,
        DWORD   nBufferSize,
        LPDWORD lpBytesRead,
        LPDWORD lpTotalBytesAvail,
        LPDWORD lpBytesLeftThisMessage
    ));
    MOCK_METHOD2(Process32FirstWrapper, BOOL(
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe
    ));
    MOCK_METHOD2(Process32NextWrapper, BOOL(
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe
    ));
    MOCK_METHOD5(ReadFileWrapper, BOOL(
        HANDLE       hFile,
        LPVOID       lpBuffer,
        DWORD        nNumberOfBytesToRead,
        LPDWORD      lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
    ));
    MOCK_METHOD1(ReleaseMutexWrapper, BOOL(HANDLE hMutex));
    MOCK_METHOD1(RemoveFileWrapper, int(LPCWSTR filename));
    MOCK_METHOD4(SetEntriesInAclWrapper, DWORD(
        ULONG              cCountOfExplicitEntries,
        PEXPLICIT_ACCESS_W pListOfExplicitEntries,
        PACL               OldAcl,
        PACL               *NewAcl
    ));
    MOCK_METHOD3(SetHandleInformationWrapper, BOOL(
        HANDLE hObject,
        DWORD  dwMask,
        DWORD  dwFlags
    ));
    MOCK_METHOD4(SetSecurityDescriptorDaclWrapper, BOOL(
        PSECURITY_DESCRIPTOR pSecurityDescriptor,
        BOOL                 bDaclPresent,
        PACL                 pDacl,
        BOOL                 bDaclDefaulted
    ));
    MOCK_METHOD3(SetUserObjectSecurityWrapper, BOOL(
        HANDLE                hObj,
        PSECURITY_INFORMATION pSIRequested,
        PSECURITY_DESCRIPTOR  pSID
    ));
    MOCK_METHOD1(SleepWrapper, void(DWORD dwMilliseconds));
    MOCK_METHOD1(TruncateFileWrapper, void(std::wstring filename));
    MOCK_METHOD2(WaitForSingleObjectWrapper, DWORD(HANDLE hHandle, DWORD dwMilliseconds));
    MOCK_METHOD5(WriteFileWrapper, BOOL(
        HANDLE       hFile,
        LPCVOID      lpBuffer,
        DWORD        nNumberOfBytesToWrite,
        LPDWORD      lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    ));
};

#endif