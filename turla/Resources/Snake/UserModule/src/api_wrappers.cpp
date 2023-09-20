/*
 * Provide API Wrappers
 */

#include <fstream>
#include "api_wrappers.h"

CryptoPP::AutoSeededRandomPool prng;

// Append data string to file
void ApiWrapper::AppendStringWrapper(std::wstring file_path, std::string data) {
    std::ofstream out_file;
    out_file.open(std::filesystem::path(file_path), std::ios_base::app);
    out_file << data << "\n";
}

// Wrapper for CloseHandle (handleapi.h)
BOOL ApiWrapper::CloseHandleWrapper(HANDLE hObject) {
    return CloseHandle(hObject);
}

// Wrapper for CloseDesktop function (winuser.h)
BOOL ApiWrapper::CloseDesktopWrapper(HDESK hDesktop) {
    return CloseDesktop(hDesktop);
}

// Wrapper for ConnectNamedPipe (namedpipeapi.h)
BOOL ApiWrapper::ConnectNamedPipeWrapper(
    HANDLE       hNamedPipe,
    LPOVERLAPPED lpOverlapped
) {
    return ConnectNamedPipe(hNamedPipe, lpOverlapped);
}

// Wrapper for ConvertStringSecurityDescriptorToSecurityDescriptor (sddl.h)
BOOL ApiWrapper::ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
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

// Wrapper for CreateFile (fileapi.h)
HANDLE ApiWrapper::CreateFileWrapper(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
) {
    return CreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    );
}

// Wrapper for CreateMutexW (synchapi.h)
HANDLE ApiWrapper::CreateMutexWrapper(
    LPSECURITY_ATTRIBUTES lpMutexAttributes,
    BOOL                  bInitialOwner,
    LPCWSTR               lpName
) {
    return CreateMutexW(
        lpMutexAttributes,
        bInitialOwner,
        lpName
    );
}

// Wrapper for CreateNamedPipe (winbase.h)
HANDLE ApiWrapper::CreateNamedPipeWrapper(
    LPCWSTR               lpName,
    DWORD                 dwOpenMode,
    DWORD                 dwPipeMode,
    DWORD                 nMaxInstances,
    DWORD                 nOutBufferSize,
    DWORD                 nInBufferSize,
    DWORD                 nDefaultTimeOut,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    return CreateNamedPipeW(
        lpName,
        dwOpenMode,
        dwPipeMode,
        nMaxInstances,
        nOutBufferSize,
        nInBufferSize,
        nDefaultTimeOut,
        lpSecurityAttributes
    );
}

// Wrapper for CreatePipe (namedpipeapi.h)
BOOL ApiWrapper::CreatePipeWrapper(
    PHANDLE               hReadPipe,
    PHANDLE               hWritePipe,
    LPSECURITY_ATTRIBUTES lpPipeAttributes,
    DWORD                 nSize
) {
    return CreatePipe(
        hReadPipe,
        hWritePipe,
        lpPipeAttributes,
        nSize
    );
}

// Wrapper for CreateProcessW (processthreadsapi.h)
BOOL ApiWrapper::CreateProcessWrapper(
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
) {
    return CreateProcessW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
}

// Wrapper for CreateProcessWithTokenW (winbase.h)
BOOL ApiWrapper::CreateProcessWithTokenWrapper(
    HANDLE                hToken,
    DWORD                 dwLogonFlags,
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    return CreateProcessWithTokenW(
        hToken,
        dwLogonFlags,
        lpApplicationName,
        lpCommandLine,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
}

// Wrapper for CreateThread (processthreadsapi.h)
HANDLE ApiWrapper::CreateThreadWrapper(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
        DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
) {
    return CreateThread(
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId
    );
}

// Wrapper for CreateToolhelp32Snapshot (tlhelp32.h)
HANDLE ApiWrapper::CreateToolhelp32SnapshotWrapper(
    DWORD dwFlags,
    DWORD th32ProcessID
) {
    return CreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}

// Get current UTC time
std::string ApiWrapper::CurrentUtcTimeWrapper() {
    struct tm* time_info;
    char time_buffer[100];
    time_t raw_time = time(NULL);
    time_info = gmtime(&raw_time);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", time_info);
    return std::string(time_buffer);
}

std::vector<CryptoPP::byte> ApiWrapper::GenerateIvWrapper(size_t size) {
    // Generate IV
    // Reference: https://cryptopp.com/wiki/Initialization_Vector
    std::vector<CryptoPP::byte> iv = std::vector<CryptoPP::byte>(size);
    prng.GenerateBlock(&iv[0], size);
    return iv;
}

// Wrapper for DisconnectNamedPipe (namedpipeapi.h)
BOOL ApiWrapper::DisconnectNamedPipeWrapper(HANDLE hNamedPipe) {
    return DisconnectNamedPipe(hNamedPipe);
}

// Wrapper for DuplicateTokenEx (securitybaseapi.h)
BOOL ApiWrapper::DuplicateTokenExWrapper(
    HANDLE                       hExistingToken,
    DWORD                        dwDesiredAccess,
    LPSECURITY_ATTRIBUTES        lpTokenAttributes,
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    TOKEN_TYPE                   TokenType,
    PHANDLE                      phNewToken
) {
    return DuplicateTokenEx(
        hExistingToken,
        dwDesiredAccess,
        lpTokenAttributes,
        ImpersonationLevel,
        TokenType,
        phNewToken
    );
}

// Wrapper for FlushFileBuffers (fileapi.h)
BOOL ApiWrapper::FlushFileBuffersWrapper(HANDLE hFile) {
    return FlushFileBuffers(hFile);
}

// Wrapper for GetComputerName (winbase.h)
BOOL ApiWrapper::GetComputerNameWrapper(
    LPWSTR  lpBuffer,
    LPDWORD nSize
) {
    return GetComputerNameW(lpBuffer, nSize);
}

// Wrapper for GetCurrentThreadId function (processthreadsapi.h)
DWORD ApiWrapper::GetCurrentThreadIdWrapper() {
    return GetCurrentThreadId();
}

std::vector<std::filesystem::directory_entry> ApiWrapper::GetDirEntries(std::wstring src) {
    std::vector<std::filesystem::directory_entry> entries;
    for (auto &entry : std::filesystem::directory_iterator(src)) {
        entries.push_back(entry);
    }
    return entries;
}

// Wrapper for GetExitCodeProcess (processthreadsapi.h)
BOOL ApiWrapper::GetExitCodeProcessWrapper(
    HANDLE  hProcess,
    LPDWORD lpExitCode
) {
    return GetExitCodeProcess(hProcess, lpExitCode);
}

// Wrapper for GetFileSize (fileapi.h)
DWORD ApiWrapper::GetFileSizeWrapper(
    HANDLE  hFile,
    LPDWORD lpFileSizeHigh
) {
    return GetFileSize(hFile, lpFileSizeHigh);
}


// Wrapper for GetLastError (errhandlingapi.h)
DWORD ApiWrapper::GetLastErrorWrapper() {
    return GetLastError();
}

// Wrapper for GetModuleFileName (libloaderapi.h)
DWORD ApiWrapper::GetModuleFileNameWrapper(
    HMODULE hModule,
    LPWSTR  lpFilename,
    DWORD   nSize
) {
    return GetModuleFileNameW(hModule, lpFilename, nSize);
}

// Wrapper for GetProcessWindowStation function (winuser.h)
HWINSTA ApiWrapper::GetProcessWindowStationWrapper() {
    return GetProcessWindowStation();
}

// Wrapper for GetSecurityDescriptorDacl (securitybaseapi.h)
BOOL ApiWrapper::GetSecurityDescriptorDaclWrapper(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    LPBOOL               lpbDaclPresent,
    PACL                 *pDacl,
    LPBOOL               lpbDaclDefaulted
) {
    return GetSecurityDescriptorDacl(
        pSecurityDescriptor,
        lpbDaclPresent,
        pDacl,
        lpbDaclDefaulted
    );
}

// Wrapper for GetThreadDesktop function (winuser.h)
HDESK ApiWrapper::GetThreadDesktopWrapper(DWORD dwThreadId) {
    return GetThreadDesktop(dwThreadId);
}

// Wrapper for GetTokenInformation (securitybaseapi.h)
BOOL ApiWrapper::GetTokenInformationWrapper(
    HANDLE                  TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    LPVOID                  TokenInformation,
    DWORD                   TokenInformationLength,
    PDWORD                  ReturnLength
) {
    return GetTokenInformation(
        TokenHandle,
        TokenInformationClass,
        TokenInformation,
        TokenInformationLength,
        ReturnLength
    );
}

 // Wrapper for GetUserObjectSecurity (winuser.h)
BOOL ApiWrapper::GetUserObjectSecurityWrapper(
    HANDLE                hObj,
    PSECURITY_INFORMATION pSIRequested,
    PSECURITY_DESCRIPTOR  pSID,
    DWORD                 nLength,
    LPDWORD               lpnLengthNeeded
) {
    return GetUserObjectSecurity(
        hObj,
        pSIRequested,
        pSID,
        nLength,
        lpnLengthNeeded
    );
}

// Wrapper for HttpOpenRequest (wininet.h)
HINTERNET ApiWrapper::HttpOpenRequestWrapper(
    HINTERNET hConnect,
    LPCWSTR   lpszVerb,
    LPCWSTR   lpszObjectName,
    LPCWSTR   lpszVersion,
    LPCWSTR   lpszReferrer,
    LPCWSTR   *lplpszAcceptTypes,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    return HttpOpenRequestW(
        hConnect,
        lpszVerb,
        lpszObjectName,
        lpszVersion,
        lpszReferrer,
        lplpszAcceptTypes,
        dwFlags,
        dwContext
    );
}

// Wrapper for HttpQueryInfo (wininet.h)
BOOL ApiWrapper::HttpQueryInfoWrapper(
    HINTERNET hRequest,
    DWORD     dwInfoLevel,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength,
    LPDWORD   lpdwIndex
) {
    return HttpQueryInfoW(
        hRequest,
        dwInfoLevel,
        lpBuffer,
        lpdwBufferLength,
        lpdwIndex
    );
}

// Wrapper for HttpSendRequest (wininet.h)
BOOL ApiWrapper::HttpSendRequestWrapper(
    HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
) {
    return HttpSendRequestW(
        hRequest,
        lpszHeaders,
        dwHeadersLength,
        lpOptional,
        dwOptionalLength
    );
}

// Wrapper for InitializeSecurityDescriptor function (securitybaseapi.h)
BOOL ApiWrapper::InitializeSecurityDescriptorWrapper(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    DWORD                dwRevision
) {
    return InitializeSecurityDescriptor(
        pSecurityDescriptor,
        dwRevision
    );
}

// Wrapper for InternetCloseHandle (wininet.h)
BOOL ApiWrapper::InternetCloseHandleWrapper(HINTERNET hInternet) {
    return InternetCloseHandle(hInternet);
}

// Wrapper for InternetConnect (wininet.h)
HINTERNET ApiWrapper::InternetConnectWrapper(
    HINTERNET     hInternet,
    LPCWSTR       lpszServerName,
    INTERNET_PORT nServerPort,
    LPCWSTR       lpszUserName,
    LPCWSTR       lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
) {
    return InternetConnectW(
        hInternet,
        lpszServerName,
        nServerPort,
        lpszUserName,
        lpszPassword,
        dwService,
        dwFlags,
        dwContext
    );
}

// Wrapper for InternetOpen (wininet.h)
HINTERNET ApiWrapper::InternetOpenWrapper(
    LPCWSTR lpszAgent,
    DWORD   dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD   dwFlags
) {
    return InternetOpenW(
        lpszAgent,
        dwAccessType,
        lpszProxy,
        lpszProxyBypass,
        dwFlags
    );
}

// Wrapper for InternetReadFile (wininet.h)
BOOL ApiWrapper::InternetReadFileWrapper(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {
    return InternetReadFile(
        hFile,
        lpBuffer,
        dwNumberOfBytesToRead,
        lpdwNumberOfBytesRead
    );
}

// Wrapper for LocalFree (winbase.h)
HLOCAL ApiWrapper::LocalFreeWrapper(HLOCAL hMem) {
    return LocalFree(hMem);
}

// Wrapper for LookupAccountSidW (winbase.h)
BOOL ApiWrapper::LookupAccountSidWrapper(
    LPCWSTR       lpSystemName,
    PSID          Sid,
    LPWSTR        Name,
    LPDWORD       cchName,
    LPWSTR        ReferencedDomainName,
    LPDWORD       cchReferencedDomainName,
    PSID_NAME_USE peUse
) {
    return LookupAccountSidW(
        lpSystemName,
        Sid,
        Name,
        cchName,
        ReferencedDomainName,
        cchReferencedDomainName,
        peUse
    );
};

// Wrapper for OpenProcess (processthreadsapi.h)
HANDLE ApiWrapper::OpenProcessWrapper(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
) {
    return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

// Wrapper for OpenProcessToken (processthreadsapi.h)
BOOL ApiWrapper::OpenProcessTokenWrapper(
    HANDLE  ProcessHandle,
    DWORD   DesiredAccess,
    PHANDLE TokenHandle
) {
    return OpenProcessToken(
        ProcessHandle,
        DesiredAccess,
        TokenHandle
    );
}

BOOL ApiWrapper::PeekNamedPipeWrapper(
    HANDLE  hNamedPipe,
    LPVOID  lpBuffer,
    DWORD   nBufferSize,
    LPDWORD lpBytesRead,
    LPDWORD lpTotalBytesAvail,
    LPDWORD lpBytesLeftThisMessage
) {
    return PeekNamedPipe(
        hNamedPipe,
        lpBuffer,
        nBufferSize,
        lpBytesRead,
        lpTotalBytesAvail,
        lpBytesLeftThisMessage
    );
}

// Wrapper for Process32First (tlhelp32.h)
BOOL ApiWrapper::Process32FirstWrapper(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
) {
    return Process32First(hSnapshot, lppe);
}

// Wrapper for Process32Next (tlhelp32.h)
BOOL ApiWrapper::Process32NextWrapper(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
) {
    return Process32Next(hSnapshot, lppe);
}

// Wrapper for ReadFile (fileapi.h)
BOOL ApiWrapper::ReadFileWrapper(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
) {
    return ReadFile(
        hFile,
        lpBuffer,
        nNumberOfBytesToRead,
        lpNumberOfBytesRead,
        lpOverlapped
    );
}

// Wrapper for ReleaseMutex (synchapi.h)
BOOL ApiWrapper::ReleaseMutexWrapper(HANDLE hMutex) {
    return ReleaseMutex(hMutex);
}

// Wrapper for remove file function (stdio.h)
int ApiWrapper::RemoveFileWrapper(LPCWSTR filename) {
    return _wremove(filename);
}

// Wrapper for SetEntriesInAclW function (aclapi.h)
DWORD ApiWrapper::SetEntriesInAclWrapper(
    ULONG              cCountOfExplicitEntries,
    PEXPLICIT_ACCESS_W pListOfExplicitEntries,
    PACL               OldAcl,
    PACL               *NewAcl
) {
    return SetEntriesInAclW(
        cCountOfExplicitEntries,
        pListOfExplicitEntries,
        OldAcl,
        NewAcl
    );
}

// Wrapper for SetHandleInformation (handleapi.h)
BOOL ApiWrapper::SetHandleInformationWrapper(
    HANDLE hObject,
    DWORD  dwMask,
    DWORD  dwFlags
) {
    return SetHandleInformation(
        hObject,
        dwMask,
        dwFlags
    );
}

// Wrapper for SetSecurityDescriptorDacl function (securitybaseapi.h)
BOOL ApiWrapper::SetSecurityDescriptorDaclWrapper(
	PSECURITY_DESCRIPTOR pSecurityDescriptor,
	BOOL                 bDaclPresent,
	PACL                 pDacl,
	BOOL                 bDaclDefaulted
) {
    return SetSecurityDescriptorDacl(
        pSecurityDescriptor,
        bDaclPresent,
        pDacl,
        bDaclDefaulted
    );
}

// Wrapper for SetUserObjectSecurity function (winuser.h)
BOOL ApiWrapper::SetUserObjectSecurityWrapper(
	HANDLE                hObj,
	PSECURITY_INFORMATION pSIRequested,
	PSECURITY_DESCRIPTOR  pSID
) {
    return SetUserObjectSecurity(
        hObj,
        pSIRequested,
        pSID
    );
}

// Wrapper for sleep_for function
void ApiWrapper::SleepWrapper(DWORD dwMilliseconds) {
    return std::this_thread::sleep_for(std::chrono::milliseconds(dwMilliseconds));
}

// Wrapper for truncating file
void ApiWrapper::TruncateFileWrapper(std::wstring filename) {
    std::ofstream file_stream;
    file_stream.open(std::filesystem::path(filename), std::ofstream::out | std::ofstream::trunc);
    file_stream.close();
}

// Wrapper for WaitForSingleObject (synchapi.h)
DWORD ApiWrapper::WaitForSingleObjectWrapper(HANDLE hHandle, DWORD dwMilliseconds) {
    return WaitForSingleObject(hHandle, dwMilliseconds);
}

// Wrapper for WriteFile (fileapi.h)
BOOL ApiWrapper::WriteFileWrapper(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
) {
    return WriteFile(
        hFile,
        lpBuffer,
        nNumberOfBytesToWrite,
        lpNumberOfBytesWritten,
        lpOverlapped
    );
}