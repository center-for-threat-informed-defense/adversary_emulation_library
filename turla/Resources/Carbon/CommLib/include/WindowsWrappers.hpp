#pragma once
#include <windows.h>
#include <sddl.h>
#include <fstream>
#include <string>
#include <vector>

// Interface for API calls to be wrapped. Will be used in source code and test files.
class WinApiWrapperInterface {
public:
    WinApiWrapperInterface(){}
    virtual ~WinApiWrapperInterface(){}

    virtual BOOL CloseHandleWrapper(HANDLE hObject) = 0;

    virtual HANDLE CreateFileWrapper(
        LPCWSTR               lpFileName,
        DWORD                 dwDesiredAccess,
        DWORD                 dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD                 dwCreationDisposition,
        DWORD                 dwFlagsAndAttributes,
        HANDLE                hTemplateFile
    ) = 0;

    virtual DWORD GetFileAttributesWrapper(LPCWSTR lpFileName) = 0;

    virtual DWORD GetLastErrorWrapper() = 0;

    virtual BOOL WriteFileWrapper(
        HANDLE       hFile,
        LPCVOID      lpBuffer,
        DWORD        nNumberOfBytesToWrite,
        LPDWORD      lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    ) = 0;

    // Wrapper for Sleep function (synchapi.h)
    virtual void SleepWrapper(DWORD dwMilliseconds) = 0;
    
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

    // Wrapper for ConnectNamedPipe (namedpipeapi.h)
    virtual BOOL ConnectNamedPipeWrapper(
        HANDLE       hNamedPipe,
        LPOVERLAPPED lpOverlapped
    ) = 0;

    // Wrapper for DisconnectNamedPipe (namedpipeapi.h)
    virtual BOOL DisconnectNamedPipeWrapper(HANDLE hNamedPipe) = 0;

    // Wrapper for ReadFile (fileapi.h)
    virtual BOOL ReadFileWrapper(
        HANDLE       hFile,
        LPVOID       lpBuffer,
        DWORD        nNumberOfBytesToRead,
        LPDWORD      lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
    ) = 0;

    // Wrapper for FlushFileBuffers (fileapi.h)
    virtual BOOL FlushFileBuffersWrapper(HANDLE hFile) = 0;

    // Wrapper for ConvertStringSecurityDescriptorToSecurityDescriptor (sddl.h)
    virtual BOOL ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        LPCWSTR              StringSecurityDescriptor,
        DWORD                StringSDRevision,
        PSECURITY_DESCRIPTOR *SecurityDescriptor,
        PULONG               SecurityDescriptorSize
    ) = 0;

    // Wrapper for LocalFree(winbase.h)
    virtual HLOCAL LocalFreeWrapper(HLOCAL hMem) = 0;

    // Wrapper for GetComputerName (winbase.h)
    virtual BOOL GetComputerNameWrapper(
        LPSTR   lpBuffer,
        LPDWORD nSize
    ) = 0;

    virtual std::vector<char> ReadFileIntoVectorWrapper(std::string file_path, bool* success) = 0;

    virtual void ClearFileWrapper(std::string file_path) = 0;

    virtual bool FileExistsWrapper(std::string file_path) = 0;

    // Wrapper for appending data string to file
    virtual void AppendStringWrapper(std::string file_path, std::string data) = 0;

    // Wrapper for getting a string representation of current time
    virtual std::string CurrentUtcTimeWrapper() = 0;
};

class WinApiWrapper : public WinApiWrapperInterface {
public:
    BOOL CloseHandleWrapper(HANDLE hObject);

    HANDLE CreateFileWrapper(
        LPCWSTR               lpFileName,
        DWORD                 dwDesiredAccess,
        DWORD                 dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD                 dwCreationDisposition,
        DWORD                 dwFlagsAndAttributes,
        HANDLE                hTemplateFile
    );

    DWORD GetFileAttributesWrapper(LPCWSTR lpFileName);

    DWORD GetLastErrorWrapper();

    BOOL WriteFileWrapper(
        HANDLE       hFile,
        LPCVOID      lpBuffer,
        DWORD        nNumberOfBytesToWrite,
        LPDWORD      lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    );

    void SleepWrapper(DWORD dwMilliseconds);

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

    BOOL ConnectNamedPipeWrapper(
        HANDLE       hNamedPipe,
        LPOVERLAPPED lpOverlapped
    );

    BOOL DisconnectNamedPipeWrapper(HANDLE hNamedPipe);

    BOOL ReadFileWrapper(
        HANDLE       hFile,
        LPVOID       lpBuffer,
        DWORD        nNumberOfBytesToRead,
        LPDWORD      lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
    );

    BOOL FlushFileBuffersWrapper(HANDLE hFile);

    BOOL ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
        LPCWSTR              StringSecurityDescriptor,
        DWORD                StringSDRevision,
        PSECURITY_DESCRIPTOR *SecurityDescriptor,
        PULONG               SecurityDescriptorSize
    );

    HLOCAL LocalFreeWrapper(HLOCAL hMem);

    BOOL GetComputerNameWrapper(
        LPSTR   lpBuffer,
        LPDWORD nSize
    );

    std::vector<char> ReadFileIntoVectorWrapper(std::string file_path, bool* success);

    void ClearFileWrapper(std::string file_path);

    bool FileExistsWrapper(std::string file_path);

    void AppendStringWrapper(std::string file_path, std::string data);

    std::string CurrentUtcTimeWrapper();
};