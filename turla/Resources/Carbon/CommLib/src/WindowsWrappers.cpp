#include "WindowsWrappers.hpp"
#include <filesystem>

BOOL WinApiWrapper::CloseHandleWrapper(HANDLE hObject) {
    return CloseHandle(hObject);
}

HANDLE WinApiWrapper::CreateFileWrapper(
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

DWORD WinApiWrapper::GetFileAttributesWrapper(LPCWSTR lpFileName) {
    return GetFileAttributesW(lpFileName);
}

DWORD WinApiWrapper::GetLastErrorWrapper() {
    return GetLastError();
}

BOOL WinApiWrapper::WriteFileWrapper(
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

// Wrapper for Sleep function (synchapi.h)
void WinApiWrapper::SleepWrapper(DWORD dwMilliseconds) {
    return Sleep(dwMilliseconds);
}

// Wrapper for CreateNamedPipe (winbase.h)
HANDLE WinApiWrapper::CreateNamedPipeWrapper(
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

// Wrapper for ConnectNamedPipe (namedpipeapi.h)
BOOL WinApiWrapper::ConnectNamedPipeWrapper(
    HANDLE       hNamedPipe,
    LPOVERLAPPED lpOverlapped
) {
    return ConnectNamedPipe(hNamedPipe, lpOverlapped);
}

// Wrapper for DisconnectNamedPipe (namedpipeapi.h)
BOOL WinApiWrapper::DisconnectNamedPipeWrapper(HANDLE hNamedPipe) {
    return DisconnectNamedPipe(hNamedPipe);
}

// Wrapper for ReadFile (fileapi.h)
BOOL WinApiWrapper::ReadFileWrapper(
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

// Wrapper for FlushFileBuffers (fileapi.h)
BOOL WinApiWrapper::FlushFileBuffersWrapper(HANDLE hFile) {
    return FlushFileBuffers(hFile);
}

// Wrapper for ConvertStringSecurityDescriptorToSecurityDescriptor (sddl.h)
BOOL WinApiWrapper::ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
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

// Wrapper for LocalFree (winbase.h)
HLOCAL WinApiWrapper::LocalFreeWrapper(HLOCAL hMem) {
    return LocalFree(hMem);
}

// Wrapper for GetComputerName (winbase.h)
BOOL WinApiWrapper::GetComputerNameWrapper(
    LPSTR   lpBuffer,
    LPDWORD nSize
) {
    return GetComputerNameA(lpBuffer, nSize);
}

std::vector<char> WinApiWrapper::ReadFileIntoVectorWrapper(std::string file_path, bool* success) {
    std::ifstream file_stream(file_path, std::ios::binary);
    if (file_stream.good() && file_stream.is_open()) {
        *success = TRUE;
        return std::vector<char>((std::istreambuf_iterator<char>(file_stream)), std::istreambuf_iterator<char>());
    } else {
        *success = FALSE;
        return std::vector<char>(0);
    }
}

void WinApiWrapper::ClearFileWrapper(std::string file_path) {
    std::ofstream ofs;
    ofs.open(file_path, std::ofstream::out | std::ofstream::trunc);
    ofs.close();
}

bool WinApiWrapper::FileExistsWrapper(std::string file_path) {
    return std::filesystem::exists(file_path);
}

// Append data string to file
void WinApiWrapper::AppendStringWrapper(std::string file_path, std::string data) {
    std::ofstream out_file;
    out_file.open(std::filesystem::path(file_path), std::ios_base::app);
    out_file << data;
}

// Get current UTC time
std::string WinApiWrapper::CurrentUtcTimeWrapper() {
    struct tm time_info;
    char time_buffer[100];
    time_t raw_time = time(NULL);
    if (gmtime_s(&time_info, &raw_time) == ERROR_SUCCESS) {
         strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", &time_info);
        return std::string(time_buffer);
    }
    return std::string("2000-01-01 00:00:00");
}