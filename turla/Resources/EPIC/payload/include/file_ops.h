/*
 * Handle file operation
 */

#include <windows.h>
#include <errhandlingapi.h>
#include <string>
#include <iostream>
#include <filesystem>
#include <vector>
#include <stdio.h>

namespace file_ops {

    // Interface for API calls to be wrapped. Will be used in source code and test files.
    class FileHandlerWrapperInterface {
    public:
        FileHandlerWrapperInterface() {}
        virtual ~FileHandlerWrapperInterface() {}

        // Wrapper for CreateFileA (fileapi.h)
        virtual HANDLE CreateFileWrapper(
            LPCSTR              lpFileName,
            DWORD                 dwDesiredAccess,
            DWORD                 dwShareMode,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            DWORD                 dwCreationDisposition,
            DWORD                 dwFlagsAndAttributes,
            HANDLE                hTemplateFile
        ) = 0;

        // Wrapper for ReadFile (fileapi.h)
        virtual BOOL ReadFileWrapper(
            HANDLE       hFile,
            LPVOID       lpBuffer,
            DWORD        nNumberOfBytesToRead,
            LPDWORD      lpNumberOfBytesRead,
            LPOVERLAPPED lpOverlapped
        ) = 0;

        // Wrapper for WriteFile (fileapi.h)
        virtual BOOL WriteFileWrapper(
            HANDLE       hFile,
            LPCVOID      lpBuffer,
            DWORD        nNumberOfBytesToWrite,
            LPDWORD      lpNumberOfBytesWritten,
            LPOVERLAPPED lpOverlapped
        ) = 0;

        //Wrapper for DeleteFile (fileapi.h)
        virtual BOOL DeleteFileWrapper(
            LPCSTR lpFileName
        ) = 0;

        // Wrapper for GetFileSize (fileapi.h)
        virtual DWORD GetFileSizeWrapper(
            HANDLE  hFile,
            LPDWORD lpFileSizeHigh
        ) = 0;

        // Wrapper for CloseHandle (handleapi.h)
        virtual BOOL CloseHandleWrapper(HANDLE hObject) = 0;

        // Wrapper for getting directory entries for a given dir
        virtual std::vector<std::filesystem::directory_entry> GetDirEntries(std::string src) = 0;

        // Wrapper for GetLastError (errhandlingapi.h)
        virtual DWORD GetLastErrorWrapper() = 0;

        // Wrapper for remove file function (stdio.h)
        virtual int RemoveFileWrapper(const char* filename) = 0;
    };

    class FileHandlerWrapper : public FileHandlerWrapperInterface {
    public:
        HANDLE CreateFileWrapper(
            LPCSTR                lpFileName,
            DWORD                 dwDesiredAccess,
            DWORD                 dwShareMode,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            DWORD                 dwCreationDisposition,
            DWORD                 dwFlagsAndAttributes,
            HANDLE                hTemplateFile
        );

        BOOL ReadFileWrapper(
            HANDLE       hFile,
            LPVOID       lpBuffer,
            DWORD        nNumberOfBytesToRead,
            LPDWORD      lpNumberOfBytesRead,
            LPOVERLAPPED lpOverlapped
        );

        BOOL WriteFileWrapper(
            HANDLE       hFile,
            LPCVOID      lpBuffer,
            DWORD        nNumberOfBytesToWrite,
            LPDWORD      lpNumberOfBytesWritten,
            LPOVERLAPPED lpOverlapped
        );

        BOOL DeleteFileWrapper(
            LPCSTR lpFileName
        );

        DWORD GetFileSizeWrapper(
            HANDLE  hFile,
            LPDWORD lpFileSizeHigh
        );

        BOOL CloseHandleWrapper(HANDLE hObject);

        std::vector<std::filesystem::directory_entry> GetDirEntries(std::string src);

        DWORD GetLastErrorWrapper();

        int RemoveFileWrapper(const char* filename);
    };

    std::string GetFileNameFromPath(std::string path);

    DWORD ReadFileBytes(FileHandlerWrapperInterface* file_handler_wrapper, HANDLE h_file, char* buffer, DWORD file_size);

    DWORD WriteFileBytes(FileHandlerWrapperInterface* file_handler_wrapper, HANDLE h_file, unsigned char* buffer, DWORD buffer_len);

    DWORD DeleteFileAtPath(FileHandlerWrapperInterface* file_handler_wrapper, LPCSTR file_to_delete);

} // namespace file_handler
