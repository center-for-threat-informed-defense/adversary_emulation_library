/*
 * Handle file operations
 *
 */

#include "file_ops.h"

namespace fs = std::filesystem;

namespace file_ops {

    // Wrapper for CreateFileA (fileapi.h)
    HANDLE FileHandlerWrapper::CreateFileWrapper(
        LPCSTR                lpFileName,
        DWORD                 dwDesiredAccess,
        DWORD                 dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD                 dwCreationDisposition,
        DWORD                 dwFlagsAndAttributes,
        HANDLE                hTemplateFile
    ) {
        return CreateFileA(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile
        );
    }

    // Wrapper for ReadFile (fileapi.h)
    BOOL FileHandlerWrapper::ReadFileWrapper(
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

    // Wrapper for WriteFile (fileapi.h)
    BOOL FileHandlerWrapper::WriteFileWrapper(
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

    // Wrapper for DeleteFileA (fileapi.h)
    BOOL FileHandlerWrapper::DeleteFileWrapper(
        LPCSTR lpFileName
    ) {
        return DeleteFileA(lpFileName);
    }

    // Wrapper for GetFileSize (fileapi.h)
    DWORD FileHandlerWrapper::GetFileSizeWrapper(
        HANDLE  hFile,
        LPDWORD lpFileSizeHigh
    ) {
        return GetFileSize(hFile, lpFileSizeHigh);
    }

    // Wrapper for CloseHandle (handleapi.h)
    BOOL FileHandlerWrapper::CloseHandleWrapper(HANDLE hObject) {
        return CloseHandle(hObject);
    }

    std::vector<fs::directory_entry> FileHandlerWrapper::GetDirEntries(std::string src) {
        std::vector<fs::directory_entry> entries;
        for (auto& entry : fs::directory_iterator(src)) {
            entries.push_back(entry);
        }
        return entries;
    }

    // Wrapper for GetLastError (errhandlingapi.h)
    DWORD FileHandlerWrapper::GetLastErrorWrapper() {
        return GetLastError();
    }

    // Wrapper for remove file function (stdio.h)
    int FileHandlerWrapper::RemoveFileWrapper(const char* filename) {
        return remove(filename);
    }

    std::string GetFileNameFromPath(std::string path) {
        size_t pos = path.find_last_of("\\");
        if (pos == std::string::npos) {
            return path;
        }
        return path.substr(pos + 1);
    }

    // Read file_size number of bytes into buffer from the file represented by h_file. Return ERROR_SUCCESS on success, 
    // otherwise some error code. Assumes buffer is large enough to hold file_size bytes
    // Reference: https://stackoverflow.com/a/47878746
    DWORD ReadFileBytes(FileHandlerWrapperInterface* file_handler_wrapper, HANDLE h_file, char* buffer, DWORD file_size) {
        char* p_seek_buffer = buffer;
        DWORD remaining_bytes = file_size;
        DWORD bytes_read;
        while (remaining_bytes > 0) {
            if (!file_handler_wrapper->ReadFileWrapper(h_file, p_seek_buffer, remaining_bytes, &bytes_read, NULL)) {
                return file_handler_wrapper->GetLastErrorWrapper();
            }
            p_seek_buffer += bytes_read;
            remaining_bytes -= bytes_read;
        }
        return ERROR_SUCCESS;
    }

    // Write buffer_len number of bytes into buffer to the file represented by h_file. Return ERROR_SUCCESS on success, 
    // otherwise some error code.
    DWORD WriteFileBytes(FileHandlerWrapperInterface* file_handler_wrapper, HANDLE h_file, unsigned char* buffer, DWORD buffer_len) {
        unsigned char* p_seek_buffer = buffer;
        DWORD remaining_bytes = buffer_len;
        DWORD bytes_written;
        while (remaining_bytes > 0) {
            if (!file_handler_wrapper->WriteFileWrapper(h_file, p_seek_buffer, remaining_bytes, &bytes_written, NULL)) {
                return file_handler_wrapper->GetLastErrorWrapper();
            }
            p_seek_buffer += bytes_written;
            remaining_bytes -= bytes_written;
        }
        return ERROR_SUCCESS;
    }

    // Delete the given file. Return ERROR_SUCCESS on success, otherwise some error code.
    DWORD DeleteFileAtPath(FileHandlerWrapperInterface* file_handler_wrapper, LPCSTR file_to_delete) {
        if (!file_handler_wrapper->DeleteFileWrapper(file_to_delete)) {
            return file_handler_wrapper->GetLastErrorWrapper();
        }
        return ERROR_SUCCESS;
    }


} // namespace file_handler