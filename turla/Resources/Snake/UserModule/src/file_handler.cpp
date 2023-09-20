/*
 * Handle file operations
 * 
 * CTI references:
 * [1] https://artemonsecurity.com/snake_whitepaper.pdf
 */

#include "file_handler.h"

namespace fs = std::filesystem;

namespace file_handler {

std::wstring GetFileNameFromPath(std::wstring path) {
    size_t pos = path.find_last_of(L"\\");
    if (pos == std::wstring::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

// Read file_size number of bytes into buffer from the file represented by h_file. Return ERROR_SUCCESS on success, 
// otherwise some error code. Assumes buffer is large enough to hold file_size bytes
// Reference: https://stackoverflow.com/a/47878746
DWORD ReadFileBytes(ApiWrapperInterface* api_wrapper, HANDLE h_file, char* buffer, DWORD file_size) {
    char* p_seek_buffer = buffer;
    DWORD remaining_bytes = file_size;
    DWORD bytes_read;
    while (remaining_bytes > 0) {
        if (!api_wrapper->ReadFileWrapper(h_file, p_seek_buffer, remaining_bytes, &bytes_read, NULL)) {
            return api_wrapper->GetLastErrorWrapper();
        }
        p_seek_buffer += bytes_read;
        remaining_bytes -= bytes_read;
    }
    return ERROR_SUCCESS;
}

// Write buffer_len number of bytes into buffer to the file represented by h_file. Return ERROR_SUCCESS on success, 
// otherwise some error code.
DWORD WriteFileBytes(ApiWrapperInterface* api_wrapper, HANDLE h_file, unsigned char* buffer, DWORD buffer_len) {
    unsigned char* p_seek_buffer = buffer;
    DWORD remaining_bytes = buffer_len;
    DWORD bytes_written;
    while (remaining_bytes > 0) {
        if (!api_wrapper->WriteFileWrapper(h_file, p_seek_buffer, remaining_bytes, &bytes_written, NULL)) {
            return api_wrapper->GetLastErrorWrapper();
        }
        p_seek_buffer += bytes_written;
        remaining_bytes -= bytes_written;
    }
    return ERROR_SUCCESS;
}

} // namespace file_handler
