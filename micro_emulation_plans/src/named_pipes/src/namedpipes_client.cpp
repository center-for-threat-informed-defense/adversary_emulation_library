/*
Modified from:
Client Program for Win32 Named Pipes Example.
Copyright (C) 2012 Peter R. Bloomfield.

For an exaplanation of the code, see the associated blog post:
http://avidinsight.uk/2012/03/introduction-to-win32-named-pipes-cpp/

This code is made freely available under the MIT open source license
(see accompanying LICENSE file for details).
It is intended only for educational purposes. and is provide as-is with no
guarantee about its reliability, correctness, or suitability for any purpose.


INSTRUCTIONS:

Run the accompanying server program first.
Before closing it, run this client program.
*/

#include <iostream>
#include <windows.h>
#include <stringapiset.h> // Provides MultiByteToWideChar()

using namespace std;

const char* options = "Options:\n"\
                "1 - Cobalt Strike Artifact Kit pipe\n"\
                "2 - Cobalt Strike Lateral Movement (psexec_psh) pipe\n"\
                "3 - Cobalt Strike SSH (postex_ssh) pipe\n"\
                "4 - Cobalt Strike post-exploitation pipe (4.2 and later)\n"\
                "5 - Cobalt Strike post-exploitation pipe (before 4.2)\n";

const char *pipe_names[5] = {
    "\\\\.\\pipe\\MSSE-a09-server",
    "\\\\.\\pipe\\status_4f",
    "\\\\.\\pipe\\postex_ssh_ad90",
    "\\\\.\\pipe\\postex_b83a",
    "\\\\.\\pipe\\29fe3b7c1"
};

wstring const_char_to_utf8(const char* to_convert) {
    /**
     * @brief Convert a const char* with the system encoding
     * into a UTF-8 wstring.
     */

    // First pass gets the size of the const char* after conversion
    int converted_size = MultiByteToWideChar(
        CP_ACP,  // Represents the "system encoding"
        MB_COMPOSITE,
        to_convert,
        strlen(to_convert),
        nullptr,
        0
    );
    wstring wStrTo(converted_size, 0);
    // Second pass performs the UTF-8 conversion
    MultiByteToWideChar(
        CP_UTF8,
        0,
        &to_convert[0],
        strlen(to_convert),
        &wStrTo[0],
        converted_size
    );
    return wStrTo;
}

void WriteOutput(const char* to_print) {
    /**
     * @brief Output-printing function for debugging.
     * Does not work when this exe is executed by namedpipes_executor
     * because there will be overlapping output with the server.
     */
    cout << to_print << endl;
}

HANDLE connect_pipe(wstring pipe_name) {
    /**
     * @brief Return a file handle for the named pipe.
     */
    return CreateFileW(
        pipe_name.data(), // name of the pipe
        GENERIC_READ, // only need read access
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
        );
}

int main (int argc, const char **argv)
{
    const char* pipe_option;
    HANDLE pipe;

    // Create a pipe to send data, based on user-selected type.
    if (argc == 1) {
        WriteOutput("Too few options. Specify a kind of pipe to create.\n");
        WriteOutput(options);
        return 1;
    }
    if (argc == 2) {
        if (strcmp(argv[1], "1") == 0) {
            pipe_option = pipe_names[0];
        } else if (strcmp(argv[1], "2") == 0) {
            pipe_option = pipe_names[1];
        } else if (strcmp(argv[1], "3") == 0) {
            pipe_option = pipe_names[2];
        } else if (strcmp(argv[1], "4") == 0) {
            pipe_option = pipe_names[3];
        } else if (strcmp(argv[1], "5") == 0) {
            pipe_option = pipe_names[4];
        } else {
            char errbuffer[46];
            int cx = snprintf(
                errbuffer, 45,
                "Invalid pipe type number: %s (must be 1-5).\n",
                argv[1]);
            WriteOutput(errbuffer);
            WriteOutput(options);
            return 1;
        }
    } else {
        char errbuffer[48 + sizeof(argc) + 1];
        int cx = snprintf(
            errbuffer, 48 + sizeof(argc),
            "Invalid number of arguments: %s (must be 1-5).\n",
            argc
        );
        WriteOutput(errbuffer);
        WriteOutput(options);
        return 1;
    }

    wstring pipe_name = const_char_to_utf8(pipe_option);
    pipe = connect_pipe(pipe_name);

    if (pipe == INVALID_HANDLE_VALUE) {
        // Get error code with GetLastError().
        char errbuffer[40 + sizeof(DWORD) + 1];
        int cx = snprintf(
            errbuffer, 40 + sizeof(DWORD),
            "Failed to connect to pipe (error: %d).\n",
            GetLastError()
        );
        WriteOutput(errbuffer);
        return 1;
    }

    // WriteOutput("Reading data from pipe...\n");

    // The read operation will block until there is data to read
    wchar_t buffer[128];
    DWORD numBytesRead = 0;
    BOOL result = ReadFile(
        pipe,
        buffer, // the data from the pipe will be put here
        127 * sizeof(wchar_t), // number of bytes allocated
        &numBytesRead, // this will store number of bytes actually read
        NULL // not using overlapped IO
        );

    if (result) {
        buffer[numBytesRead / sizeof(wchar_t)] = '\0'; // null terminate the string

        char readStatusBuffer[26 + int(sizeof(numBytesRead)) + 1];
        int cx = snprintf(
            readStatusBuffer,
            26 + int(sizeof(numBytesRead)),
            "Number of bytes read: %d\n",
            numBytesRead);
        // WriteOutput(readStatusBuffer);
        
        char msgStatusBuffer[13 + int(sizeof(buffer)) + 1];
        cx = snprintf(msgStatusBuffer, (13 + int(sizeof(buffer))), "Message: %s\n", buffer);
        // WriteOutput(msgStatusBuffer);
    } else {
        WriteOutput("Failed to read data from the pipe.\n");
    }

    // WriteOutput("Done.\n");
    // WriteOutput("The client will remain connected to the pipe until the server closes it, or wait 20 more seconds.\n");

    Sleep(20000);

    // Close our pipe handle
    CloseHandle(pipe);

    return 0;
}