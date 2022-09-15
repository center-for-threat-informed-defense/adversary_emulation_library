#include <iostream>
#include <string>
#include <windows.h>
#include <stringapiset.h> // Provides MultiByteToWideChar()

using namespace std;

std::string example = "\nSyntax: --pipe <pipe_type> --server <server_exe> --client <client_exe>\n"\
                "\tnamedpipes_executor.exe --pipe 1 --server namedpipes_server.exe --client namedpipes_client.exe\n"\
                "If you built this with custom server or client executable names, use those names instead.\n"\
                "\t--pipe <pipe_type>: Optional. Number indicating the type of pipe to create. "\
                "Refer to the \"pipe_type options\" for acceptable values.\n"\
                "\t--server <server_exe>: Optional. Relative path to the server executable.\n"\
                "\t--client <client_exe>: Optional. Relative path to the client executable.\n"\
                "\nThe flags can appear in any order.\n";
                
std::string options = "\npipe_type options:\n"\
                "1 - Cobalt Strike Artifact Kit pipe\n"\
                "2 - Cobalt Strike Lateral Movement (psexec_psh) pipe\n"\
                "3 - Cobalt Strike SSH (postex_ssh) pipe\n"\
                "4 - Cobalt Strike post-exploitation pipe (4.2 and later)\n"\
                "5 - Cobalt Strike post-exploitation pipe (before 4.2)\n";

std::string default_message = "\nDefaults are:\n";
std::string default_pipe = "\tpipe_type: 1\n";
std::string default_client = "\tclient_exe: namedpipes_client.exe\n";
std::string default_server = "\tserver_exe: namedpipes_server.exe\n";

std::string default_run_message = "Running with defaults:\n";

const char* default_server_exe = "namedpipes_server.exe";
const char* default_client_exe = "namedpipes_client.exe";

const char *pipe_names[5] = {
    "\\\\.\\pipe\\MSSE-a09-server",
    "\\\\.\\pipe\\status_4f",
    "\\\\.\\pipe\\postex_ssh_ad90",
    "\\\\.\\pipe\\postex_b83a",
    "\\\\.\\pipe\\29fe3b7c1"
};

const char* default_pipe_type = "1";
const int default_pipe_index = 0;

wstring const_char_to_utf8(const char* to_convert) {
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

BOOL create_server(wstring command) {
    // Manage the server
    STARTUPINFOW server_si;
    PROCESS_INFORMATION server_pi;
    ZeroMemory(&server_si, sizeof(server_si));
    server_si.cb = sizeof(server_si);
    ZeroMemory(&server_pi, sizeof(server_pi));

    BOOL proc_err = CreateProcessW(
        NULL, // lpApplicationName
        command.data(), // lpCommandLine
        NULL, // lpProcessAttributes
        NULL, // lpThreadAttributes
        FALSE, // bInheritHandles
        0, // dwCreationFlags
        NULL, // lpEnvironment
        NULL, // lpCurrentDirectory
        &server_si,
        &server_pi
    );

    return proc_err;
}

BOOL create_client(wstring command) {
    // Manage the client
    STARTUPINFOW client_si;
    PROCESS_INFORMATION client_pi;
    ZeroMemory(&client_si, sizeof(client_si));
    client_si.cb = sizeof(client_si);
    ZeroMemory(&client_pi, sizeof(client_pi));

    BOOL proc_err = CreateProcessW(
        NULL, // lpApplicationName
        command.data(), // lpCommandLine
        NULL, // lpProcessAttributes
        NULL, // lpThreadAttributes
        FALSE, // bInheritHandles
        0, // dwCreationFlags
        NULL, // lpEnvironment
        NULL, // lpCurrentDirectory
        &client_si,
        &client_pi
    );

    return proc_err;
}

std::string help_message() {
    return example + options + default_message \
        + default_pipe + default_client + default_server;
};

std::string get_args_error_string(int argc, int max_args, const char** argv) {
    // Use (argc - 1) because the executable name is the first arg
    // but the user doesn't specify that.
    std::string retval = std::string("User supplied ") \
        + std::to_string(argc - 1) + " arguments, max was " \
        + std::to_string(max_args - 1) + ".\n";
    retval += "Arguments were:\n";

    for (int i = 0; i < argc; i++) {
        retval += std::string(" ") + std::string(argv[i]);
    }
    retval += "\n";

    return retval;
}

const char* get_pipe_option_string(const char* pipe_arg) {
    if (strcmp(pipe_arg, "1") == 0) {
        return "1";
    } else if (strcmp(pipe_arg, "2") == 0) {
        return "2";
    } else if (strcmp(pipe_arg, "3") == 0) {
        return "3";
    } else if (strcmp(pipe_arg, "4") == 0) {
        return "4";
    } else if (strcmp(pipe_arg, "5") == 0) {
        return "5";
    } else {
        return NULL;
    }
}

const char* get_pipe_name(const char* int_string) {
    if (strcmp(int_string, "1") == 0) {
        return pipe_names[0];
    } else if (strcmp(int_string, "2") == 0) {
        return pipe_names[1];
    } else if (strcmp(int_string, "3") == 0)  {
        return pipe_names[2];
    } else if (strcmp(int_string, "4") == 0)  {
        return pipe_names[3];
    } else if (strcmp(int_string, "5") == 0)  {
        return pipe_names[4];
    } else {
        return NULL;
    }
}

int main(int argc, const char **argv)
{
    // Modify this to match your maximum number of arguments.
    // This count includes the mandatory argv[0], which is the executable name.
    const int max_args = 7;

    const char* pipe_option;
    bool pipe_set = false;
    const char* server_exe;
    bool server_set = false;
    const char* client_exe;
    bool client_set = false;
    // This gets appended to user input later.
    wstring space = const_char_to_utf8(" ");

    // Pass a value to the client and server to specify the pipe type.
    if (argc == 1) {
        // Default pipe type
        pipe_option = get_pipe_option_string(default_pipe_type);
        pipe_set = true;
        server_exe = default_server_exe;
        server_set = true;
        client_exe = default_client_exe;
        client_set = true;
        std::cout << default_run_message << endl;
    } else if (argc == 2) {
        if (strcmp(argv[1], "help") == 0) {
            std::cout << help_message() << endl;
            return 0;
        } else {
            std::cout << get_args_error_string(argc, max_args, argv) << endl;
            std::cout << help_message() << endl;
            return 1;
        }
    } else if (argc == 3 || argc == 5 || argc == 7) {
        // Process the first setting.
        // In practice, the "set more than once." cases should not occur when
        // processing the first setting.
        if (argc >= 3) {
            if (strcmp(argv[1], "--pipe") == 0) {
                // Process pipe arg.
                if (pipe_set) {
                    std::cout << "Bad arguments: pipe set more than once.\n" << endl;
                    std::cout << get_args_error_string(argc, max_args, argv) << endl;
                    std::cout << help_message() << endl;
                    return 1;
                } else {
                    const char* pipe_option_string = get_pipe_option_string(argv[2]);
                    if (pipe_option_string == NULL) {
                        std::cout << "Invalid pipe type number: " << argv[2] << " (must be 1-5).\n" << endl;
                        std::cout << get_args_error_string(argc, max_args, argv) << endl;
                        std::cout << help_message() << endl;
                        return 1;
                    } else {
                        pipe_option = pipe_option_string;
                        pipe_set = true;                        
                    }
                }
            } else if (strcmp(argv[1], "--server") == 0) {
                // Process server arg.
                if (server_set) {
                    std::cout << "Bad arguments: server set more than once.\n" << endl;
                    std::cout << get_args_error_string(argc, max_args, argv) << endl;
                    std::cout << help_message() << endl;
                    return 1;
                } else {
                    server_exe = argv[2];
                    server_set = true;
                }
            } else if (strcmp(argv[1], "--client") == 0) {
                // Process client arg.
                if (client_set) {
                    std::cout << "Bad arguments: client set more than once.\n" << endl;
                    std::cout << get_args_error_string(argc, max_args, argv) << endl;
                    std::cout << help_message() << endl;
                    return 1;
                } else {
                    client_exe = argv[2];
                    client_set = true;
                }
            } else {
                std::cout << "Invalid first parameter name: " << argv[1] << "\n" << endl;
                std::cout << get_args_error_string(argc, max_args, argv) << endl;
                std::cout << help_message() << endl;
                return 1;
            }

            // std::cout << "Processed 1st parameter" << endl;
        }

        // Process the second setting.
        if (argc >= 5) {
            if (strcmp(argv[3], "--pipe") == 0) {
                // Process pipe arg.
                if (pipe_set) {
                    std::cout << "Bad arguments: pipe set more than once.\n" << endl;
                    std::cout << get_args_error_string(argc, max_args, argv) << endl;
                    std::cout << help_message() << endl;
                    return 1;
                } else {
                    const char* pipe_option_string = get_pipe_option_string(argv[4]);
                    if (pipe_option_string == NULL) {
                        std::cout << "Invalid pipe type number: " << argv[4] << " (must be 1-5).\n";
                        std::cout << get_args_error_string(argc, max_args, argv) << endl;
                        std::cout << help_message() << endl;
                        return 1;
                    } else {
                        pipe_option = pipe_option_string;
                        pipe_set = true;                        
                    }
                }
            } else if (strcmp(argv[3], "--server") == 0) {
                // Process server arg.
                if (server_set) {
                    std::cout << "Bad arguments: server set more than once.\n" << endl;
                    std::cout << get_args_error_string(argc, max_args, argv) << endl;
                    std::cout << help_message() << endl;
                    return 1;
                } else {
                    server_exe = argv[4];
                    server_set = true;
                }
            } else if (strcmp(argv[3], "--client") == 0) {
                // Process client arg.
                if (client_set) {
                    std::cout << "Bad arguments: client set more than once.\n" << endl;
                    std::cout << get_args_error_string(argc, max_args, argv) << endl;
                    std::cout << help_message() << endl;
                    return 1;
                } else {
                    client_exe = argv[4];
                    client_set = true;
                }
            } else {
                std::cout << "Invalid second parameter name: " << argv[3] << "\n" << endl;
                std::cout << get_args_error_string(argc, max_args, argv) << endl;
                std::cout << help_message() << endl;
                return 1;
            }

            // std::cout << "Processed 2nd parameter" << endl;
        }

        // Process the third setting.
        if (argc == 7) {
            if (strcmp(argv[5], "--pipe") == 0) {
                // Process pipe arg.
                if (pipe_set) {
                    std::cout << "Bad arguments: pipe set more than once." << endl;
                    std::cout << get_args_error_string(argc, max_args, argv) << endl;
                    std::cout << help_message() << endl;
                    return 1;
                } else {
                    const char* pipe_option_string = get_pipe_option_string(argv[6]);
                    if (pipe_option_string == NULL) {
                        std::cout << "Invalid pipe type number: " << argv[6] << " (must be 1-5).\n" << endl;
                        std::cout << help_message() << endl;
                        return 1;
                    } else {
                        pipe_option = pipe_option_string;
                        pipe_set = true;                        
                    }
                }
            } else if (strcmp(argv[5], "--server") == 0) {
                // Process server arg.
                if (server_set) {
                    std::cout << "Bad arguments: server set more than once." << endl;
                    std::cout << get_args_error_string(argc, max_args, argv) << endl;
                    std::cout << help_message() << endl;
                    return 1;
                } else {
                    server_exe = argv[6];
                    server_set = true;
                }
            } else if (strcmp(argv[5], "--client") == 0) {
                // Process client arg.
                if (client_set) {
                    std::cout << "Bad arguments: client set more than once." << endl;
                    std::cout << get_args_error_string(argc, max_args, argv) << endl;
                    std::cout << help_message() << endl;
                    return 1;
                } else {
                    client_exe = argv[6];
                    client_set = true;
                }
            } else {
                std::cout << "Invalid second parameter name: " << argv[5] << "\n" << endl;
                std::cout << get_args_error_string(argc, max_args, argv) << endl;
                std::cout << help_message() << endl;
                return 1;
            }

            // With 7 args, all options should have been set.
            if (!(pipe_set && server_set && client_set)) {
                std::cout << "Bad arguments: maximum arguments given, but unable to set some values." << endl;
                std::cout << get_args_error_string(argc, max_args, argv) << endl;
                std::cout << help_message() << endl;
                return 1;
            }

            // std::cout << "Processed 3rd parameter" << endl;
        }

        // At this point we've processed all user-specified options,
        // but some settings may remain undefined. If so, set the defaults.
        if (argc == 3 || argc == 5) {
            // Set defaults for whatever settings remain un-set.
            // std::cout << "Setting un-set defaults." << endl;
            if (!pipe_set) {
                pipe_option = default_pipe_type;
                pipe_set = true;
                // std::cout << "Set default pipe_type: " << pipe_option << endl;       
            }
            if (!server_set) {
                server_exe = default_server_exe;
                server_set = true;
                // std::cout << "Set default server_exe: " << server_exe << endl;       
            }
            if (!client_set) {
                client_exe = default_client_exe;
                client_set = true;
                // std::cout << "Set default client_exe: " << client_exe << endl;    
            }
        }

    } else {
        std::cout << get_args_error_string(argc, max_args, argv) << endl;
        std::cout << help_message() << endl;
        return 1;
    }

    std::cout << "Using these settings:" << endl;
    std::cout << "\tpipe_type: " << pipe_option << " (" << get_pipe_name(pipe_option) << ")" << endl;
    std::cout << "\tserver_exe: " << server_exe << endl;
    std::cout << "\tclient_exe: " << client_exe << "\n" << endl;

    wstring server_pipe_type = const_char_to_utf8(pipe_option);
    wstring wserver_exe = const_char_to_utf8(server_exe);
    wstring wclient_exe = const_char_to_utf8(client_exe);

    wstring wserver_cmd = wserver_exe + space + server_pipe_type;
    wstring wclient_cmd = wclient_exe + space + server_pipe_type;

    std::wcout << L"Starting server with command: " << wserver_cmd << endl;
    BOOL server_proc_err = create_server(wserver_cmd);
    if (!server_proc_err) {
        std::cout << \
            "CreateProcess failed for server (error: " \
            << GetLastError() << ").\n" << endl;
        return 1;
    }

    std::wcout << L"Starting client with command: " << wclient_cmd << endl;
    BOOL client_proc_err = create_client(wclient_cmd);
    if (!client_proc_err) {
        std::cout << 
            "CreateProcess failed for client (error: " \
            << GetLastError() << ").\n" << endl;
        return 1;
    }

    std::cout << "Waiting for server and client to finish..."<< endl;
    std::cout << "The server will write \"*** Hello Pipe World ***\" to the pipe." << endl;
    std::cout << "The client will read from the server, wait 20 seconds, and close its connection." << endl;
    std::cout << "The server will wait 30 seconds and close the pipe." << endl;
    // Wait more than 30 seconds so that anything after the Sleep() prints last:
    Sleep(35000);

    std::cout << "Executor done.\n" << endl;
}
