#include <iostream>

#include "ClientPP.hpp"

int main(int argc, const char * argv[]) {

    // drop embedded, encrypted CommsLib.dylib to cwd
    // find and decrypt CommsLib.dylib to /tmp/store

    // load CommsLib.dylib
    //      https://stackoverflow.com/q/43184544
    //      - does ClientPP have to call dlopen/dlclose?
    //      - does ClientPP need to open/close every time it tries to HTTP request?
    // call dlopen to load dylib
    // load symbol (HTTP request function) from dylib
    // close dylib

    // Figure 9 - https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
    // int dwRandomTimeSleep = 0;
    // time_t dwTimeSeed;
    // int dwRandomValue;
    // while ( 1 ) {
    //     if ( ClientPP::osInfo(dwRandomTimeSleep))
    //         ClientPP::runClient(dwRandomTimeSleep);
    //     dwTimeSeed = time(0LL);
    //     srand(dwTimeSeed);
    //     dwRandomValue = rand();
    //     dwRandomTimeSleep = dwRandomValue;
    // }

    std::cout << "Hello, World!\n";
    return 0;
}
