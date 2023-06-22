#include <iostream>

#include "clientPP.hpp"

int main(int argc, const char * argv[]) {

    // Figure 9 - https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
    // int dwRandomTimeSleep = 0;
    // time_t dwTimeSeed;
    // int dwRandomValue;
    // while ( 1 ) {
    //     if ( clientPP::osInfo(dwRandomTimeSleep))
    //         clientPP::runClient(dwRandomTimeSleep);
    //     dwTimeSeed = time(0LL);
    //     srand(dwTimeSeed);
    //     dwRandomValue = rand();
    //     dwRandomTimeSleep = dwRandomValue;
    // }

    std::cout << "Hello, World!\n";
    return 0;
}
