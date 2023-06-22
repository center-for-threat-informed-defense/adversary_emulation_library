#ifndef clientPP_hpp
#define clientPP_hpp

#include <stdio.h>
#include <string>
#include <stdint.h>
#include <stdbool.h>

class clientPP
{
public:
    std::string pathProcess;
    int8_t      clientID[24];
    std::string strClientID;
    int64_t     installTime;
    void        *urlRequest;
    int8_t      keyDecrypt[24];
    int64_t     timeCheckRequestTimeout;
    int         posDomain;
    std::string domain;
    int         count;

    static bool osInfo(int dwRandomTimeSleep);

    static void runClient(int dwRandomTimeSleep);

    static int8_t createClientID();
};


#endif /* clientPP_hpp */
