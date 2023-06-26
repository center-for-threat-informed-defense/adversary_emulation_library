#include <iostream>
#include "Comms.hpp"
#include "CommsPriv.hpp"

void HelloWorld(const char * s)
{
    CommsPriv *theObj = new CommsPriv;
    theObj->HelloWorldPriv(s);
    delete theObj;
};

void CommsPriv::HelloWorldPriv(const char * s) 
{
    std::cout << s << std::endl;
};

