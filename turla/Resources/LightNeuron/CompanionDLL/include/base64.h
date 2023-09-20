// Code from: https://stackoverflow.com/a/13935718
// This code is a fork of Rene Nyffenegger's code: https://github.com/ReneNyffenegger/cpp-base64

#ifndef _BASE64_H_
#define _BASE64_H_

#include <vector>
#include <string>
typedef unsigned char BYTE;

std::string base64_encode(BYTE const* buf, unsigned int bufLen);
std::vector<BYTE> base64_decode(std::string const&);

#endif