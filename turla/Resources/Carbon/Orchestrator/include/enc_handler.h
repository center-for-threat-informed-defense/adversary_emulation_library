#ifndef CAST_ENCRYPTION_H_
#define CAST_ENCRYPTION_H_

#include <cstring>
#include <vector>
#include "cast.h"
#include "osrng.h"
#include "pwdbased.h"
#include "sha.h"
#include "modes.h"
#include "filters.h"

namespace enc_handler {

std::vector<char> Cast128Encrypt(std::vector<char> plaintext, std::vector<unsigned char> key);
std::vector<char> Cast128Decrypt(std::vector<char> ciphertext, std::vector<unsigned char> key);

} // namespace

#endif