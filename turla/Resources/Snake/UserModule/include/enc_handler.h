/*
 * Handle encryption for user module
 */

#ifndef SNAKE_USERLAND_ENCRYPTION_H_
#define SNAKE_USERLAND_ENCRYPTION_H_

#include <cstring>
#include <vector>
#include "api_wrappers.h"
#include "cast.h"
#include "pwdbased.h"
#include "sha.h"
#include "modes.h"
#include "filters.h"

namespace enc_handler {
extern const char* kXorKey;
extern const size_t kXorLen;
extern const std::string kDefaultPassword;
extern const std::string kDefaultSalt;

std::vector<char> Cast128Encrypt(ApiWrapperInterface* api_wrapper, std::vector<char> plaintext, std::vector<unsigned char> key);

std::vector<char> Cast128Decrypt(std::vector<char> ciphertext, std::vector<unsigned char> key);

std::vector<unsigned char> GenerateCast128Key(std::string password, std::string salt);

} // namespace

// XOR n bytes of data starting at input. Will update in-place
void XorInPlace(unsigned char* input, size_t n);

void XorInPlace(char* input, size_t n);

#endif
