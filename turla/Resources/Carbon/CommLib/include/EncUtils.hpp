#pragma once
#include <memory>
#include <string>
#include <vector>

#include "WindowsWrappers.hpp"

#include "cryptopp/cast.h"
#include "cryptopp/config.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/base64.h"
#include "cryptopp/modes.h"
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/sha.h"
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/SecBlock.h"

#define FAIL_ENCRYPTION_EXCEPTION 0x3001
#define RSA_CIPHERTEXT_LENGTH 256

typedef unsigned char byte;

// CAST-128 utilities
namespace cast128_enc {

extern std::vector<unsigned char> kCast128Key;
std::vector<char> Cast128Encrypt(std::vector<char> plaintext, std::vector<unsigned char> key);
std::vector<char> Cast128Decrypt(std::vector<char> ciphertext, std::vector<unsigned char> key);

} // namespace

// RSA utilities
namespace rsa_enc {

extern std::string rsa_private_key_base64;

// Use base64-encoded RSA private key to decrypt using OAEP padding and SHA1
std::vector<unsigned char> RsaOaepSha1DecryptWithBase64Key(WinApiWrapperInterface* api_wrapper, std::vector<char> v_ciphertext, std::string base64_key);

} // namespace

std::pair<std::shared_ptr<byte[]>, size_t> DecryptServerTaskResp(WinApiWrapperInterface* api_wrapper, std::shared_ptr<byte[]> encrypted_blob, size_t encrypted_blob_len);

std::pair<std::shared_ptr<byte[]>, size_t> decodeValue(std::string encoded);
std::string decodeToString(std::string encoded);

std::string encodeData(byte* inputData, size_t dataSize);

template<int N>
inline std::string encodeData(byte (&inputData)[N]){return encodeData(&inputData[0], N);};

std::string encodeData(std::string inputData);