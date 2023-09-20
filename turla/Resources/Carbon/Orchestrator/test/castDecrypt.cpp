#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <vector>
#include "cast.h"
#include "osrng.h"
#include "pwdbased.h"
#include "sha.h"
#include "modes.h"
#include "filters.h"
#include "base64.h"

std::vector<unsigned char> key = {
    (unsigned char)0xf2, (unsigned char)0xd4, (unsigned char)0x56, (unsigned char)0x08, 
    (unsigned char)0x91, (unsigned char)0xbd, (unsigned char)0x94, (unsigned char)0x86, 
    (unsigned char)0x92, (unsigned char)0xc2, (unsigned char)0x8d, (unsigned char)0x2a,
    (unsigned char)0x93, (unsigned char)0x91, (unsigned char)0xe7, (unsigned char)0xd9
};

std::string VCharToStr(std::vector<char> vChar) {
    std::string s(vChar.begin(), vChar.end());
    return s;
}

std::vector<char> StrToVChar(std::string str) {
    std::vector<char> v(str.begin(), str.end());
    return v;
}

// Reference: Sample program from https://www.cryptopp.com/wiki/Block_Cipher
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

void decryptPrintLog(std::string filePath) {
    std::cout << "File: " << filePath << std::endl;

    std::ifstream fileStream(filePath, std::ios::binary);
    if (fileStream.good() && fileStream.is_open()) {
        std::vector<char> ciphertext((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());
        std::cout << "filesize: " << ciphertext.size() << std::endl;
        std::cout << "\n------------------------------------------------------------\n" << std::endl;
        try {
            std::cout << VCharToStr(Cast128Decrypt(ciphertext, key)) << std::endl;
            std::cout << "\n------------------------------------------------------------\n" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "Encountered exception when decrypting: " << std::string(e.what()) << std::endl;
        }
    } else {
        std::cout << "Unable to read the file " << filePath << std::endl;
    }
    
}

int main (int argc, char *argv[]) {
    if (argc != 2) {
        std::cout << "Usage: castDecrypt.exe <absolute path to file>";
        std::cout << "Enter \'1\' to exit." << std::endl;
        int x;
        std::cin >> x;
        return 0;
    }
    decryptPrintLog(std::string(argv[1]));
    std::cout << "Finished printing file. Enter \'1\' to exit.";
    int x;
    std::cin >> x;
}