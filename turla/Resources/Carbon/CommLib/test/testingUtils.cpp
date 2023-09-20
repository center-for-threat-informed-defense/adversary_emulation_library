#include <filesystem>
#include <iostream>
#include "testing.h"
#include "EncUtils.hpp"

bool writeEncryptedConfig(){
    if (std::filesystem::exists(encryptedDummyConfigFile)) {
        std::cout << "encrypted config file already exists." << std::endl;
        return true;
    }

    std::ifstream ifs(originalDummyConfigFile, std::ifstream::in);
    if (!ifs.good()) {
        std::cerr << "Unable to open unencrypted dummy config file" << std::endl;
        return false;
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    auto dummyFileAsString = buffer.str();
    ifs.close();
    std::vector<char> dummyFileAsVector{dummyFileAsString.begin(), dummyFileAsString.end()};
    auto encrypFileContents = cast128_enc::Cast128Encrypt(dummyFileAsVector, cast128_enc::kCast128Key);

    std::ofstream encrypFile{encryptedDummyConfigFile, std::ios::binary | std::ios::out | std::ios::trunc};
    if (!encrypFile.good()) {
        std::cerr << "Unable to create or open encrypted dummy config file" << std::endl;
        return false;
    }
    encrypFile.write(&encrypFileContents[0], encrypFileContents.size());
    encrypFile.close();

    return true;
}


