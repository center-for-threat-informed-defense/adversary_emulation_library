#include "stego.h"
#include "base64.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>
#include <iterator>
#include <stdio.h>
#include <filesystem>

int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cout << "No filepath specified" << std::endl;
        exit(0);
    }
    std::string filepath = argv[1];

    if (argc < 3) {
        std::cout << "No key was provided" << std::endl;
        exit(0);
    }
    std::string key = argv[2];

    std::vector<unsigned char> bytes;

    if (!std::filesystem::exists(filepath)) {
        std::cout << "Invalid file path" << std::endl;
        exit(0);
    }
    std::ifstream file(filepath, std::ios_base::in | std::ios_base::binary);
    unsigned char ch = file.get();
    while (file.good()) {
        bytes.push_back(ch);
        ch = file.get();
    }
    size_t size = bytes.size();
    
    std::string encoded = base64_encode(reinterpret_cast<unsigned char*>(bytes.data()), bytes.size());

    char* image = (char*)malloc(encoded.size() + 1);
    memcpy(image, encoded.c_str(), encoded.size() + 1);

    int result = analyzeJPG(image, key, ".\\log.txt");

    if (!result) {
        std::cout << std::endl << "Image was unchanged" << std::endl;
    }
    else {
        std::vector<unsigned char> decoded;
        decoded = base64_decode(std::string(image)); //Decode the image

        typedef std::basic_ofstream<unsigned char, std::char_traits<unsigned char> > uofstream;
        std::ofstream fout("output.jpg", std::ios::out | std::ios::binary);
        fout.write((const char*)decoded.data(), decoded.size());

        std::cout << std::endl << "Output file written to: output.jpg" << std::endl;
    }
}