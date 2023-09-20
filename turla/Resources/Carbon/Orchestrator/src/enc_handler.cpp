#include "..\include\enc_handler.h"

namespace enc_handler {

CryptoPP::AutoSeededRandomPool prng;

// Reference: https://cryptopp.com/wiki/Initialization_Vector
std::vector<CryptoPP::byte> GenerateIv(size_t size) {
    // Generate IV
    std::vector<CryptoPP::byte> iv = std::vector<CryptoPP::byte>(size);
    prng.GenerateBlock(&iv[0], size);
    return iv;
}

/*
 * Cast128Encrypt:
 *      About:
 *          Encrypt a vector of characters with Cast128 using a given key.
 *          Used to encrypt data when outputting a file.
 *      MITRE ATT&CK Tecnhiques:
 *          T1027: Obfuscated Files or Information
 *      Result:
 *      	Returns an encrypted vector of characters if no errors are encountered.
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *          https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 *          https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra
 *      Other References:
 *          Sample program from https://www.cryptopp.com/wiki/Block_Cipher     
 */
std::vector<char> Cast128Encrypt(std::vector<char> plaintext, std::vector<unsigned char> key) {
    size_t key_size = key.size();
    
    // Verify provided key size
    if (key_size != CryptoPP::CAST128::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("Invalid key size.");
    }

    // Set key and IV. Note that IV and block size are both 8 bytes.
    CryptoPP::byte key_bytes[CryptoPP::CAST128::DEFAULT_KEYLENGTH];
    CryptoPP::byte iv_bytes[CryptoPP::CAST128::BLOCKSIZE];

    std::vector<CryptoPP::byte> iv = GenerateIv(CryptoPP::CAST128::BLOCKSIZE);
    
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
 *          Decrypt a vector of characters with Cast128 using a given key.
 *          Used to read the encrypted config file and files created by the comms lib.
 *      MITRE ATT&CK Tecnhiques:
 *          T1140: Deobfuscate/Decode Files or Information
 *      Result:
 *      	Returns a decrypted vector of characters if no errors are encountered.
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *          https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 *          https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra
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

} // namespace
