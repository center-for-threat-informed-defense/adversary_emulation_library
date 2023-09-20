#include "../include/mutex.h"

namespace mutex {

std::vector<std::string> vMutexNames; // vector to hold the names of the mutexes we'll create

// get the names of the mutexes from the vars set by 'orchestrator' and put them in the vector
void PopulateNamesVector() {
    vMutexNames.push_back(orchestrator::lpLogAccessName);
    vMutexNames.push_back(orchestrator::lpELogAccessName);
    vMutexNames.push_back(orchestrator::lpFileUploadName);
    vMutexNames.push_back(orchestrator::lpTasksName);
    vMutexNames.push_back(orchestrator::lpConfigName);
}

// actually make the mutexes
int CreateMutexes() {
    for (std::string mutexName: vMutexNames) {
        try {
            static Mutex mutex{util::StringtoLPCWSTR(mutexName)};
            orchestrator::mMutexMap.emplace(mutexName, mutex);

            std::ostringstream stream;
            stream << "[MTX] CreateMutexes handle to " << mutexName;
            util::logEncrypted(orchestrator::regLogPath, stream.str());
        } catch(const std::exception& e) {
            util::logEncrypted(orchestrator::errorLogPath, "[ERROR-MTX] CreateMutexs failed. GetLastError: " + GetLastError());
            util::logEncrypted(orchestrator::errorLogPath, "[ERROR-MTX] CreateMutexs failed. Exception: " + std::string(e.what()));
            return FAIL_MUTEX_CREATE_MUTEX;
        }
    }

    util::logEncrypted(orchestrator::regLogPath, "[MTX] Successfully created mutexes");
    return ERROR_SUCCESS;
}

// Get the names of the mutexes to create, and then create them
int MutexManager() {
    int retVal;

    PopulateNamesVector();

    retVal = CreateMutexes();
    if (retVal != ERROR_SUCCESS) {
        return retVal;
    }

    return ERROR_SUCCESS;
}

} // namespace mutex