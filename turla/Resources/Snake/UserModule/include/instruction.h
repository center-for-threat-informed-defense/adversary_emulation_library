#ifndef SNAKE_USERLAND_INSTRUCTION_H_
#define SNAKE_USERLAND_INSTRUCTION_H_

#include <string>
#include "api_wrappers.h"
#include "logging.h"
#include "usermodule_errors.h"

#define TASK_EMPTY 0
#define TASK_CMD_EXECUTE 1
#define TASK_PSH_EXECUTE 2
#define TASK_PROC_EXECUTE 3
#define TASK_FILE_DOWNLOAD 4
#define TASK_FILE_UPLOAD 5
#define TASK_LOGS_UPLOAD 6
#define INSTRUCTION_ID_LEN 18

namespace instruction {

struct Instruction {
    int instruction_type;
    int sleep_time;
    int reserved_option_1;
    int reserved_option_2;
    std::wstring instruction_id;
    std::wstring shell_command;
    std::wstring file_to_download;
    std::wstring download_dest_path;
    std::wstring file_to_upload;
    std::wstring process_binary_path;
    std::wstring process_args;
    std::wstring runas_user; // user to execute process under
    std::string original_str; // original string representation
};

DWORD ExtractInstructionInformation(ApiWrapperInterface* api_wrapper, std::string response, Instruction* received_instruction);

} // namespace instruction

#endif