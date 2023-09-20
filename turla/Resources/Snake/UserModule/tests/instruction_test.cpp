#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <windows.h>
#include "instruction.h"
#include "test_util.h"
#include <string>
#include <iostream>

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::StrEq;

// Text fixture for shared data
class InstructionTest : public ::testing::Test {
protected:
    MockApiWrapper mock_api_wrapper;
    std::string mock_timestamp = "2000-12-01 12:34:56";
    instruction::Instruction dummy_cmd_instruction;
    instruction::Instruction dummy_psh_instruction;
    instruction::Instruction dummy_proc_no_arg_instruction;
    instruction::Instruction dummy_proc_arg_instruction;
    instruction::Instruction dummy_payload_instruction;
    instruction::Instruction dummy_upload_instruction;
    instruction::Instruction dummy_logs_upload_instruction;
    std::wstring dummy_cmd_id = L"123456789012345678";
    std::wstring dummy_cmd_command = L"whoami /all";
    std::wstring dummy_psh_command = L"ZwBlAHQALQBjAGgAaQBsAGQAaQB0AGUAbQAgAHQAZQBzAHQAaQBuAGcA";
    std::wstring dummy_proc_path = L"C:\\path to\\my\\executable.exe";
    std::wstring dummy_proc_args = L"arg1 arg2 argwith|special&characters#@";
    std::string dummy_beacon_response_cmd = "ID123456789012345678#01 &d2hvYW1pIC9hbGw=#5&&&";
    std::string dummy_beacon_response_psh_cmd = "ID123456789012345678#02 &ZwBlAHQALQBjAGgAaQBsAGQAaQB0AGUAbQAgAHQAZQBzAHQAaQBuAGcA#11&testdomain\\testuser&&";
    std::string dummy_beacon_resp_proc_args = "ID123456789012345678#03 &C:\\path to\\my\\executable.exe&YXJnMSBhcmcyIGFyZ3dpdGh8c3BlY2lhbCZjaGFyYWN0ZXJzI0A=#20&&&";
    std::string dummy_beacon_resp_proc_no_args = "ID123456789012345678#03 &C:\\path to\\my\\executable.exe#19&&&";
    std::string dummy_payload_download_instr = "ID123456789012345678#04 &payloadname&dest_path#12&&&";
    std::string dummy_file_upload_instr = "ID123456789012345678#05 &C:\\path\\to\\file#12&&&";
    std::string dummy_logs_upload_instr = "ID123456789012345678#06 #13&&&";
    std::string resp_invalid_format = "ID1234561235678#01 &d2hvYW1pIC9hbGw=#5&&&";
    std::string resp_invalid_type = "ID123456789012345678#28 &d2hvYW1pIC9hbGw=#5&&&";
    std::string resp_no_arg = "ID123456789012345678#01 #5&&&";
    std::string resp_invalid_base64 = "ID123456789012345678#01 &@@#5&&&";
    std::string resp_missing_both_payload_args = "ID123456789012345678#04 #5&&&";
    std::string resp_missing_payload_arg = "ID123456789012345678#04 &payloadname#5&&&";

    void SetUp() override {
        dummy_cmd_instruction = instruction::Instruction();
        dummy_cmd_instruction.instruction_type = 1;
        dummy_cmd_instruction.sleep_time = 5;
        dummy_cmd_instruction.instruction_id = dummy_cmd_id;
        dummy_cmd_instruction.shell_command = dummy_cmd_command;
        dummy_cmd_instruction.runas_user = L"";
        dummy_cmd_instruction.original_str = dummy_beacon_response_cmd;

        dummy_psh_instruction = instruction::Instruction();
        dummy_psh_instruction.instruction_type = 2;
        dummy_psh_instruction.sleep_time = 11;
        dummy_psh_instruction.instruction_id = dummy_cmd_id;
        dummy_psh_instruction.shell_command = dummy_psh_command;
        dummy_psh_instruction.runas_user = L"testdomain\\testuser";
        dummy_psh_instruction.original_str = dummy_beacon_response_psh_cmd;

        dummy_proc_arg_instruction = instruction::Instruction();
        dummy_proc_arg_instruction.instruction_type = 3;
        dummy_proc_arg_instruction.sleep_time = 20;
        dummy_proc_arg_instruction.instruction_id = dummy_cmd_id;
        dummy_proc_arg_instruction.process_binary_path = dummy_proc_path;
        dummy_proc_arg_instruction.process_args = dummy_proc_args;
        dummy_proc_arg_instruction.runas_user = L"";
        dummy_proc_arg_instruction.original_str = dummy_beacon_resp_proc_args;

        dummy_proc_no_arg_instruction = instruction::Instruction();
        dummy_proc_no_arg_instruction.instruction_type = 3;
        dummy_proc_no_arg_instruction.sleep_time = 19;
        dummy_proc_no_arg_instruction.instruction_id = dummy_cmd_id;
        dummy_proc_no_arg_instruction.process_binary_path = dummy_proc_path;
        dummy_proc_no_arg_instruction.process_args = L"";
        dummy_proc_no_arg_instruction.runas_user = L"";
        dummy_proc_no_arg_instruction.original_str = dummy_beacon_resp_proc_no_args;

        dummy_payload_instruction = instruction::Instruction();
        dummy_payload_instruction.instruction_type = 4;
        dummy_payload_instruction.sleep_time = 12;
        dummy_payload_instruction.instruction_id = dummy_cmd_id;
        dummy_payload_instruction.file_to_download = std::wstring(L"payloadname");
        dummy_payload_instruction.download_dest_path = std::wstring(L"dest_path");
        dummy_payload_instruction.runas_user = L"";
        dummy_payload_instruction.original_str = dummy_payload_download_instr;

        dummy_upload_instruction = instruction::Instruction();
        dummy_upload_instruction.instruction_type = 5;
        dummy_upload_instruction.sleep_time = 12;
        dummy_upload_instruction.instruction_id = dummy_cmd_id;
        dummy_upload_instruction.file_to_upload = std::wstring(L"C:\\path\\to\\file");
        dummy_upload_instruction.runas_user = L"";
        dummy_upload_instruction.original_str = dummy_file_upload_instr;

        dummy_logs_upload_instruction = instruction::Instruction();
        dummy_logs_upload_instruction.instruction_type = 6;
        dummy_logs_upload_instruction.sleep_time = 13;
        dummy_logs_upload_instruction.instruction_id = dummy_cmd_id;
        dummy_logs_upload_instruction.runas_user = L"";
        dummy_logs_upload_instruction.original_str = dummy_logs_upload_instr;
    }
};

// Define our own matching logic to compare Instruction structs
MATCHER_P(CmdInstructionEq, pTarget, "") {
    return (pTarget->instruction_type == arg->instruction_type) &&
        (pTarget->sleep_time == arg->sleep_time) &&
        (pTarget->instruction_id.compare(arg->instruction_id) == 0) &&
        (pTarget->shell_command.compare(arg->shell_command) == 0) &&
        (pTarget->original_str.compare(arg->original_str) == 0);
}

MATCHER_P(ProcCmdInstructionEq, pTarget, "") {
    return (pTarget->instruction_type == arg->instruction_type) &&
        (pTarget->sleep_time == arg->sleep_time) &&
        (pTarget->instruction_id.compare(arg->instruction_id) == 0) &&
        (pTarget->process_binary_path.compare(arg->process_binary_path) == 0) &&
        (pTarget->process_args.compare(arg->process_args) == 0) &&
        (pTarget->original_str.compare(arg->original_str) == 0);
}

MATCHER_P(PayloadInstructionEq, pTarget, "") {
    return (pTarget->instruction_type == arg->instruction_type) &&
        (pTarget->sleep_time == arg->sleep_time) &&
        (pTarget->instruction_id.compare(arg->instruction_id) == 0) &&
        (pTarget->file_to_download.compare(arg->file_to_download) == 0) &&
        (pTarget->download_dest_path.compare(arg->download_dest_path) == 0) &&
        (pTarget->original_str.compare(arg->original_str) == 0);
}

MATCHER_P(UploadInstructionEq, pTarget, "") {
    return (pTarget->instruction_type == arg->instruction_type) &&
        (pTarget->sleep_time == arg->sleep_time) &&
        (pTarget->instruction_id.compare(arg->instruction_id) == 0) &&
        (pTarget->file_to_upload.compare(arg->file_to_upload) == 0) &&
        (pTarget->original_str.compare(arg->original_str) == 0);
}

TEST_F(InstructionTest, TestExtractInstructionSuccess) {
    instruction::Instruction cmd_instr = instruction::Instruction();
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, dummy_beacon_response_cmd, &cmd_instr), ERROR_SUCCESS);
    EXPECT_THAT(&cmd_instr, CmdInstructionEq(&dummy_cmd_instruction));

    instruction::Instruction psh_instr = instruction::Instruction();
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, dummy_beacon_response_psh_cmd, &psh_instr), ERROR_SUCCESS);
    EXPECT_THAT(&psh_instr, CmdInstructionEq(&dummy_psh_instruction));

    instruction::Instruction proc_no_arg_instr = instruction::Instruction();
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, dummy_beacon_resp_proc_no_args, &proc_no_arg_instr), ERROR_SUCCESS);
    EXPECT_THAT(&proc_no_arg_instr, ProcCmdInstructionEq(&dummy_proc_no_arg_instruction));

    instruction::Instruction proc_instr = instruction::Instruction();
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, dummy_beacon_resp_proc_args, &proc_instr), ERROR_SUCCESS);
    EXPECT_THAT(&proc_instr, ProcCmdInstructionEq(&dummy_proc_arg_instruction));

    instruction::Instruction payload_instr = instruction::Instruction();
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, dummy_payload_download_instr, &payload_instr), ERROR_SUCCESS);
    EXPECT_THAT(&payload_instr, PayloadInstructionEq(&dummy_payload_instruction));

    instruction::Instruction upload_instr = instruction::Instruction();
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, dummy_file_upload_instr, &upload_instr), ERROR_SUCCESS);
    EXPECT_THAT(&upload_instr, UploadInstructionEq(&dummy_upload_instruction));

    instruction::Instruction logs_upload_instr = instruction::Instruction();
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, dummy_logs_upload_instr, &logs_upload_instr), ERROR_SUCCESS);
    EXPECT_THAT(&logs_upload_instr, UploadInstructionEq(&dummy_logs_upload_instruction));
}

TEST_F(InstructionTest, TestExtractInstructionFail) {
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).Times(7).WillRepeatedly(Return(mock_timestamp));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(StrEq(logging::kC2LogFile), _)).Times(7);
    
    instruction::Instruction received = instruction::Instruction();
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, resp_invalid_format, &received), FAIL_INVALID_INSTRUCTION_RESPONSE);
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, resp_invalid_type, &received), FAIL_UNSUPPORTED_INSTRUCTION_TYPE);
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, resp_invalid_type, &received), FAIL_UNSUPPORTED_INSTRUCTION_TYPE);
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, resp_no_arg, &received), FAIL_MISSING_INSTRUCTION_ARGS);
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, resp_invalid_base64, &received), FAIL_INVALID_BASE64);
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, resp_missing_both_payload_args, &received), FAIL_MISSING_INSTRUCTION_ARGS);
    EXPECT_EQ(instruction::ExtractInstructionInformation(&mock_api_wrapper, resp_missing_payload_arg, &received), FAIL_INVALID_INSTRUCTION_ARG_FORMAT);
}
