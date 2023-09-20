#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>
#include <string>
#include <winerror.h>
#include "file_handler.h"

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::PrintToString;

namespace fs = std::filesystem;

std::string targetConfigPath("C:\\Mock Program Files\\Windows NT\\setuplst.xml");
std::string targetLoaderDllPath("C:\\Mock Sysroot\\system32\\mressvc.dll");
std::string targetOrchDllPath("C:\\Mock Program Files\\Windows NT\\MSSVCCFG.dll");
std::string targetCommsDllPath("C:\\Mock Program Files\\Windows NT\\msxhlp.dll");

// Mock the wrapper functions for unit tests
class MockFileHandlerCallWrapper : public file_handler::FileHandlerCallWrapperInterface {
public:
	virtual ~MockFileHandlerCallWrapper(){}
	
	MOCK_METHOD1(GetEnvironmentVariableWrapper, std::string(const char* env_var));
	MOCK_METHOD3(WriteDataToFile, int(std::string filepath, const unsigned char* data, std::streamsize n));
	MOCK_METHOD1(DirectoryExists, bool(fs::path dir));
	MOCK_METHOD4(ConvertStringSecurityDescriptorToSecurityDescriptorWrapper, BOOL(
        LPCWSTR              StringSecurityDescriptor,
        DWORD                StringSDRevision,
        PSECURITY_DESCRIPTOR *SecurityDescriptor,
        PULONG               SecurityDescriptorSize
    ));
	MOCK_METHOD0(GetLastErrorWrapper, DWORD());
	MOCK_METHOD1(LocalFreeWrapper, HLOCAL(HLOCAL hMem));
	MOCK_METHOD2(CreateDirectoryWrapper, BOOL(
		LPCWSTR               lpPathName,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes
	));
};

// Test fixture for shared data
class FileHandlerTest : public ::testing::Test {
protected:
    MockFileHandlerCallWrapper mock_fh_call_wrapper;
	LPCSTR mock_base_dir = "C:\\Mock Program Files\\Windows NT";
	LPCSTR mock_program_files_dir = "C:\\Mock Program Files";
	LPCWSTR dacl_str = L"D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)";
	LPCWSTR tasks_dir_path = L"C:\\Mock Program Files\\Windows NT\\0511";
	LPCWSTR tasks_output_dir_path = L"C:\\Mock Program Files\\Windows NT\\2028";
	LPCWSTR nls_dir_path = L"C:\\Mock Program Files\\Windows NT\\Nlts";
};

// Define our own matching logic to compare filesystem paths.
MATCHER_P(FsPathEq, want_path, "") { 
	return (PrintToString(arg) == PrintToString(want_path)); 
}

TEST_F(FileHandlerTest, SuccessSetBaseDirectory) {
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("PROGRAMFILES")))
		.WillOnce(Return(std::string(mock_program_files_dir)));
	EXPECT_CALL(mock_fh_call_wrapper, DirectoryExists(FsPathEq(mock_base_dir)))
		.WillOnce(Return(true));
	EXPECT_CALL(mock_fh_call_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
		StrEq(dacl_str),
		SDDL_REVISION_1,
        _,
        NULL
	)).Times(3).WillRepeatedly(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, LocalFreeWrapper(_)).Times(3).WillRepeatedly(Return(HANDLE(NULL)));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_output_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(nls_dir_path),
		_
	)).WillOnce(Return(TRUE));
	
	// Base working directory should not be defined yet.
	ASSERT_EQ(file_handler::base_working_directory, "");
	ASSERT_EQ(file_handler::SetBaseWorkingDirectory(&mock_fh_call_wrapper), ERROR_SUCCESS);
	ASSERT_EQ(file_handler::base_working_directory, mock_base_dir);
	
}

TEST_F(FileHandlerTest, FailSetBaseDirectoryNonExisting) {
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("PROGRAMFILES")))
		.WillOnce(Return(std::string("C:\\Program Files")));
	EXPECT_CALL(mock_fh_call_wrapper, DirectoryExists(FsPathEq("C:\\Program Files\\Windows NT")))
		.WillOnce(Return(false));
		
	ASSERT_EQ(file_handler::base_working_directory, "");
	ASSERT_EQ(file_handler::SetBaseWorkingDirectory(&mock_fh_call_wrapper), FAIL_TARGET_BASE_DIR_DNE);
	ASSERT_EQ(file_handler::base_working_directory, "");
	
}

TEST_F(FileHandlerTest, FailSetBaseDirectoryFailGetEnv) {
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("PROGRAMFILES")))
		.WillOnce(Return(std::string("")));
	EXPECT_CALL(mock_fh_call_wrapper, DirectoryExists(_)).Times(0);
	
	ASSERT_EQ(file_handler::SetBaseWorkingDirectory(&mock_fh_call_wrapper), FAIL_ENV_DNE_PROG_FILE);
	ASSERT_EQ(file_handler::base_working_directory, "");
}

TEST_F(FileHandlerTest, SuccessDropComponentsAndGetLoaderDllPath) {
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("PROGRAMFILES")))
		.WillOnce(Return(std::string(mock_program_files_dir)));
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("SYSTEMROOT")))
		.WillOnce(Return(std::string("C:\\Mock Sysroot")));
	EXPECT_CALL(mock_fh_call_wrapper, DirectoryExists(_))
		.WillOnce(Return(true));
	EXPECT_CALL(mock_fh_call_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
		StrEq(dacl_str),
		SDDL_REVISION_1,
        _,
        NULL
	)).Times(3).WillRepeatedly(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, LocalFreeWrapper(_)).Times(3).WillRepeatedly(Return(HANDLE(NULL)));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_output_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(nls_dir_path),
		_
	)).WillOnce(Return(TRUE));

	// WriteDataToFile must be called exactly 4 times with the specified args
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(_, _, _))
		.Times(0);
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetConfigPath), file_handler::kConfigFileData, file_handler::kConfigFileDataLen))
		.WillOnce(Return(ERROR_SUCCESS));
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetLoaderDllPath), file_handler::kLoaderDllData, file_handler::kLoaderDllDataLen))
		.WillOnce(Return(ERROR_SUCCESS));
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetOrchDllPath), file_handler::kOrchestratorDllData, file_handler::kOrchestratorDllDataLen))
		.WillOnce(Return(ERROR_SUCCESS));
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetCommsDllPath), file_handler::kCommsDllData, file_handler::kCommsDllDataLen))
		.WillOnce(Return(ERROR_SUCCESS));
	
	EXPECT_EQ(file_handler::SetBaseWorkingDirectory(&mock_fh_call_wrapper), ERROR_SUCCESS);
	EXPECT_TRUE(file_handler::GetLoaderDllPath().empty());
	EXPECT_EQ(file_handler::base_working_directory, mock_base_dir);
	EXPECT_EQ(file_handler::DropComponents(&mock_fh_call_wrapper), ERROR_SUCCESS);
	EXPECT_EQ(file_handler::GetLoaderDllPath(), targetLoaderDllPath);
}

TEST_F(FileHandlerTest, FailDropConfigNoBaseDir) {
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(_, _, _))
		.Times(0);

	EXPECT_EQ(file_handler::base_working_directory, "");
	EXPECT_EQ(file_handler::DropComponents(&mock_fh_call_wrapper), FAIL_DROP_CONFIG_BASE_DIR_NOT_INIT);
	EXPECT_TRUE(file_handler::GetLoaderDllPath().empty());
}

TEST_F(FileHandlerTest, FailDropConfigFailWrite) {
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("PROGRAMFILES")))
		.WillOnce(Return(std::string(mock_program_files_dir)));
	EXPECT_CALL(mock_fh_call_wrapper, DirectoryExists(_))
		.WillOnce(Return(true));

	EXPECT_CALL(mock_fh_call_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
		StrEq(dacl_str),
		SDDL_REVISION_1,
        _,
        NULL
	)).Times(3).WillRepeatedly(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, LocalFreeWrapper(_)).Times(3).WillRepeatedly(Return(HANDLE(NULL)));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_output_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(nls_dir_path),
		_
	)).WillOnce(Return(TRUE));

	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(_, _, _))
		.Times(0);
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetConfigPath), file_handler::kConfigFileData, file_handler::kConfigFileDataLen))
		.WillOnce(Return(FAIL_OPEN_FILE_WRITE));
	
	EXPECT_EQ(file_handler::SetBaseWorkingDirectory(&mock_fh_call_wrapper), ERROR_SUCCESS);
	EXPECT_EQ(file_handler::DropComponents(&mock_fh_call_wrapper), FAIL_DROP_CONFIG_FILE_WRITE);
	EXPECT_TRUE(file_handler::GetLoaderDllPath().empty());
}

TEST_F(FileHandlerTest, FailDropLoaderNoSysrootEnvVar) {
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("PROGRAMFILES")))
		.WillOnce(Return(std::string(mock_program_files_dir)));
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("SYSTEMROOT")))
		.WillOnce(Return(std::string("")));
	EXPECT_CALL(mock_fh_call_wrapper, DirectoryExists(_))
		.WillOnce(Return(true));
	EXPECT_CALL(mock_fh_call_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
		StrEq(dacl_str),
		SDDL_REVISION_1,
        _,
        NULL
	)).Times(3).WillRepeatedly(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, LocalFreeWrapper(_)).Times(3).WillRepeatedly(Return(HANDLE(NULL)));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_output_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(nls_dir_path),
		_
	)).WillOnce(Return(TRUE));

	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(_, _, _))
		.Times(0);
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetConfigPath), file_handler::kConfigFileData, file_handler::kConfigFileDataLen))
		.WillOnce(Return(ERROR_SUCCESS));
	
	EXPECT_EQ(file_handler::SetBaseWorkingDirectory(&mock_fh_call_wrapper), ERROR_SUCCESS);
	EXPECT_EQ(file_handler::DropComponents(&mock_fh_call_wrapper), FAIL_DROP_LOADER_ENV_DNE_SYS_ROOT);
	EXPECT_TRUE(file_handler::GetLoaderDllPath().empty());
}

TEST_F(FileHandlerTest, FailDropLoaderFailWrite) {
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("PROGRAMFILES")))
		.WillOnce(Return(std::string(mock_program_files_dir)));
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("SYSTEMROOT")))
		.WillOnce(Return(std::string("C:\\Mock Sysroot")));
	EXPECT_CALL(mock_fh_call_wrapper, DirectoryExists(_))
		.WillOnce(Return(true));
	EXPECT_CALL(mock_fh_call_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
		StrEq(dacl_str),
		SDDL_REVISION_1,
        _,
        NULL
	)).Times(3).WillRepeatedly(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, LocalFreeWrapper(_)).Times(3).WillRepeatedly(Return(HANDLE(NULL)));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_output_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(nls_dir_path),
		_
	)).WillOnce(Return(TRUE));

	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(_, _, _))
		.Times(0);
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetConfigPath), file_handler::kConfigFileData, file_handler::kConfigFileDataLen))
		.WillOnce(Return(ERROR_SUCCESS));
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetLoaderDllPath), file_handler::kLoaderDllData, file_handler::kLoaderDllDataLen))
		.WillOnce(Return(FAIL_OPEN_FILE_WRITE));
	
	EXPECT_EQ(file_handler::SetBaseWorkingDirectory(&mock_fh_call_wrapper), ERROR_SUCCESS);
	EXPECT_EQ(file_handler::DropComponents(&mock_fh_call_wrapper), FAIL_DROP_LOADER_FILE_WRITE);
	EXPECT_TRUE(file_handler::GetLoaderDllPath().empty());
}

TEST_F(FileHandlerTest, FailDropOrchFailWrite) {
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("PROGRAMFILES")))
		.WillOnce(Return(std::string(mock_program_files_dir)));
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("SYSTEMROOT")))
		.WillOnce(Return(std::string("C:\\Mock Sysroot")));
	EXPECT_CALL(mock_fh_call_wrapper, DirectoryExists(_))
		.WillOnce(Return(true));
	EXPECT_CALL(mock_fh_call_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
		StrEq(dacl_str),
		SDDL_REVISION_1,
        _,
        NULL
	)).Times(3).WillRepeatedly(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, LocalFreeWrapper(_)).Times(3).WillRepeatedly(Return(HANDLE(NULL)));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_output_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(nls_dir_path),
		_
	)).WillOnce(Return(TRUE));

	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(_, _, _))
		.Times(0);
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetConfigPath), file_handler::kConfigFileData, file_handler::kConfigFileDataLen))
		.WillOnce(Return(ERROR_SUCCESS));
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetLoaderDllPath), file_handler::kLoaderDllData, file_handler::kLoaderDllDataLen))
		.WillOnce(Return(ERROR_SUCCESS));
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetOrchDllPath), file_handler::kOrchestratorDllData, file_handler::kOrchestratorDllDataLen))
		.WillOnce(Return(FAIL_OPEN_FILE_WRITE));
	
	EXPECT_EQ(file_handler::SetBaseWorkingDirectory(&mock_fh_call_wrapper), ERROR_SUCCESS);
	EXPECT_EQ(file_handler::DropComponents(&mock_fh_call_wrapper), FAIL_DROP_ORCH_FILE_WRITE);
	EXPECT_EQ(file_handler::GetLoaderDllPath(), targetLoaderDllPath);
}

TEST_F(FileHandlerTest, FailDropCommsLibFailWrite) {
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("PROGRAMFILES")))
		.WillOnce(Return(std::string(mock_program_files_dir)));
	EXPECT_CALL(mock_fh_call_wrapper, GetEnvironmentVariableWrapper(StrEq("SYSTEMROOT")))
		.WillOnce(Return(std::string("C:\\Mock Sysroot")));
	EXPECT_CALL(mock_fh_call_wrapper, DirectoryExists(_))
		.WillOnce(Return(true));
	EXPECT_CALL(mock_fh_call_wrapper, ConvertStringSecurityDescriptorToSecurityDescriptorWrapper(
		StrEq(dacl_str),
		SDDL_REVISION_1,
        _,
        NULL
	)).Times(3).WillRepeatedly(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, LocalFreeWrapper(_)).Times(3).WillRepeatedly(Return(HANDLE(NULL)));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(tasks_output_dir_path),
		_
	)).WillOnce(Return(TRUE));
	EXPECT_CALL(mock_fh_call_wrapper, CreateDirectoryWrapper(
		StrEq(nls_dir_path),
		_
	)).WillOnce(Return(TRUE));

	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(_, _, _))
		.Times(0);
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetConfigPath), file_handler::kConfigFileData, file_handler::kConfigFileDataLen))
		.WillOnce(Return(ERROR_SUCCESS));
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetLoaderDllPath), file_handler::kLoaderDllData, file_handler::kLoaderDllDataLen))
		.WillOnce(Return(ERROR_SUCCESS));
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetOrchDllPath), file_handler::kOrchestratorDllData, file_handler::kOrchestratorDllDataLen))
		.WillOnce(Return(ERROR_SUCCESS));
	EXPECT_CALL(mock_fh_call_wrapper, WriteDataToFile(StrEq(targetCommsDllPath), file_handler::kCommsDllData, file_handler::kCommsDllDataLen))
		.WillOnce(Return(FAIL_OPEN_FILE_WRITE));

	EXPECT_EQ(file_handler::SetBaseWorkingDirectory(&mock_fh_call_wrapper), ERROR_SUCCESS);
	EXPECT_EQ(file_handler::DropComponents(&mock_fh_call_wrapper), FAIL_DROP_COMMS_FILE_WRITE);
	EXPECT_EQ(file_handler::GetLoaderDllPath(), targetLoaderDllPath);
}
