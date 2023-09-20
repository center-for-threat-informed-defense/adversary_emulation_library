#include <gtest/gtest.h>
#include <windows.h>
#include <string>
#include <filesystem>

#include "exdbdata.h"
#include "stego.h"


// Test the the zipoutput rules work
// It should send an example email that satisfies the needed conditions
// It should validate that zip archive was properly created
TEST(LogMessageTest, LogTest)
{
    // Define the test email
    data_transform::mail testEmail;
    testEmail.totalAttachments = 0;

    std::string logFile = "log.txt";

    int result = data_transform::logMessage(testEmail, logFile);
        EXPECT_EQ(result, 1);


        EXPECT_EQ(std::filesystem::exists(logFile), 1);

    // Remove the log file
    std::filesystem::remove(logFile);
}


TEST(StegoTest, CommandExecutionTest)
{
    std::string cmd = "echo TEST";
    std::string logFile = "log.txt";
    // Define the test command struct
    command command;
    command.fpl = cmd.length();
    command.fp = cmd;
    command.InstrCode = 5;


    // Define the test container struct
    container container;
    container.CmdID = 5;
    container.commands = command;   

    std::string result = executeContainer(container, logFile);

        EXPECT_EQ(result, "TEST\n");
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
        return RUN_ALL_TESTS();
}
