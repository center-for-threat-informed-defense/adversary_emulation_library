#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <testing.h>
#include <configFile.h>
#include "EncUtils.hpp"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Return;
using ::testing::StrEq;

// Test fixture for shared data
class TestUtils : public ::testing::Test {
protected:
    MockWinApiWrapper mock_api_wrapper;
};

TEST_F(TestUtils, TestStringToNetworkAddress){
    // Checking multiple failing paths

    std::list<std::string> failStrings {
        "", ":", ":80", "::"
    };
    for (auto failStr : failStrings){
        std::cout << "checking " << failStr << std::endl;
        auto failOut = stringToNetworkAddress(failStr);
        if (failOut != nullptr) {
            auto [ addr, port, resourcePath ] = *failOut.get();
            FAIL() << "Should have failed with " << failStr << ", instead had these values: \"" << addr << "\" : \"" << port << "\" : \"" << resourcePath << "\"";
        }
        SUCCEED();
    }

    // Checking simple path with IP
    std::cout << "Checking simple path with IP" << std::endl;
    
    std::string inputAddr = "1.1.1.1";
    int inputPort = 8080;
    std::string inputResourcePath = "/path/to/resource";

    std::string fullInputPath = inputAddr + ":" + std::to_string(inputPort) + ":" + inputResourcePath;

    auto passOut = stringToNetworkAddress(fullInputPath);
    ASSERT_NE(passOut, nullptr) << "Got null for " << fullInputPath;

    auto [ addr, port, resourcePath ] = *passOut.get();
    EXPECT_THAT(addr, StrEq(inputAddr)) << "For " << fullInputPath <<", got address as " << addr;
    EXPECT_EQ(port, inputPort) << "For " << fullInputPath <<", got port as " << port;
    EXPECT_THAT(resourcePath, StrEq(inputResourcePath)) << "For " << fullInputPath << ",  got resourcePath as " << resourcePath;


    // Checking simple path with url
    std::cout << "Checking simple path with url" << std::endl;
    
    inputAddr = "https://google.com";
    inputPort = 8080;
    inputResourcePath = "/path/to/resource";

    fullInputPath = inputAddr + ":" + std::to_string(inputPort) + ":" + inputResourcePath;

    passOut = stringToNetworkAddress(fullInputPath);
    ASSERT_NE(passOut, nullptr) << "Got null for " << fullInputPath;

    std::tie( addr, port, resourcePath ) = *passOut.get();

    EXPECT_THAT(addr, StrEq(inputAddr)) << "For " << fullInputPath <<", got address as " << addr;
    EXPECT_EQ(port, inputPort) << "For " << fullInputPath <<", got port as " << port;
    EXPECT_THAT(resourcePath, StrEq(inputResourcePath)) << "For " << fullInputPath << ",  got resourcePath as " << resourcePath;

    // Checking pass path with IP, no port
    std::cout << "Checking pass path with IP, no port" << std::endl;
    
    inputAddr = "1.1.1.1";
    inputResourcePath = "/path/to/resource";

    fullInputPath = inputAddr + ":" + inputResourcePath;

    passOut = stringToNetworkAddress(fullInputPath);
    ASSERT_NE(passOut, nullptr) << "Got null for " << fullInputPath;

    std::tie( addr, port, resourcePath ) = *passOut.get();
    EXPECT_THAT(addr, StrEq(inputAddr)) << "For " << fullInputPath <<", got address as " << addr;
    // The returned port should be the default port.
    EXPECT_EQ(port, defaultPort) << "For " << fullInputPath <<", got port as " << port;
    EXPECT_THAT(resourcePath, StrEq(inputResourcePath)) << "For " << fullInputPath << ",  got resourcePath as " << resourcePath;

    // Checking simple path with IP, no resource path
    std::cout << "Checking simple path with IP, no resource path" << std::endl;
    
    inputAddr = "1.1.1.1";
    inputPort = 8080;

    fullInputPath = inputAddr + ":" + std::to_string(inputPort) ;

    passOut = stringToNetworkAddress(fullInputPath);
    ASSERT_NE(passOut, nullptr) << "Got null for " << fullInputPath;

    std::tie( addr, port, resourcePath ) = *passOut.get();
    EXPECT_THAT(addr, StrEq(inputAddr)) << "For " << fullInputPath <<", got address as " << addr;
    EXPECT_EQ(port, inputPort) << "For " << fullInputPath <<", got port as " << port;
    // The returned resource path should be the default one.
    EXPECT_THAT(resourcePath, StrEq(defaultHttpResource)) << "For " << fullInputPath << ",  got resourcePath as " << resourcePath;

    // Checking simple path with IP, no port, no resource path
    std::cout << "Checking simple path with IP, no port, no resource path" << std::endl;
    
    inputAddr = "1.1.1.1";

    fullInputPath = inputAddr;

    passOut = stringToNetworkAddress(fullInputPath);
    ASSERT_NE(passOut, nullptr) << "Got null for " << fullInputPath;

    std::tie( addr, port, resourcePath ) = *passOut.get();
    EXPECT_THAT(addr, StrEq(inputAddr)) << "For " << fullInputPath <<", got address as " << addr;
    // The returned port should be the default one.
    EXPECT_EQ(port, defaultPort) << "For " << fullInputPath <<", got port as " << port;
    // The returned resource path should be the default one.
    EXPECT_THAT(resourcePath, StrEq(defaultHttpResource)) << "For " << fullInputPath << ",  got resourcePath as " << resourcePath;

    
    // Checking simple path with default values
    std::cout << "Checking simple path with url" << std::endl;
    
    inputAddr = kTestingServer;
    inputPort = 80;
    inputResourcePath = "/javascript/view.php";

    fullInputPath = inputAddr + ":" + std::to_string(inputPort) + ":" + inputResourcePath;

    passOut = stringToNetworkAddress(fullInputPath);
    ASSERT_NE(passOut, nullptr) << "Got null for " << fullInputPath;

    std::tie( addr, port, resourcePath ) = *passOut.get();

    EXPECT_THAT(addr, StrEq(inputAddr)) << "For " << fullInputPath <<", got address as " << addr;
    EXPECT_EQ(port, inputPort) << "For " << fullInputPath <<", got port as " << port;
    EXPECT_THAT(resourcePath, StrEq(inputResourcePath)) << "For " << fullInputPath << ",  got resourcePath as " << resourcePath;

}

TEST_F(TestUtils, TestParseConfigFile){
    // Catch all logging messages
    EXPECT_CALL(mock_api_wrapper, CurrentUtcTimeWrapper()).WillRepeatedly(Return(""));
    EXPECT_CALL(mock_api_wrapper, AppendStringWrapper(_, _)).Times(AtLeast(0));

    // Convert test config file to encrypted test config file
    ASSERT_TRUE(writeEncryptedConfig());

     // This test just checks against dummy config file.
    auto dummyConfig = ParseConfigFile(&mock_api_wrapper, encryptedDummyConfigFile);
    ASSERT_NE(dummyConfig, nullptr) << "Got null when parsing.";

    // Looking for all sections
    for (const auto& sectionToFind : SECTION_NAMES){
        EXPECT_NE (dummyConfig.get()->find(sectionToFind), dummyConfig.get()->end()) << "Unable to find section " << sectionToFind;
    }

    // Checking that there are not too many sections.
    EXPECT_EQ(dummyConfig.get()->size(), SECTION_NAMES.size()) << "Wrong number of sections- expected " <<  SECTION_NAMES.size() << " got " << dummyConfig.get()->size();

    // Checking certain properties.
    auto address1 = (*dummyConfig.get())[SECTION_CW_INET].find("address1");
    EXPECT_NE(address1, (*dummyConfig.get())[SECTION_CW_INET].end()) << "Unable to find the parameter address1" ;
    EXPECT_THAT(address1->second, StrEq(kTestingServer+":"+std::to_string(kTestingPort)+":"+kTestingResource)) << "Property value was wrong: got " << address1->second << "Should be " << kTestingServer+":"+std::to_string(kTestingPort)+":"+kTestingResource;

}
