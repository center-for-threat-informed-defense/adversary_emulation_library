#include "pch.h"
#include "..\LatMovementDLL\latmove.h"

TEST(LatMovementModule, CommandExecutionTest) {
	// Check that execute command works for whoami on Dragon
	std::string input = "whoami";
	EXPECT_TRUE(strstr(ExecuteLatMovementCmd(input).c_str(), "dragon"));
}