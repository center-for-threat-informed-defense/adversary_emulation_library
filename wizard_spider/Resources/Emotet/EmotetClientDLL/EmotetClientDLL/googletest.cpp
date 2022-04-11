// GoogleTest.cpp

#include "pch.h"
#include <gtest/gtest.h>
#include "dllmain.h"



int main(int argc, char* argv[])
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}