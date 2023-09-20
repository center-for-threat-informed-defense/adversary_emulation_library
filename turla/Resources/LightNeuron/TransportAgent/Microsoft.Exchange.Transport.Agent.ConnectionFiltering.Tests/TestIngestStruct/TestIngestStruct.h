#pragma once

#include <iostream>
#include <windows.h>
#include <string>
#include <fstream>

namespace test_ingest_struct {
	struct mail {
		char* name;
		int totalRecipients;
		char** recipients;
		int totalAttachments;
		char** attachmentFileNames;
		char** attachmentContents;
	};

	extern "C" __declspec(dllexport) int MessageValidator(mail * s);
}
