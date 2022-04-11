#pragma once
#ifndef Commands
#define Commands

/*
 * CommandsEnum:
 *      About:
 *          Defines the command enumeration for client/server comms
 *			CTI: https://www.infoblox.com/wp-content/uploads/threat-intelligence-report-malicious-activity-report-trickbot-loader.pdf
 */
enum
{
	Register = 0,
	KeepAlive = 1,
	Download = 5,
	UploadFile = 6,
	LogCmdExec = 10,
	LogModuleResult = 14,
	UpdateConfig = 23,
	UpdateBot = 25,
	GetInjectTraffic = 63,
	Exfiltrate = 64,
	GetTasks = 80
};


#endif