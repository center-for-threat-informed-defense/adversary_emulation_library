using System.Diagnostics;

namespace dotone
{
    class emu
    {
        public static string pwd = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Desktop\";

        static bool server(string action)
        {
            if(action == "setup")
            {
                string serverpwd = pwd + @"serverRoot\";
                Directory.CreateDirectory(serverpwd);
                var serverFile = Dot_One.Resource1.http_file_server;
                using var serverWriter = new BinaryWriter(File.OpenWrite(serverpwd + @"httpserver.exe"));
                serverWriter.Write(serverFile);
                serverWriter.Close();

                var oneFile = Dot_One.Resource1.EULA;
                var oneWriter = new BinaryWriter(File.OpenWrite(serverpwd + "EULA.one"));
                oneWriter.Write(oneFile);
                oneWriter.Close();

                var readmeFile = Dot_One.Resource1.README;
                var readmeWriter = new BinaryWriter(File.OpenWrite(serverpwd + "README.md"));
                readmeWriter.Write(readmeFile);
                readmeWriter.Close();

                if(File.Exists(serverpwd + @"httpserver.exe"))
                {
                    Process p = new Process();
                    p.StartInfo = new ProcessStartInfo(serverpwd + "httpserver.exe");
                    p.StartInfo.Arguments = @" /=" + serverpwd;
                    p.StartInfo.CreateNoWindow = true;
                    p.Start();
                    Thread.Sleep(1000);

                    Process.Start(new ProcessStartInfo { FileName = serverpwd + "EULA.one", UseShellExecute = true });
                    return true;
                }
                else 
                { 
                    return false; 
                }
            }
            else if(action == "cleanup")
            {
                Process[] workers = Process.GetProcessesByName("httpserver");
                foreach(Process worker in workers)
                {
                    worker.Kill();
                    worker.WaitForExit();
                    worker.Dispose();
                }
                Thread.Sleep(2000);
                Directory.Delete(pwd + @"\serverRoot",true);
                Process.Start(new ProcessStartInfo { FileName = "cmd.exe", WindowStyle= ProcessWindowStyle.Hidden, Arguments = "/C schtasks /Delete /TN CMDTestTask /F" });
                return true;
            }
            else 
            { 
                Console.WriteLine ("Invalid action : " + action); 
                return false; 
            }

        }
        static int Main()
        {
            string cmd = "";
            bool flag1 = server("setup");
            if (flag1 == true)
            { 
                Console.Write("Press return to exit...");
                cmd = Console.ReadLine();
                server("cleanup");
            }
            else if(flag1 == false)
            {
                Console.WriteLine("Something went wrong writing the server file to disk!");
            }

            return 0;
        }
    }
}