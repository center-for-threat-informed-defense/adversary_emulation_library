//using System;
//using System.IO;
//using System.Threading;

namespace FileAccess
{
    class Program
    {
        public struct Variables 
        {
            public bool recur;
            public string dirPath;
            public string logFilePath;
            public int accessDelay;

            public void print()
            {
                Console.WriteLine($"1. Recursive: {recur}");
                Console.WriteLine($"2. Directory path to search: \"{dirPath}\"");
                Console.WriteLine($"3. Log File: \"{logFilePath}\"");
                Console.WriteLine($"4. Delay (seconds) between file accesses: {accessDelay}");
            }

            /*
             * Parses the given input and decides what the user wants to change.
             * It then gets the users input and updates the appropriate variable.
            */
            public void parseUserInput(int selection)
            {
                string result;
                Console.Clear();
                if (selection == 1)
                {
                    result = getUserInput("Recursive (Y/N)", false).ToUpper();
                    if (result == "Y")
                    {
                        recur = true;
                    }
                    else
                    {
                        recur = false;
                    }
                }
                else if (selection == 2)
                {
                    result = getUserInput("Input path to desired search directory.", true);
                    if (Directory.Exists(result))
                    {
                        dirPath = result;
                    }
                    else
                    {
                        Console.WriteLine($"Directory: {result} not found.\n");
                    }
                }
                else if (selection == 3)
                {
                    result = getUserInput("Input path to desired log file.", true);
                    if (result == "")
                    {
                        Console.WriteLine("No path entered.\n");
                    }
                    else
                    {
                        logFilePath = result;
                    }
                }
                else if (selection == 4)
                {
                    bool loop = true;
                    while (loop)
                    {
                        result = getUserInput("Input delay, in seconds, between file accesses.", false);
                        int delay;
                        if (int.TryParse(result, out delay))
                        {
                            accessDelay = delay;
                            loop = false;
                        }
                        else
                        {
                            Console.WriteLine("Unexpected input. Please try again.\n");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Unknown input entered. Please make a new selection.\n");
                }
                Console.Clear();
            }
        }


        static void Main(string[] args)
        {
            Console.Clear();
            Variables variables = parseArgs(args);

            Thread.Sleep(3000);
            Console.Clear();
            Console.WriteLine("Executing with the following variables:");
            variables.print();
            Thread.Sleep(5000);

            using (StreamWriter sw = File.AppendText(variables.logFilePath))
            {
                sw.Write("\nBeginning File modifation and renaming.\n\n");
            }


            List<string> allFiles = GetFilesFromPath(variables.dirPath, variables.recur);
            Console.Clear();
            Console.WriteLine("\nBeginning file modification and renaming.\n");
            foreach (string file in allFiles)
            {
                if (file == variables.logFilePath)
                {
                    Console.WriteLine("Ignoring log file.");
                    continue; //Don't modify the log file in any way unless to update with a new action
                }
                Thread.Sleep(variables.accessDelay * 1000);
                string[] tmpFile = file.Split('.');
                if (tmpFile[tmpFile.Length - 1] == "txt") //We only want to modify txt files, since adding a newline char won't break them
                {
                    ModifyFile(file, "\n", variables.logFilePath);
                }
                else //Anything that is not a .txt file will be renamed
                {
                    UpdateFileName(file, ".bk", variables.logFilePath);
                }
            }

            
            Console.WriteLine("\n\nFinished with file modification.\n\nBeginning cleanup...\n");
            Thread.Sleep(5000);
            Console.Clear();
            cleanup(variables);
            
        }


        /*
         * Collects a list of all the files in the given path
         * If "recur" is set to true, it will do a recursive search on all directories that are found in the given path.
        */
        static List<string> GetFilesFromPath(string path, bool recur)
        {
            List<string> files = new List<string>();
            try
            {
                Console.WriteLine($" \nCollecting files from: {path}\n");
                Thread.Sleep(1000);
                files.AddRange(Directory.GetFiles(path));

                Console.WriteLine("Files found: ");
                files.ToList().ForEach(Console.WriteLine);
                

                if (recur)
                {
                    Console.WriteLine("Searching recurisivly in directories.");
                    foreach (string dir in Directory.GetDirectories(path))
                    {
                        files.AddRange(GetFilesFromPath(dir, recur));
                    }
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            return files;
        }

        /*
         * Used to modify files by appending {newLine} to the end of each file given
        */
        static bool ModifyFile(string path, string newLine, string logFile)
        {
            if (!File.Exists(path))
            {
                Console.WriteLine("File: {0} does not exist.", path);
                return false;
            }
            try
            {
                using (StreamWriter sw = File.AppendText(path))
                {
                    sw.Write(newLine);
                    LogActivity($"File: {path} appended with \\n char.", logFile);
                }
                return true;
            }
            catch (UnauthorizedAccessException e)
            {
                LogActivity($"Could not modify {path} due to error: {e}", logFile);
                Console.WriteLine(e);
                return false;
            }
        }

        /*
         * Renames the file using a new extension that is provided
        */
        static bool UpdateFileName(string path, string newExtension, string logFile)
        {
            System.IO.FileInfo fi = new System.IO.FileInfo(path);
            if (fi.Exists)
            {
                fi.MoveTo((path += newExtension));
                LogActivity($"File {getCleanFileName(path)} renamed to: {path}", logFile);
                return true;
            }
            return false;
        }

        /*
         * Used to log all activity that is done by this program.
         * This should make it easier to ensure that everything can be cleaned up at the end.
        */
        static void LogActivity(string message, string path)
        {
            Console.WriteLine(message);
            System.IO.File.AppendAllText(path, (message += "\n"));
        }

        /* 
         * Checks if there are any args sent to the program and shows the menu if requested.
        */
        static Variables parseArgs(string[] args)
        {
            Variables variables = new Variables();
            
            //Set the default variables
            variables.recur = false;
            variables.logFilePath = @".\log.txt";
            variables.dirPath = @".\";
            variables.accessDelay = 0;

            //If true, the user would like to update some of the variables.
            if (args.Length > 0)
            {
                if (args[0] == "-menu")
                {
                    while (true)
                    {
                        printMenu(variables);
                        int selection;
                        selection = Convert.ToInt16(Console.ReadLine());
                        if (selection == 0)
                        {
                            Console.WriteLine("Commiting Variables...");
                            Thread.Sleep(2000);
                            return variables;
                        }
                        else 
                        {
                            variables.parseUserInput(selection);
                        }
                    }
                }
            }
            return variables;
        }

        /*
         * Print the menu for user input.
        */
        static void printMenu(Variables variables)
        {
            Console.WriteLine("File Access menu. Please input the number corresponding to the setting you would like to update.");
            Console.WriteLine("0. Commit variables and run program.");
            variables.print();
            Console.WriteLine("Please enter your selection: ");
            
        }

        /*
         * Helper function to read user input and help with input validation.
        */
        static string getUserInput(string message, bool isPath)
        {
            string result;
            Console.WriteLine(message);
            if (isPath)
            {
                result = @"" + Console.ReadLine();
            }
            else
            {
                result = "";
                bool loop = true;
                while (loop)
                {
                    result += Console.ReadLine();
                    if (result == "")
                    {
                        Console.WriteLine("Please input a response.");
                    }
                    else
                    {
                        loop = false;
                    }
                }
            }
            
            return result;
        }

        static void cleanup(Variables variables)
        {
            using (StreamWriter sw = File.AppendText(variables.logFilePath))
            {
                sw.Write("\n\nFinished with file modification. Beginning cleanup.\n");
            }

            List<string> files = GetFilesFromPath(variables.dirPath, variables.recur);
            Thread.Sleep(5000);
            Console.Clear();
            Console.WriteLine("\nBeginning cleanup of renamed files.\n");
            Thread.Sleep(2500);

            files.AddRange(Directory.GetFiles(variables.dirPath));

            foreach(string file in files)
            {
                string[] chkFileName = file.Split(".");
                if (chkFileName[(chkFileName.Length-1)] == "bk")
                {
                    System.IO.FileInfo fi = new System.IO.FileInfo(file);
                    if (fi.Exists)
                    {
                        string newFileName = getCleanFileName(file);
                        fi.MoveTo(newFileName);
                        LogActivity($"File {file} renamed to: {newFileName}", variables.logFilePath);
                    }
                }
                Thread.Sleep(1500);
            }

            Console.WriteLine("\nFile cleanup finished.");

        }

        static string getCleanFileName(string fileName)
        {
            return fileName.Substring(0, fileName.Length-3);
        }
    }
}


