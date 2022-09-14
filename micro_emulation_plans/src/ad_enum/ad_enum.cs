using System.DirectoryServices;
using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.Collections;

[SupportedOSPlatform("windows")]
public class ad_enum{
    internal struct Variables{ //store the configurable variables for the program so they are accessible by every function
        public static int command { get; set; } //which command to run
        public static int limit { get; set; } //how many objects to output
        public static int[]? commandList { get; set; } //list of commands to run, default is null
    }
    public static void Main(string[] args){
        //set the defaults for the variables
        Variables.command = 9; //9 is used to signify that the default command has not been modified
        Variables.limit = 20;

        parseArgs(args); //parse any command line arguments passed and then decide how to proceed
        outputData(""); //put a space at the end of the log file
    }

    /// <summary>
    /// Function for logging to a text file at .\ad_enum_log.txt and outputting to console.
    /// </summary>
    public static void outputData(string message){
        Console.WriteLine(message);
        System.IO.File.AppendAllText(@".\ad_enum_log.txt", message += "\n");
    }

    //this region contains the functions used to create the user interface and capture user input
    #region User Interface

    /// <summary>
    /// Given an int, return a string describing the command corresponding to that int.
    /// </summary>
    private static string getEnumCmd(int cmd){
        switch(cmd){
            case 0:
                return "Query LDAP for all users, and output user information.";
            case 1:
                return "Query LDAP for all users, and output their name.";
            case 2:
                return "Query LDAP for all groups, and output their name, members, and member of.";
            case 3:
                return "Query LDAP for all groups containing the word \"admin\" in their name, and output their name,\n    members, and member of.";
            case 4:
                return "Query LDAP for all computers on the domain.";
            case 5:
                return "Query LDAP for all domain controllers on the domain.";
            case 6:
                return "List information about users currently logged on to this computer.";
            case 7:
                return "List the network shares on this computer.";
            case 8:
                return "List the current sessions on this computer.";
            case 9:
                return getEnumCmd(0);
            case 10:
                string retStr = "";
                foreach(int str in Variables.commandList){
                    retStr += getEnumCmd(str)+"\n  * ";
                }
                return retStr.Remove(retStr.Length -5, 5);
        }
        return "";
    }

    /// <summary>
    /// Parse the command line arguments passed to the program.
    /// </summary>
    /// <param name="args">A string list of command line argument(s).</param>
    private static void parseArgs(string[] args){
        if (args.Length > 0){ //if there are arguments
            if (args[0] == "-h" || args[0] == "-help"){ //for -h or -help, print the help menu and then exit
                printHelp();
                Environment.Exit(0);
            }else if (args[0] == "-m" || args[0] == "-menu"){ //for -m or -menu, print the menu and then capture user input
                printMenu();
            }else if (args[0] == "-c" || args[0] == "-command"){ //for -c or -command
                if (args.Length > 1 && args[1] != null && args[1] != ""){ //if there is a second argument
                    getCommand(args[1]); //process that second argument
                }else{ //if there isn't a second argument, print an error message and exit
                    Console.WriteLine("[!] Incomplete argument passed. Please try again.");
                    Environment.Exit(0);
                }
                if (args.Length > 2){ //if there is a third argument
                    if (args[2] == "-l" || args[2] == "-limit"){ //-l or -limit is the only other valid argument
                        if (args.Length > 3 && args[3] != null && args[3] != ""){ //if there is a fourth argument
                            getLimit(args[3]); //process that argument
                            runCmd(); //run the program with the updated settings
                        }else{ //if there isn't a fourth argument, print an error message and exit
                            Console.WriteLine("[!] Incomplete argument passed. Please try again.");
                            Environment.Exit(0);
                        }
                    }else{ //if the third argument isn't -l or -limit, print an error message and exit
                        Console.WriteLine("[!] Unrecognized command line argument(s) detected. To access the help menu, use the command line argument \"-h\" or \"-help\"");
                        Environment.Exit(0);
                    }
                }else{ //if there are just two arguments and they were valid, run the program
                    runCmd();
                }
            }else if (args[0] == "-l" || args[0] == "-limit"){ //for -l or -limit
                if (args.Length > 1 && args[1] != null && args[1] != ""){ //if there is a second argument
                    getLimit(args[1]); //process that second argument
                }else{ //if there isn't a second argument, prnt an error message and exit
                    Console.WriteLine("[!] Incomplete argument passed. Please try again.");
                    Environment.Exit(0);
                }
                if (args.Length > 2){ //if there is a third argument
                    if (args[2] == "-c" || args[2] == "-command"){ //-c or -command is the only other valid argument
                        if (args.Length > 3 && args[3] != null && args[3] != ""){ //if there is a fourth argument
                            getCommand(args[3]); //process that argument
                            runCmd(); //run the program with the updated settings
                        }else{ //if there isn't a fourth argument, print an error message and exit
                            Console.WriteLine("[!] Incomplete argument passed. Please try again.");
                            Environment.Exit(0);
                        }
                    }else{ //if the third argument isn't -c or -command, print an error message and exit
                        Console.WriteLine("[!] Unrecognized command line argument(s) detected. To access the help menu, use the command line argument \"-h\" or \"-help\"");
                        Environment.Exit(0);
                    }
                }else{ //if there are just two arguments, and they were valid, run the program
                    runCmd();
                }
            }else{ //if there was an argument passed but it isn't any of the above arguments, print an error message and exit
                Console.WriteLine("[!] Unrecognized command line argument(s) detected. To access the help menu, use the command line argument \"-h\" or \"-help\"");
                Environment.Exit(0);
            }
        }else{ //if no arguments are passed, run with the defaults
            Console.WriteLine("No command line arguments detected, running with defaults.\nTo access the help menu, use the command line argument \"-h\" or \"-help\"\n");
            runDefault();
        }
    }

    /// <summary>
    /// Print the program's help menu.
    /// </summary>
    private static void printHelp(){
        Console.WriteLine("\n--------------------------------[ Active Directory Enumeration Help ]-------------------------------");
        Console.WriteLine("This program emulates Active Directory enumeration with multiple LDAP queries and Windows API calls.");
        Console.WriteLine("");
        Console.WriteLine("DEFAULTS:");
        Console.WriteLine(" If no arguments are passed, the program will perform the following five enumeration commands:");
        Console.WriteLine("  * "+getEnumCmd(0));
        Console.WriteLine("  * "+getEnumCmd(3));
        Console.WriteLine("  * "+getEnumCmd(5));
        Console.WriteLine("  * "+getEnumCmd(7));
        Console.WriteLine("  * "+getEnumCmd(8));
        Console.WriteLine(" The program will only return the first 20 results from these commands.");
        Console.WriteLine(" If the program is unable to locate a domain controller, only the last two commands will be run.");
        Console.WriteLine("");
        Console.WriteLine("ARGUMENTS:");
        Console.WriteLine("| Argument                                         | Explanation                                 |");
        Console.WriteLine("|--------------------------------------------------|---------------------------------------------|");
        Console.WriteLine("| > ad_enum.exe [-h/-help]                         |   Display this help menu.                   |");
        Console.WriteLine("| > ad_enum.exe [-m/-menu]                         |   Display the main menu.                    |");
        Console.WriteLine("| > ad_enum.exe [-c/-command (0-8)/(0,1,2...)/all] |   Select enumeration command(s) to run.     |");
        Console.WriteLine("| > ad_enum.exe [-l/-limit (1-1000)]               |   Limit the number of objects returned.     |");
        Console.WriteLine("|--------------------------------------------------|---------------------------------------------|");
        Console.WriteLine("  - All arguments are case sensitive.");
        Console.WriteLine("  - The -c/-command argument must be passed one of the following options:");
        Console.WriteLine("     * A single number from 0 to 8 (i.e. -c 5).");
        Console.WriteLine("     * A comma delimited list of numbers from 0 to 8 (i.e. -c 0,1,2,3) without whitespace.");
        Console.WriteLine("     * The string \"all\" (i.e. -c all). This is case sensitive.");
        Console.WriteLine("  - The -l/-limit argument must be passed with a number from 1 to 1000, and has a default of 20.");
        Console.WriteLine("  - Example - run the program with commands 0, 2, 7, and 9 with an output limit of 10:");
        Console.WriteLine("     * ad_enum.exe -c 0,2,7,9 -l 10");
        Console.WriteLine("  - Example - run the program with all commands and an output limit of 15: ");
        Console.WriteLine("     * ad_enum.exe -c all -l 15");
        Console.WriteLine("");
        Console.WriteLine("COMMANDS:");
        Console.WriteLine(" 0. "+getEnumCmd(0));
        Console.WriteLine(" 1. "+getEnumCmd(1));
        Console.WriteLine(" 2. "+getEnumCmd(2));
        Console.WriteLine(" 3. "+getEnumCmd(3));
        Console.WriteLine(" 4. "+getEnumCmd(4));
        Console.WriteLine(" 5. "+getEnumCmd(5));
        Console.WriteLine(" 6. "+getEnumCmd(6));
        Console.WriteLine(" 7. "+getEnumCmd(7));
        Console.WriteLine(" 8. "+getEnumCmd(8));
        Console.WriteLine("----------------------------------------------------------------------------------------------------\n");
    }

    /// <summary>
    /// Print the program's main menu, and then capture user input.
    /// </summary>
    private static void printMenu(){
        Console.WriteLine("\n--------------------------------[ Active Directory Enumeration Menu ]-------------------------------");
        Console.WriteLine("This program emulates Active Directory enumeration with multiple LDAP queries and Windows API calls.");
        Console.WriteLine("");
        Console.WriteLine("DEFAULTS:");
        Console.WriteLine(" The program will perform the following five enumeration commands:");
        Console.WriteLine("  * "+getEnumCmd(0));
        Console.WriteLine("  * "+getEnumCmd(3));
        Console.WriteLine("  * "+getEnumCmd(5));
        Console.WriteLine("  * "+getEnumCmd(7));
        Console.WriteLine("  * "+getEnumCmd(8));
        Console.WriteLine(" The program will only return the first 20 results from these commands.");
        Console.WriteLine(" If the program is unable to locate a domain controller, only the last two commands will be run.");
        Console.WriteLine("");
        parseMenu();
    }

    /// <summary>
    /// Process the command line argument for changing the command to run.
    /// </summary>
    /// <param name="arg">A string passed as an argument.</param>
    private static void getCommand(string arg){
        if(arg.Equals("all")){ //if "all" is passed, set the command list to all commands, and the "command" variable to 10
            int[] cmds = {0,1,2,3,4,5,6,7,8};
            Variables.commandList = cmds;
            Variables.command = 10;
        }else if(arg.Contains(',')){ //check if arg has commas in it
            //if yes, then strip it into a list, and then store that list into the Variables struct
            string[] argList = arg.Split(',');
            ArrayList argAL = new ArrayList();
            foreach(string cmd in argList){ //go through the argList list and check if each cmd in it is valid
                int tmp = 0;
                if(int.TryParse(cmd, out tmp)){
                    if((tmp >= 0 && tmp <= 8)){
                        argAL.Add(tmp);
                    }else{
                        outputData("[!] One of the commands selected was not valid.");
                        outputData("[!] Please enter a comma delimited list without whitespace with numbers from 0 to 8.");
                        Environment.Exit(0);
                    }
                }else{
                    outputData("[!] One of the commands selected was not valid.");
                    outputData("[!] Please enter a comma delimited list without whitespace with numbers from 0 to 8.");
                    Environment.Exit(0);
                }
            }
            int[] cmdList = new int[argList.Length]; //assuming that the previous foreach loop will only complete if every command passed in the argument is valid
            int i = 0;
            foreach(object cmd in argAL){ //build the list of ints corresponding to commands to run
                int tmp = 0;
                int.TryParse(Convert.ToString(cmd), out tmp);
                cmdList[i] = tmp;
                i++;
            }
            Variables.commandList = cmdList;
            Variables.command = 10;
        }else{ //if just a single command is passed
            int tmp, command = 0;
            if(int.TryParse(arg, out tmp)){ //check if the string is an int
                if(tmp >= 0 && tmp <= 8){ //check if the int is within the range of commands
                    command = tmp; //set the tmp variable to command
                }else{ //if not, output an error and exit
                    outputData("[!] Invalid selection detected. Please enter a number from 0 to 8.");
                    Environment.Exit(0);
                }
            }else{ //if not, output an error and exit
                outputData("[!] Invalid selection detected. Please enter a number from 0 to 8.");
                Environment.Exit(0);
            }
            Variables.command = command; //update the Variables struct with the new command
        }
    }

    /// <summary>
    /// Process the command line argument for changing the limit of output objects.
    /// </summary>
    /// <param name="arg">A string passed as an arguemnt.</param>
    private static void getLimit(string arg){
        int tmp, limit = 0;
        if(int.TryParse(arg, out tmp)){ //check if the string is an int
            if(tmp >= 1 && tmp <= 1000){ //check if the int is within the allowed range
                limit = tmp; //set the tmp variable to limit
            }else{ //if not, output an error and exit
                outputData("[!] Invalid selection detected. Please enter a number from 1 to 1000.");
                Environment.Exit(0);
            }
        }else{ //if not, output an error and exit
            outputData("[!] Invalid selection detected. Please enter a number from 1 to 1000.");
            Environment.Exit(0);
        }
        Variables.limit = limit; //update the Variables struct with the new limit
    }

    /// <summary>
    /// Output the current settings for the program and the main menu options, and then parse the user's input.
    /// </summary>
    private static void parseMenu(){
        Console.WriteLine("The current enumeration command is:\n  * "+getEnumCmd(Variables.command));
        Console.WriteLine("The current limit for the number of outputs is: "+Variables.limit);
        Console.WriteLine("");
        Console.WriteLine("Below are the options for the menu:");
        Console.WriteLine(" 0. Run the program with its default settings.");
        Console.WriteLine(" 1. Run the program with the current command and limit settings.");
        Console.WriteLine(" 2. Change the enumeration command.");
        Console.WriteLine(" 3. Change the limit for the number of outputs.");
        Console.Write("Please enter a number from 0 to 3 corresponding to one of the menu options: ");
        string selection = Console.ReadLine(); //grab user input
        if (Int32.TryParse(selection, out int s)){ //check if user input is an int
            if (s >= 0 && s <= 3){ //check if user input is one of the options to select
                switch(s){
                    case 0: //run the program with the default settings
                        Console.WriteLine();
                        runDefault();
                        return;
                    case 1: //run the program with the current settings from Variables
                        Console.WriteLine();
                        runCmd();
                        return;
                    case 2: //get a new command to run
                        Console.WriteLine("----------------------------------------------------------------------------------------------------");
                        Variables.command = parseCommand();
                        parseMenu();
                        return;
                    case 3: //get a new limit to use
                        Console.WriteLine("----------------------------------------------------------------------------------------------------");
                        Variables.limit = parseLimit();
                        parseMenu();
                        return;
                }
            } else { //if not, output an error and call this function again
                Console.WriteLine("[!] Invalid selection detected. Please enter a number from 0 to 3.");
                Console.WriteLine("");
                parseMenu();
            }
        } else { //if not, output an error and call this function again
            Console.WriteLine("[!] Invalid selection detected. Please enter a number from 0 to 3.");
            Console.WriteLine("");
            parseMenu();
        }
    }

    /// <summary>
    /// Output the different commands the user can pick from and parse the user's input. If given valid user input, update the command.
    /// </summary>
    private static int parseCommand(){
        int retVal = 0;
        Console.WriteLine("Below are the different enumeration commands that you can run:"); //display available commands
        Console.WriteLine(" 0. "+getEnumCmd(0));
        Console.WriteLine(" 1. "+getEnumCmd(1));
        Console.WriteLine(" 2. "+getEnumCmd(2));
        Console.WriteLine(" 3. "+getEnumCmd(3));
        Console.WriteLine(" 4. "+getEnumCmd(4));
        Console.WriteLine(" 5. "+getEnumCmd(5));
        Console.WriteLine(" 6. "+getEnumCmd(6));
        Console.WriteLine(" 7. "+getEnumCmd(7));
        Console.WriteLine(" 8. "+getEnumCmd(8));
        Console.WriteLine();
        Console.WriteLine("You can enter one of the following:");
        Console.WriteLine(" * A single number from 0 to 8 corresponding to one of the commands.");
        Console.WriteLine(" * A comma separated list with no whitespace containing numbers corresponding to the commands.");
        Console.WriteLine(" * The string \"all\" to run all of the commands.");
        Console.Write("Please make your selection: ");
        string selection = Console.ReadLine(); //grab user input
        Console.WriteLine("----------------------------------------------------------------------------------------------------");
        if(selection.Equals("all")){
            int[] cmds = {0,1,2,3,4,5,6,7,8};
            Variables.commandList = cmds;
            retVal = 10;
        }else if(selection.Contains(',')){ //if yes, then strip it into a list, and then store that list into the Variables struct
            bool error = false;
            string[] argList = selection.Split(',');
            ArrayList argAL = new ArrayList();
            foreach(string cmd in argList){ //go through the argList list and check if each cmd in it is valid
                int tmp = 0;
                if(int.TryParse(cmd, out tmp)){
                    if((tmp >= 0 && tmp <= 8)){
                        argAL.Add(tmp);
                    }else{
                        error = true;
                        Console.WriteLine("[!] One of the commands selected was not valid.");
                        Console.WriteLine("[!] Please enter a comma delimited list without whitespace with numbers from 0 to 8.");
                        Console.WriteLine();
                        retVal = parseCommand();
                        break;
                    }
                }else{
                    error = true;
                    Console.WriteLine("[!] One of the commands selected was not valid.");
                    Console.WriteLine("[!] Please enter a comma delimited list without whitespace with numbers from 0 to 8.");
                    Console.WriteLine();
                    retVal = parseCommand();
                    break;
                }
            }
            if(!error){
                int[] cmdList = new int[argList.Length]; //assuming that the previous foreach loop will only complete if every command passed in the argument is valid
                int i = 0;
                foreach(object cmd in argAL){ //build the list of ints corresponding to commands to run
                    int tmp = 0;
                    int.TryParse(Convert.ToString(cmd), out tmp);
                    cmdList[i] = tmp;
                    i++;
                }
                Variables.commandList = cmdList;
                retVal = 10; //10 signifies that the program should be executing a list of commands rather than a single one
            }
        }else{
            if (Int32.TryParse(selection, out int s)){ //check if user input is an int
                if (s >= 0 && s <= 8){ //check if user input corresponds to a command
                    retVal = s; //update the return valie
                } else { //if not, output an error and call this function again
                    Console.WriteLine("[!] Invalid selection detected. Please enter a number from 0 to 8.");
                    Console.WriteLine("");
                    retVal = parseCommand();
                }
            } else { //if not, output an error and call this function again
                Console.WriteLine("[!] Invalid selection detected. Please enter a number from 0 to 8.");
                Console.WriteLine("");
                retVal = parseCommand();
            }
        }
        return retVal; //return the selected command
    }

    /// <summary>
    /// Output the valid range for the limit of objects to output, and parse the user's input. If given valid user input, update the limit.
    /// </summary>
    private static int parseLimit(){
        int retVal = 0;
        Console.Write("Please enter a number from 1 to 1000 for the number of objects to output: "); //output valid range
        string selection = Console.ReadLine(); //grab user input
        Console.WriteLine("----------------------------------------------------------------------------------------------------");
        if (Int32.TryParse(selection, out int s)){ //check if user input is an int
            if (s >= 1 && s <= 1000){ //check if user input is within valid range
                retVal = s; //update return value
            } else { //if not, output an error and call this function again
                Console.WriteLine("[!] Invalid selection detected. Please enter a number from 1 to 1000.");
                Console.WriteLine("");
                retVal = parseLimit();
            }
        } else { //if not, output an error and vall this function again
            Console.WriteLine("[!] Invalid selection detected. Please enter a number from 1 to 1000.");
            Console.WriteLine("");
            retVal = parseLimit();
        }
        return retVal; //return the updated limit
    }

    /// <summary>
    /// Run the selected command with the selected limit of objects to output.
    /// </summary>
    private static void runCmd(){
        bool domain = isOnDomain();

        //output the current settings
        outputData("----------------------------------[ Active Directory Enumeration ]----------------------------------");
        outputData("Running the program with the following settings:");
        outputData(" The current enumeration command is:\n  * "+getEnumCmd(Variables.command));
        outputData(" The current limit for the number of outputs is: "+Variables.limit);
        outputData("----------------------------------------------------------------------------------------------------");

        //validate if computer on domain or not
        if(Variables.command < 6 || Variables.command == 9){ //if an LDAP command is selected
            if(!domain){ //if not on a domain, output an error and exit
                outputData("[!] Unable to locate a domain controller, the selected command will not be able to run.");
                outputData("[!] Exiting...");
                Environment.Exit(0);
            }else{ //if on a domain, print the LDAP path and continue
                outputData("Obtaining LDAP information from: "+GetCurrentDomainPath()+"\n");   
            }
        }else if(Variables.command == 10){ //if we are going to run multiple commands
            bool ldapCmd = false;
            bool nonLDAPCmd = false;
            foreach(int cmd in Variables.commandList){ //figure out which commands are going to be run (ldap or non ldap)
                if(cmd < 6){
                    ldapCmd = true;
                }
                if(cmd > 5){
                    nonLDAPCmd = true;
                }
            }
            if(ldapCmd){
                if(!domain){
                    if(nonLDAPCmd){ //if there are non LDAP commands we are trying to run, print error and continue with those
                        outputData("[!] Unable to locate a domain controller, some commands will not be able to run.\n");
                    }else{ //if we are only trying to run LDAP commands and we are not on a domain, print error and exit
                        outputData("[!] Unable to locate a domain controller, no selected commands will be able to run.");
                        outputData("[!] Exiting...");
                        Environment.Exit(0);
                    }
                }else{
                    outputData("Obtaining LDAP information from: "+GetCurrentDomainPath()+"\n");
                }
            }
            foreach(int cmd in Variables.commandList){
                if(cmd < 6 && domain)
                    runEnumCmd(cmd);
                else
                    runEnumCmd(cmd);
                outputData("----------------------------------------------------------------------------------------------------");
            }
        }

        runEnumCmd(Variables.command); //call the requested command
    }

    /// <summary>
    /// Run the program with the default settings
    /// </summary>
    private static void runDefault(){
        bool domain = false;
        if(isOnDomain()) //check if the computer is on a domain
            domain = true;

        outputData("----------------------------------[ Active Directory Enumeration ]----------------------------------");
        if(!domain){ //if not on a domain, tell the user
            outputData("[!] Unable to locate a domain controller, some commands will not be able to run.");
        }
        outputData("Running the program with the default settings:");
        outputData(" The current enumeration commands are: ");
        if(domain){ //only run these commands if on a domain
            outputData("  * "+getEnumCmd(0));
            outputData("  * "+getEnumCmd(3));
            outputData("  * "+getEnumCmd(5));
        }
        outputData("  * "+getEnumCmd(7));
        outputData("  * "+getEnumCmd(8));
        outputData(" The current limit for the number of outputs is: "+Variables.limit);
        outputData("----------------------------------------------------------------------------------------------------");

        if(domain){ //only run these commands if on a domain
            runEnumCmd(0);
            outputData("----------------------------------------------------------------------------------------------------");
            runEnumCmd(3);
            outputData("----------------------------------------------------------------------------------------------------");
            runEnumCmd(5);
            outputData("----------------------------------------------------------------------------------------------------");
        }
        runEnumCmd(7);
        outputData("----------------------------------------------------------------------------------------------------");
        runEnumCmd(8);
        outputData("----------------------------------------------------------------------------------------------------");

    }

    /// <summary>
    /// Run the program with all available commands
    /// </summar>
    private static void runAll(){
        bool domain = false;
        if(isOnDomain()) //check if the computer is on a domain
            domain = true;

        outputData("----------------------------------[ Active Directory Enumeration ]----------------------------------");
        if(!domain){ //if not on a domain, tell the user
            outputData("Unable to locate a domain controller, some commands will not be run.");
        }
        outputData("Running the program with all available commands:");
        outputData(" The current enumeration commands are: ");
        if(domain){ //only run these commands if on a domain
            outputData("  * "+getEnumCmd(0));
            outputData("  * "+getEnumCmd(1));
            outputData("  * "+getEnumCmd(2));
            outputData("  * "+getEnumCmd(3));
            outputData("  * "+getEnumCmd(4));
            outputData("  * "+getEnumCmd(5));
        }
        outputData("  * "+getEnumCmd(6));
        outputData("  * "+getEnumCmd(7));
        outputData("  * "+getEnumCmd(8));
        outputData(" The current limit for the number of outputs is: "+Variables.limit);
        outputData("----------------------------------------------------------------------------------------------------");

        if(domain){ //only run these commands if on a domain
            runEnumCmd(0);
            outputData("----------------------------------------------------------------------------------------------------");
            runEnumCmd(1);
            outputData("----------------------------------------------------------------------------------------------------");
            runEnumCmd(2);
            outputData("----------------------------------------------------------------------------------------------------");
            runEnumCmd(3);
            outputData("----------------------------------------------------------------------------------------------------");
            runEnumCmd(4);
            outputData("----------------------------------------------------------------------------------------------------");
            runEnumCmd(5);
            outputData("----------------------------------------------------------------------------------------------------");
        }
        runEnumCmd(6);
        outputData("----------------------------------------------------------------------------------------------------");
        runEnumCmd(7);
        outputData("----------------------------------------------------------------------------------------------------");
        runEnumCmd(8);
        outputData("----------------------------------------------------------------------------------------------------");
    }

    /// <summary>
    /// Run the specified enumeration command corresponding to the passed int
    /// </summary>
    private static void runEnumCmd(int cmd){
        switch(cmd){ //call the requested command
            case 0:
                GetAdditionalUserInfo();
                break;
            case 1:
                GetAllUsers();
                break;
            case 2:
                GetAllGroups();
                break;
            case 3:
                GetAdministratorMembers();
                break;
            case 4:
                GetComputers();
                break;
            case 5:
                GetDomainControllers();
                break;
            case 6:
                NetWkstaUserEnumWrapper();
                break;
            case 7:
                EnumNetSharesWrapper();
                break;
            case 8:
                QuerySession();
                break;
            case 9:
                GetAdditionalUserInfo();
                break;
        }
    }

    #endregion

    //region containing the enumeration commands for the program
    #region Enum Commands
    //source for LDAP commands: https://www.codemag.com/article/1312041/Using-Active-Directory-in-.NET

    /// <summary>
    /// Check if the computer is on a domain, and return a corresponding bool
    /// </summary>
    private static bool isOnDomain(){
        bool retVal = false;
        try{ //attempt to get the current domain path
            GetCurrentDomainPath();
            retVal = true; //if the above command does not error, set the return value to true
        }catch(System.Runtime.InteropServices.COMException e){ //this exception is thrown if the program cannot contact a domain controller
            retVal = false; //if the exception is caught, set the return value to false
        }

        return retVal;
    }

    /// <summary>
    /// Get the LDAP path to a valid domain controller, and return that path.
    /// </summary>
    private static string GetCurrentDomainPath(){
        DirectoryEntry de = new DirectoryEntry("LDAP://RootDSE");
        return "LDAP://" + de.Properties["defaultNamingContext"][0].ToString();
    }

    /// <summary>
    /// Output all the users on the domain.
    /// </summary>
    private static void GetAllUsers(){
        SearchResultCollection results;
        DirectoryEntry de = new DirectoryEntry(GetCurrentDomainPath());
        DirectorySearcher ds =new DirectorySearcher(de);
        ds.Filter = "(&(sAMAccountType=805306368))"; //this filters for user accoutns

        results = ds.FindAll();
        outputData("Users in the domain: ");
        outputData("");
        int i = 0;
        foreach (SearchResult sr in results){
            if(i>=Variables.limit) //enforce the output limit
                break;
            outputData(" Name: "+sr.GetPropertyValue("name"));
            i++;
        }
        outputData("");
    }

    /// <summary>
    /// Output all the users on the domain, and their additional information.
    /// </summary>
    private static void GetAdditionalUserInfo(){
        SearchResultCollection results;
        DirectoryEntry de = new DirectoryEntry(GetCurrentDomainPath());
        DirectorySearcher ds =new DirectorySearcher(de);

        ds.PropertiesToLoad.Add("name"); //Full Name
        ds.PropertiesToLoad.Add("mail"); //Email Address
        ds.PropertiesToLoad.Add("givenname"); //First Name
        ds.PropertiesToLoad.Add("sn"); //Last Name
        ds.PropertiesToLoad.Add("userPrincipalName"); //Login Name
        ds.PropertiesToLoad.Add("distinguishedName"); //Distinguished Name

        ds.Filter = "(&(sAMAccountType=805306368))"; //this filters for user accounts

        results = ds.FindAll();
        outputData("Users in the domain with additional user information: ");
        outputData("");
        int i = 0;
        foreach (SearchResult sr in results){
            if(i>=Variables.limit) //enforce the output limit
                break;
            outputData(" Name: "+sr.GetPropertyValue("name"));
            outputData("  * Email: "+sr.GetPropertyValue("mail"));
            outputData("  * First Name: "+sr.GetPropertyValue("givenname"));
            outputData("  * Last Name: "+sr.GetPropertyValue("sn"));
            outputData("  * Login Name: "+sr.GetPropertyValue("userPrincipalName"));
            outputData("  * Distinguished Name: "+sr.GetPropertyValue("distinguishedName"));
            outputData("");
            i++;
        }
    }

    /// <summary>
    /// Output all the groups on the domain, their member of section, and their members.
    /// </summary>
    private static void GetAllGroups(){
        SearchResultCollection results;
        DirectoryEntry de = new DirectoryEntry(GetCurrentDomainPath());
        DirectorySearcher ds =new DirectorySearcher(de);

        ds.Sort = new SortOption("name", SortDirection.Ascending);
        ds.PropertiesToLoad.Add("name");
        ds.PropertiesToLoad.Add("memberof");
        ds.PropertiesToLoad.Add("member");

        ds.Filter = "(&(objectCategory=Group))"; //set the filter for groups

        results = ds.FindAll();
        outputData("Groups in the domain: ");
        outputData("");
        int i = 0;
        foreach (SearchResult sr in results){
            if(i>=Variables.limit) //enforce the output limit
                break;
            outputData(" Group Name: "+sr.GetPropertyValue("name"));

            if(sr.Properties["memberof"].Count > 0){
                outputData("     Member of...");
                foreach(string item in sr.Properties["memberof"]){
                    outputData("      * "+item);
                }
            }

            if(sr.Properties["member"].Count > 0){
                outputData("     Members");
                foreach(string item in sr.Properties["member"]){
                    outputData("      * "+item);
                }
            }
            outputData("");
            i++;
        }
    }

    /// <summary>
    /// Output all the groups on the domain whose name contains "Admin", their member of section, and their members.
    /// </summary>
    private static void GetAdministratorMembers(){
        SearchResultCollection results;
        DirectoryEntry de = new DirectoryEntry(GetCurrentDomainPath());
        DirectorySearcher ds =new DirectorySearcher(de);

        ds.Filter = "(&(objectCategory=Group)(name=*Admin*))"; //set the filter for groups whose name contains "Admin"

        results = ds.FindAll();
        outputData("Groups in the domain with \"Admin\" in the name: ");
        outputData("");
        int i = 0;
        foreach(SearchResult sr in results){
            if(i>=Variables.limit) //enforce the output limit
                break;
            outputData(" Group Name: "+sr.GetPropertyValue("name"));

            if(sr.Properties["memberof"].Count > 0){
                outputData("     Member of...");
                foreach(string item in sr.Properties["memberof"]){
                    outputData("      * "+item);
                }
            }

            if(sr.Properties["member"].Count > 0){
                outputData("     Members");
                foreach(string item in sr.Properties["member"]){
                    outputData("      * "+item);
                }
            }
            outputData("");
            i++;
        }
    }

    /// <summary>
    /// Output all the computers on the domain and additional information about those computers.
    /// </summary>
    private static void GetComputers(){
        SearchResultCollection results;
        DirectoryEntry de = new DirectoryEntry(GetCurrentDomainPath());
        DirectorySearcher ds =new DirectorySearcher(de);

        ds.Filter = "(&(objectCategory=Computer))"; //set the filter to computers

        results = ds.FindAll();
        outputData("Getting computers on the domain and their information: ");
        outputData("");
        int i = 0;
        foreach(SearchResult sr in results){
            if(i>=Variables.limit) //enfore the output limit
                break;
            outputData(" Computer Name: "+sr.GetPropertyValue("name"));
            outputData(" * Fully Qualified Domain Name: "+sr.GetPropertyValue("dNSHostName"));
            outputData(" * Location: "+sr.GetPropertyValue("location"));
            outputData(" * Operating System: "+sr.GetPropertyValue("operatingSystem"));
            outputData(" * Operating System Service Pack: "+sr.GetPropertyValue("operatingSystemServicePack"));
            outputData(" * Operating System Version: "+sr.GetPropertyValue("operatingSystemVersion"));
            outputData(" * Distinguished Name: "+sr.GetPropertyValue("distinguishedName"));

            if(sr.Properties["memberof"].Count > 0){
                outputData("     Member of...");
                foreach(string item in sr.Properties["memberof"]){
                    outputData("      * "+item);
                }
            }
            outputData("");
            i++;
        }
    }

    /// <summary>
    /// Output all the domain controllers on the domain and additional information about those computers
    /// </summary>
    private static void GetDomainControllers(){
        SearchResultCollection results;
        DirectoryEntry de = new DirectoryEntry(GetCurrentDomainPath());
        DirectorySearcher ds =new DirectorySearcher(de);

        ds.Filter = "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"; //set the filter to computers that are domain controllers

        results = ds.FindAll();
        outputData("Getting domain controllers and their information: ");
        outputData("");
        int i = 0;
        foreach(SearchResult sr in results){
            if(i>=Variables.limit) //enforce the output limit
                break;
            outputData(" Computer Name: "+sr.GetPropertyValue("name"));
            outputData(" * Fully Qualified Domain Name: "+sr.GetPropertyValue("dNSHostName"));
            outputData(" * Location: "+sr.GetPropertyValue("location"));
            outputData(" * Operating System: "+sr.GetPropertyValue("operatingSystem"));
            outputData(" * Operating System Service Pack: "+sr.GetPropertyValue("operatingSystemServicePack"));
            outputData(" * Operating System Version: "+sr.GetPropertyValue("operatingSystemVersion"));
            outputData(" * Distinguished Name: "+sr.GetPropertyValue("distinguishedName"));

            if(sr.Properties["memberof"].Count > 0){
                outputData("     Member of...");
                foreach(string item in sr.Properties["memberof"]){
                    outputData("      * "+item);
                }
            }
            outputData("");
            i++;
        }
    }

    /// <summary>
    /// Output the different user sessions on the current computer.
    /// </summary>
    private static void NetWkstaUserEnumWrapper(){
        NetWkstaUser nwu = new NetWkstaUser();
        IEnumerable<NetWkstaUser.WKSTA_USER_INFO_1> wkstaUserEnum = nwu.CallNetWkstaUserEnum(null);//passing null uses local computer, can pass DNS or NetBIOS name
        int i = 0;
        outputData("Listing information about users current logged onto this computer:");
        outputData("");
        foreach (NetWkstaUser.WKSTA_USER_INFO_1 wui in wkstaUserEnum){
            if(i>=Variables.limit) //enforce the output limit
                break;
            PrintWkstaUserInfo(wui);
            i++;
        }
    }

    /// <summary>
    /// Helper function for printing a WKSTA_USER_INFO_1 struct.
    /// </summary>
    private static void PrintWkstaUserInfo(NetWkstaUser.WKSTA_USER_INFO_1 wui){
        outputData(" Username: "+wui.wkui1_username);
        outputData("  * Logon Domain: "+wui.wkui1_logon_domain);
        outputData("  * Operating System Domains: "+wui.wkui1_oth_domains);
        outputData("  * Logon Server: "+wui.wkui1_logon_server);
        outputData("");
    }

    /// <summary>
    /// Output the different SMB shares on the current computer.
    /// </summary>
    private static void EnumNetSharesWrapper(){
        NetShares ns = new NetShares();
        NetShares.SHARE_INFO_1[] shInf = ns.EnumNetShares(null);//passing null uses local computer, can pass DNS or NetBIOS name
        int i = 0;
        outputData("Listing network shares on this computer: ");
        outputData("");
        foreach (NetShares.SHARE_INFO_1 shi in shInf){
            if(i>=Variables.limit)
                break;
            PrintNetShare(shi);
            i++;
        }
    }

    /// <summary>
    /// Helper function for printing a SHARE_INFO_1 struct.
    /// </summary>
    private static void PrintNetShare(NetShares.SHARE_INFO_1 shi){
        outputData(" Share Name: "+shi.shi1_netname);
        outputData("  * Share Type: "+shi.shi1_type);
        outputData("  * Share Remark: "+shi.shi1_remark);
        outputData("");
    }

    /// <summary>
    /// Output the different sessions on the current computer with the "query session" command
    /// </summary>
    private static void QuerySession(){
        var proc = new Process{ //initialize the "query session" process
            StartInfo = new ProcessStartInfo{
                FileName = "cmd.exe",
                Arguments = "/c \"query session\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            }
        };
        proc.Start(); //start the process
        ArrayList output = new ArrayList(); //initialize array list for contining the process' output
        while (!proc.StandardOutput.EndOfStream){ //build the output of the process into the array list
            string line =  proc.StandardOutput.ReadLine();
            output.Add(line);
        }
        outputData("Listing the user sessions on this computer:");
        outputData("");
        int i = 0;
        foreach (string obj in output){ //output the information from the array list
            if(i>Variables.limit) //just > here because the first line of this output is always the header
                break;
            outputData(obj);
            i++;
        }
    }

    #endregion
}

[SupportedOSPlatform("windows")]
public static class ADExtensionMethods{
    /// <summary>
    /// Given a SearchResult and string propertyName, return the string value of that property. This helper function makes the output sections of the LDAP calls much cleaner.
    /// </summary>
    public static string GetPropertyValue(this SearchResult sr, string propertyName){
        string ret = string.Empty;
        if(sr.Properties[propertyName].Count > 0){
            ret = sr.Properties[propertyName][0].ToString();
        }
        return ret;
    }
}

[SupportedOSPlatform("windows")]
/// <summary>
/// Class containing necessary dll imports, structs, and variables for the NetShareEnum API call
/// </summary>
public class NetShares //source: https://www.pinvoke.net/default.aspx/netapi32/netshareenum.html
{
    #region External Calls
    [DllImport("Netapi32.dll", SetLastError = true)]
    static extern int NetApiBufferFree(IntPtr Buffer);
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetShareEnum(
         StringBuilder ServerName,
         int level,
         ref IntPtr bufPtr,
         uint prefmaxlen,
         ref int entriesread,
         ref int totalentries,
         ref int resume_handle
         );
    #endregion
    #region External Structures
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_1
    {
        public string shi1_netname;
        public uint shi1_type;
        public string shi1_remark;
        public SHARE_INFO_1(string sharename, uint sharetype, string remark)
        {
        this.shi1_netname = sharename;
        this.shi1_type = sharetype;
        this.shi1_remark = remark;
        }
        public override string ToString()
        {
        return shi1_netname;
        }
    }
    #endregion
    const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;
    const int NERR_Success = 0;
    private enum NetError : uint
    {
        NERR_Success = 0,
        NERR_BASE = 2100,
        NERR_UnknownDevDir = (NERR_BASE + 16),
        NERR_DuplicateShare = (NERR_BASE + 18),
        NERR_BufTooSmall = (NERR_BASE + 23),
    }
    private enum SHARE_TYPE : uint
    {
        STYPE_DISKTREE = 0,
        STYPE_PRINTQ = 1,
        STYPE_DEVICE = 2,
        STYPE_IPC = 3,
        STYPE_SPECIAL = 0x80000000,
    }
    public SHARE_INFO_1[] EnumNetShares(string Server)
    {
        List<SHARE_INFO_1> ShareInfos = new List<SHARE_INFO_1>();
        int entriesread = 0;
        int totalentries = 0;
        int resume_handle = 0;
        int nStructSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
        IntPtr bufPtr = IntPtr.Zero;
        StringBuilder server = new StringBuilder(Server);
        int ret = NetShareEnum(server, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref entriesread, ref totalentries, ref resume_handle);
        if (ret == NERR_Success)
        {
        IntPtr currentPtr = bufPtr;
        for (int i = 0; i < entriesread; i++)
        {
            SHARE_INFO_1 shi1 = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
            ShareInfos.Add(shi1);
            currentPtr += nStructSize;
        }
        NetApiBufferFree(bufPtr);
        return ShareInfos.ToArray();
        }
        else
        {
        ShareInfos.Add(new SHARE_INFO_1("ERROR=" + ret.ToString(),10,string.Empty));
        return ShareInfos.ToArray();
        }
    }
}

[SupportedOSPlatform("windows")]
/// <summary>
/// Class containing necessary dll imports, structs, and variables for the NetWkstaUserEnum API call
/// </summary>
public class NetWkstaUser{ //source: https://github.com/BloodHoundAD/SharpHoundCommon/blob/d8015b908773a8a6da5c9aeeb2c532a6384f49f0/src/CommonLib/NativeMethods.cs

    private const int NetWkstaUserEnumQueryLevel = 1;

    public virtual IEnumerable<WKSTA_USER_INFO_1> CallNetWkstaUserEnum(string servername)
    {
        var ptr = IntPtr.Zero;
        try
        {
            var resumeHandle = 0;
            //_log.LogTrace("Beginning NetWkstaUserEnum for {ServerName}", servername);
            var result = NetWkstaUserEnum(servername, NetWkstaUserEnumQueryLevel, out ptr, -1, out var entriesread,
                out _,
                ref resumeHandle);

            //_log.LogTrace("Result of NetWkstaUserEnum for computer {ServerName} is {Result}", servername, result);

            if (result != NERR.NERR_Success && result != NERR.ERROR_MORE_DATA){
                ad_enum.outputData("Error with NetWkstaUserEnum, unable to get output.");
            }

            var iter = ptr;
            for (var i = 0; i < entriesread; i++)
            {
                var data = Marshal.PtrToStructure<WKSTA_USER_INFO_1>(iter);
                iter = (IntPtr)(iter.ToInt64() + Marshal.SizeOf(typeof(WKSTA_USER_INFO_1)));
                yield return data;
            }
        }
        finally
        {
            if (ptr != IntPtr.Zero)
                NetApiBufferFree(ptr);
        }
    }

    #region Session Enum Imports

    public enum NERR
    {
        NERR_Success = 0,
        ERROR_MORE_DATA = 234,
        ERROR_NO_BROWSER_SERVERS_FOUND = 6118,
        ERROR_INVALID_LEVEL = 124,
        ERROR_ACCESS_DENIED = 5,
        ERROR_INVALID_PARAMETER = 87,
        ERROR_NOT_ENOUGH_MEMORY = 8,
        ERROR_NETWORK_BUSY = 54,
        ERROR_BAD_NETPATH = 53,
        ERROR_NO_NETWORK = 1222,
        ERROR_INVALID_HANDLE_STATE = 1609,
        ERROR_EXTENDED_ERROR = 1208,
        NERR_BASE = 2100,
        NERR_UnknownDevDir = NERR_BASE + 16,
        NERR_DuplicateShare = NERR_BASE + 18,
        NERR_BufTooSmall = NERR_BASE + 23
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WKSTA_USER_INFO_1
    {
        public string wkui1_username;
        public string wkui1_logon_domain;
        public string wkui1_oth_domains;
        public string wkui1_logon_server;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern NERR NetWkstaUserEnum(
        string servername,
        int level,
        out IntPtr bufptr,
        int prefmaxlen,
        out int entriesread,
        out int totalentries,
        ref int resume_handle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(
        IntPtr Buff);

    #endregion
}