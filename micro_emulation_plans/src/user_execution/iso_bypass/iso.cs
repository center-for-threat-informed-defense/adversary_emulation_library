using System.Diagnostics;

public class iso {
    
    public static void Main(string[] args){
        string fileName = @"download.iso";
        if (args.Length > 0 && (args[0].ToLower() == "-f" || args[0].ToLower() == "-file"))
        {
            fileName = args[1];
        }
        string dir = "";
        Console.WriteLine(fileName);
        if (File.Exists(fileName))
        {
            dir = Path.GetFullPath(fileName);
        }
        else 
        {
            Console.WriteLine("Unable to locate the ISO file { " + fileName + " } to mount. Exiting.");
        }
        
        if(dir != ""){
            string driveName = MountISO(dir); //try to mount the ISO, and then get its drive letter
            if(driveName != ""){
                runEXE(driveName);
                EjectISO(dir);
            }else{
                Console.WriteLine("Unable to locate the mounted ISO.");
            }
        }
    }

    public static string MountISO(string isoPath){ //attempt to mount the given ISO file and then get the drive letter where it was mounted
        DriveInfo[] drivesPre = DriveInfo.GetDrives(); //get a list of all mounted drives so we can find where the ISO was mounted
        bool mountedISO = false;
        string sFilePath = @""+isoPath; //file location of the ISO
        string sPath = ""; //directory containing the ISO
        string sFileName = ""; //file name and extension of the ISO
        try{ //attempt to fill the sPath and sFileName variables
            sPath = Path.GetDirectoryName(sFilePath);
            sFileName = Path.GetFileName(sFilePath);
        }catch{
            Console.WriteLine("Encountered an error obtaining the path to the ISO file.");
        }

        if(sPath != "" && sFileName != ""){ //if sPath and sFIleName were successfully filled, attempt to mount the ISO
            Console.WriteLine("Attempting to mount the ISO: "+sFilePath);
            dynamic folderItemVerbs = null;

            try{
                //create a Shell.Application instance so we can mount the ISO
                dynamic shellApplication = Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application")); 
                dynamic folder = shellApplication.NameSpace(sPath);
                dynamic folderItem = folder.ParseName(sFileName);
                folderItemVerbs = folderItem.Verbs(); //list of verbs (Mount, Eject, Open With, other things that come up when you right click)
            }catch{
                Console.WriteLine("Encountered an error creating the shell application to mount the ISO.");
            }

            if(folderItemVerbs != null){
                try{
                    foreach(dynamic verb in folderItemVerbs){ //go through the list of verbs and find Mount
                        if(verb.Name.Equals("Mount")){
                            verb.DoIt(); //mount the ISO
                            Console.WriteLine("Successfully mounted the ISO.");
                            mountedISO = true;
                            break;
                        }
                    }
                }catch{
                    Console.WriteLine("Encountered an issue mounting the ISO.");
                }
            }
        }

        if(mountedISO){ //after we mount the ISO, sleep for a few seconds to ensure that the ISO has fully mounted (windows takes a bit to do this) and then find the drive letter for the ISO
            Console.WriteLine("Attempting to find the drive letter of the mounted ISO");
            Thread.Sleep(5000); //needed to ensure that the ISO has time to mount before looking for it
            DriveInfo[] drivesPost = DriveInfo.GetDrives(); //get a new list of drives mounted
            bool oldDrive = false;
            string driveNamePre = "";
            string driveNamePost = "";
            foreach(dynamic drivePost in drivesPost){ //nested foreach for both lists of drives moutned
                try{
                    driveNamePost = drivePost.Name;
                    oldDrive = false;
                    foreach(dynamic drivePre in drivesPre){
                        try{
                            driveNamePre = drivePre.Name;
                            if(driveNamePost == driveNamePre){
                                oldDrive = true;
                            }
                        }catch{
                            oldDrive = true;
                        }
                    }
                    if(!oldDrive){ //if drivePre isn't in the first list of mounted drives, that should be our ISO, so return that letter
                        Console.WriteLine("ISO located at drive letter "+driveNamePost);
                        return driveNamePost;
                    }
                }catch{
                    Console.WriteLine("Encountered an error attempting to find the drive letter of the mounted ISO.");
                }
            }
        }
        return ""; //if something errors or we are unable to find the mounted iso, return an empty string
    }

    public static void EjectISO(string isoPath)
    {
        Console.WriteLine("Attempting to dismount ISO...");
        string command = "dismount-diskimage -imagepath '"+isoPath+"'";
        try{
            Process process = new Process();
            process.StartInfo.FileName = "powershell.exe";
            process.StartInfo.Arguments = "-c \""+command+"\"";
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            process.WaitForExit();
            Console.WriteLine("ISO was successfully dismounted.");
        }catch{
            Console.WriteLine("Encountered an error dismounting the ISO. Please eject manually if it is still mounted.");
        }
    }

    public static void runEXE(string driveName){
        string command = driveName += "run.bat";
        Console.WriteLine(command);

        Console.WriteLine("Attempting to run executable...");
        try{
            Process process = new Process();
            process.StartInfo.FileName = "powershell.exe";
            process.StartInfo.Arguments = "-c "+command;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.RedirectStandardOutput = false;
            process.Start();
            process.WaitForExit();
            Console.WriteLine("Done with execution.");
        }catch{
            Console.WriteLine("Encountered an error running the executable.");
        }
    }
}