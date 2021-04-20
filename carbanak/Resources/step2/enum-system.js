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