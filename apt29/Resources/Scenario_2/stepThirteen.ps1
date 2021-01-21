# This code was derived from http://www.pinvoke.net

function comp {
$Signature=@"
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
static extern bool GetComputerNameEx(COMPUTER_NAME_FORMAT NameType,string lpBuffer, ref uint lpnSize);	
enum COMPUTER_NAME_FORMAT
{ComputerNameNetBIOS,ComputerNameDnsHostname,ComputerNameDnsDomain,ComputerNameDnsFullyQualified,ComputerNamePhysicalNetBIOS,ComputerNamePhysicalDnsHostname,ComputerNamePhysicalDnsDomain,ComputerNamePhysicalDnsFullyQualified}
public static string GCN() {
bool success;
string name = "                    ";
uint size = 20;
success = GetComputerNameEx(COMPUTER_NAME_FORMAT.ComputerNameNetBIOS, name, ref size);
return "NetBIOSName:\t" + name.ToString();
}
"@
Add-Type -MemberDefinition $Signature -Name GetCompNameEx -Namespace Kernel32
$result = [Kernel32.GetCompNameEx]::GCN()
return $result
}
function domain {
$Signature=@"
[DllImport("netapi32.dll", SetLastError=true)]
public static extern int NetWkstaGetInfo(string servername, int level, out IntPtr bufptr);
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WKSTA_INFO_100 {
public int platform_id;
public string computer_name;
public string lan_group;
public int ver_major;
public int ver_minor;
}
public static string NWGI() 
{
string host = null;
IntPtr buffer;
var ret = NetWkstaGetInfo(host, 100, out buffer);
var strut_size = Marshal.SizeOf(typeof (WKSTA_INFO_100));
WKSTA_INFO_100 wksta_info;
wksta_info = (WKSTA_INFO_100) Marshal.PtrToStructure(buffer, typeof (WKSTA_INFO_100));
string domainName = wksta_info.lan_group;
return "DomainName:\t" + domainName.ToString();
}
"@
Add-Type -MemberDefinition $Signature -Name NetWGetInfo -Namespace NetAPI32
$result = [NetAPI32.NetWGetInfo]::NWGI()
return $result
}
function user {
$Signature=@"
[DllImport("secur32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int GetUserNameEx (int nameFormat, string userName, ref int userNameSize);
public static string GUN() {
string uname = "                                        ";
int size = 40;
int EXTENDED_NAME_FORMAT_NAME_DISPLAY = 2;
string ret = "";
if(0 != GetUserNameEx(EXTENDED_NAME_FORMAT_NAME_DISPLAY, uname, ref size))
{
ret += "UserName:\t" + uname.ToString();
}  
return ret;
}
"@
Add-Type -MemberDefinition $Signature -Name GetUNameEx -Namespace Secur32
$result = [Secur32.GetUNameEx]::GUN()
return $result
}
function pslist {
$Signature=@"
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
private struct PROCESSENTRY32
{
const int MAX_PATH = 260;
internal UInt32 dwSize;
internal UInt32 cntUsage;
internal UInt32 th32ProcessID;
internal IntPtr th32DefaultHeapID;
internal UInt32 th32ModuleID;
internal UInt32 cntThreads;
internal UInt32 th32ParentProcessID;
internal Int32 pcPriClassBase;
internal UInt32 dwFlags;
[MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
internal string szExeFile;
}
[DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
static extern IntPtr CreateToolhelp32Snapshot([In]UInt32 dwFlags, [In]UInt32 th32ProcessID);

[DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
static extern bool Process32First([In]IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

[DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
static extern bool Process32Next([In]IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

[DllImport("kernel32", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
private static extern bool CloseHandle([In] IntPtr hObject);

public static string CT32S() {
IntPtr hProcessSnap = CreateToolhelp32Snapshot(0x00000002, 0);
PROCESSENTRY32 procEntry = new PROCESSENTRY32();
procEntry.dwSize = (UInt32)Marshal.SizeOf(typeof(PROCESSENTRY32));
string ret = "";
if (Process32First(hProcessSnap, ref procEntry))
{
do
{
ret += (procEntry.th32ProcessID).ToString() + "\t" + (procEntry.szExeFile).ToString() + "\n";
} while (Process32Next(hProcessSnap, ref procEntry));
}
CloseHandle(hProcessSnap);
return ret;
}
"@
Add-Type -MemberDefinition $Signature -Name CT32Snapshot  -Namespace Kernel32
$result = [Kernel32.CT32Snapshot]::CT32S()
return $result
}