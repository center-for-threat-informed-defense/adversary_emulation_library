function psenum
{
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

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
        $StructureFields,

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

    [Reflection.TypeAttributes] $StructureAttributes = 'Class,Public,Sealed,BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructureAttributes = $StructureAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructureAttributes = $StructureAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    switch($CharSet)
    {
        Ansi{$StructureAttributes = $StructureAttributes -bor [Reflection.TypeAttributes]::AnsiClass}
        Auto{$StructureAttributes = $StructureAttributes -bor [Reflection.TypeAttributes]::AutoClass}
        Unicode{$StructureAttributes = $StructureAttributes -bor [Reflection.TypeAttributes]::UnicodeClass}
    }

    $StructureBuilder = $Module.DefineType($FullName, $StructureAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructureFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructureFields.Keys)
    {
        $Index = $StructureFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructureFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructureBuilder.DefineField($FieldName, $Type, 'Public')

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
    $SizeMethod = $StructureBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructureBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructureBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructureBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructureBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructureBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructureBuilder.CreateType()
}

function Invoke-NtQuerySystemInformation {

    $DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib') 

    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run) 

    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False) 

    $TypeBuilder = $ModuleBuilder.DefineType('Ntdll', 'Public, Class') 

    $PInvokeMethod = $TypeBuilder.DefineMethod('NtQuerySystemInformation', 
                                               [Reflection.MethodAttributes] 'Public, Static', 
                                               [UInt32], 
                                               [Type[]] @([UInt32], [IntPtr],[UInt32], [UInt32].MakeByRefType())) 


    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String])) 
    $FieldArray = [Reflection.FieldInfo[]] @( 
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'), 
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet') 
    ) 

    $FieldValueArray = [Object[]] @( 
        'NtQuerySystemInformation', 
        $True, 
        $True, 
        [Runtime.InteropServices.CallingConvention]::Winapi, 
        [Runtime.InteropServices.CharSet]::Unicode 
    ) 

    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, 
                                                                                     @('Ntdll.dll'), 
                                                                                     $FieldArray, 
                                                                                     $FieldValueArray) 

    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute) 

    $Ntdll = $TypeBuilder.CreateType() 

    $UNICODE_STRING = struct $ModuleBuilder UNICODE_STRING @{
        Length        = field 0 UInt16
        MaximumLength = field 1 UInt16
        Buffer        = field 2 IntPtr
    }

    $LARGE_INTEGER = struct $ModuleBuilder _LARGE_INTEGER @{
        QUADPART    = field 0 Int64  -Offset 0
        LOWPART     = field 1 UInt32 -Offset 0 
        HIGHPART    = field 2 Int32  -Offset 4
    } -ExplicitLayout

    $SystemProcessInformation = struct $ModuleBuilder SystemProcessInformation @{
        NextEntryOffset                 = field 0 UInt32
        NumberOfThreads                 = field 1 UInt32
        SpareLi1                        = field 2 $LARGE_INTEGER
        SpareLi2                        = field 3 $LARGE_INTEGER
        SpareLi3                        = field 4 $LARGE_INTEGER
        CreateTime                      = field 5 $LARGE_INTEGER
        UserTime                        = field 6 $LARGE_INTEGER
        KernelTime                      = field 7 $LARGE_INTEGER
        ImageName                       = field 8 $UNICODE_STRING
        BasePriority                    = field 9 UInt32
        UniqueProcessId                 = field 10 IntPtr
        InheritedFromUniqueProcessId    = field 11 IntPtr
        HandleCount                     = field 12 UInt32
        SessionId                       = field 13 UInt32
        PageDirectoryBase               = field 14 IntPtr
        PeakVirtualSize                 = field 15 IntPtr
        VirtualSize                     = field 16 IntPtr 
        PageFaultCount                  = field 17 UInt32
        PeakWorkingSetSize              = field 18 IntPtr
        WorkingSetSize                  = field 19 IntPtr
        QuotaPeakPagedPoolUsage         = field 20 IntPtr
        QuotaPagedPoolUsage             = field 21 IntPtr
        QuotaPeakNonPagedPoolUsage      = field 22 IntPtr
        QuotaNonPagedPoolUsage          = field 23 IntPtr
        PagefileUsage                   = field 24 IntPtr
        PeakPagefileUsage               = field 25 IntPtr
        PrivatePageCount                = field 26 IntPtr
        ReadOperationCount              = field 27 $LARGE_INTEGER
        WriteOperationCount             = field 28 $LARGE_INTEGER
        OtherOperationCount             = field 29 $LARGE_INTEGER
        ReadTransferCount               = field 30 $LARGE_INTEGER
        WriteTransferCount              = field 31 $LARGE_INTEGER
        OtherTransferCount              = field 32 $LARGE_INTEGER
    }

    [int]$BuffPtr_Size = 0
    while ($true) {
        [IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtr_Size)
        $SystemInformationLength = New-Object Int
        # SystemProcessInformation Class = 5
        $CallResult = $Ntdll::NtQuerySystemInformation(5, $BuffPtr, $BuffPtr_Size, [ref]$SystemInformationLength)
        
        # STATUS_INFO_LENGTH_MISMATCH
        if ($CallResult -eq 3221225476) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
            [int]$BuffPtr_Size = [System.Math]::Max($BuffPtr_Size,$SystemInformationLength)
        }
        # STATUS_SUCCESS
        elseif ($CallResult -eq 0) {
            break
        }
        # Probably: 0xC0000005 -> STATUS_ACCESS_VIOLATION
        else {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
            return
        }
    }
    
    # Create in-memory struct
    $SystemProcessInformation = New-Object SystemProcessInformation
    $SystemProcessInformation = $SystemProcessInformation.GetType()
    $BuffOffset = $BuffPtr.ToInt64()
    
    $SystemModuleArray = @()
    while ($true) {
        $SystemPointer = New-Object System.Intptr -ArgumentList $($BuffOffset)
        $Structure = [system.runtime.interopservices.marshal]::PtrToStructure($SystemPointer,[type]$SystemProcessInformation)
        
        # Get Process Owner
        $ProcessPid = $Structure.UniqueProcessId
        $ProcessOwner = Get-WmiObject Win32_Process -Filter "ProcessId='$ProcessPid'" | Select @{Name="UserName";Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}}
        $ProcessOwner = $ProcessOwner | Select -ExpandProperty UserName
        if ($ProcessOwner -eq "\") { $ProcessOwner = "" }

        $HashTable = @{
            PID = $Structure.UniqueProcessId
            User = $ProcessOwner
            InheritedFromPID = $Structure.InheritedFromUniqueProcessId
            ImageName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Structure.ImageName.Buffer)
            Priority = $Structure.BasePriority
            CreateTime = $Structure.CreateTime
            UserCPU = $Structure.UserTime
            KernelCPU = $Structure.KernelTime
            ThreadCount = $Structure.NumberOfThreads
            HandleCount = $Structure.HandleCount
            PageFaults = $Structure.PageFaultCount
            SessionId = $Structure.SessionId
            PageDirectoryBase = $Structure.PageDirectoryBase
            PeakVirtualSize = "$($Structure.PeakVirtualSize.ToInt64()/[math]::pow(1024,2)) MB"
            VirtualSize = "$($Structure.VirtualSize.ToInt64()/[math]::pow(1024,2)) MB"
            PeakWorkingSetSize = "$($Structure.PeakWorkingSetSize.ToInt64()/[math]::pow(1024,2)) MB"
            WorkingSetSize = "$($Structure.WorkingSetSize.ToInt64()/[math]::pow(1024,2)) MB"
            QuotaPeakPagedPoolUsage = "$($Structure.QuotaPeakPagedPoolUsage.ToInt64()/[math]::pow(1024,2)) MB"
            QuotaPagedPoolUsage = "$($Structure.QuotaPagedPoolUsage.ToInt64()/[math]::pow(1024,2)) MB"
            QuotaPeakNonPagedPoolUsage = "$($Structure.QuotaPeakNonPagedPoolUsage.ToInt64()/[math]::pow(1024,2)) MB"
            QuotaNonPagedPoolUsage = "$($Structure.QuotaNonPagedPoolUsage.ToInt64()/[math]::pow(1024,2)) MB"
            PagefileUsage = "$($Structure.PagefileUsage.ToInt64()/[math]::pow(1024,2)) MB"
            PeakPagefileUsage = "$($Structure.PeakPagefileUsage.ToInt64()/[math]::pow(1024,2)) MB"
            PrivatePageCount = "$($Structure.PrivatePageCount.ToInt64()/[math]::pow(1024,2)) MB"
            ReadOperationCount = $Structure.ReadOperationCount
            WriteOperationCount = $Structure.WriteOperationCount
            OtherOperationCount = $Structure.OtherOperationCount
            ReadTransferCount = $Structure.ReadTransferCount
            WriteTransferCount = $Structure.WriteTransferCount
            OtherTransferCount = $Structure.OtherTransferCount
        }
        $Object = New-Object PSObject -Property $HashTable
        $SystemModuleArray += $Object
    
        # Check if we reached the end of the list
        if ($([System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset)) -eq 0) {
            Break
        } else {
            $BuffOffset = $BuffOffset + $Structure.NextEntryOffset
        }
    }
    
    # Free allocated SystemModuleInformation array
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
    
    # We want this object in a specific order
    $ResultObject = $SystemModuleArray

    $ResultObject | Select-Object PID,@{Name="PPID";Expression={$_.InheritedFromPID}},@{Name="Image";Expression={$_.ImageName}},@{Name="Session";Expression={$_.SessionId}},User | Format-Table
    Return
}

function ProcessList {
    Invoke-NtQuerySystemInformation
}
