#requires -version 2
# Relevant functions pulled from PowerView.ps1 dev branch

function New-InMemoryModule {
    <#
    .SYNOPSIS
    Creates an in-memory assembly and module
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    .DESCRIPTION
    When defining custom enums, structs, and unmanaged functions, it is
    necessary to associate to an assembly module. This helper function
    creates an in-memory module that can be passed to the 'enum',
    'struct', and Add-Win32Type functions.
    .PARAMETER ModuleName
    Specifies the desired name for the in-memory assembly and module. If
    ModuleName is not provided, it will default to a GUID.
    .EXAMPLE
    $Module = New-InMemoryModule -ModuleName Win32
    #>
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

function Add-Win32Type
{
    <#
    .SYNOPSIS
    Creates a .NET type for an unmanaged Win32 function.
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: func
    .DESCRIPTION
    Add-Win32Type enables you to easily interact with unmanaged (i.e.
    Win32 unmanaged) functions in PowerShell. After providing
    Add-Win32Type with a function signature, a .NET type is created
    using reflection (i.e. csc.exe is never called like with Add-Type).
    The 'func' helper function can be used to reduce typing when defining
    multiple function definitions.
    .PARAMETER DllName
    The name of the DLL.
    .PARAMETER FunctionName
    The name of the target function.
    .PARAMETER EntryPoint
    The DLL export function name. This argument should be specified if the
    specified function name is different than the name of the exported
    function.
    .PARAMETER ReturnType
    The return type of the function.
    .PARAMETER ParameterTypes
    The function parameters.
    .PARAMETER NativeCallingConvention
    Specifies the native calling convention of the function. Defaults to
    stdcall.
    .PARAMETER Charset
    If you need to explicitly call an 'A' or 'W' Win32 function, you can
    specify the character set.
    .PARAMETER SetLastError
    Indicates whether the callee calls the SetLastError Win32 API
    function before returning from the attributed method.
    .PARAMETER Module
    The in-memory module that will host the functions. Use
    New-InMemoryModule to define an in-memory module.
    .PARAMETER Namespace
    An optional namespace to prepend to the type. Add-Win32Type defaults
    to a namespace consisting only of the name of the DLL.
    .EXAMPLE
    $Mod = New-InMemoryModule -ModuleName Win32
    $FunctionDefinitions = @(
    (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
    (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
    (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
    )
    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
    $Kernel32 = $Types['kernel32']
    $Ntdll = $Types['ntdll']
    $Ntdll::RtlGetCurrentPeb()
    $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
    $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')
    .NOTES
    Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189
    When defining multiple function prototypes, it is ideal to provide
    Add-Win32Type with an array of function signatures. That way, they
    are all incorporated into the same in-memory module.
    #>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function psenum {
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
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
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

function Get-Domain {
    <#
    .SYNOPSIS
    Returns the domain object for the current (or specified) domain.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
    domain or the domain specified with -Domain X.
    .PARAMETER Domain
    Specifies the domain name to query for, defaults to the current domain.
    .PARAMETER Credential
    A [Management.Automation.PSCredential] object of alternate credentials
    for connection to the target domain.
    .EXAMPLE
    Get-Domain -Domain testlab.local
    .EXAMPLE
    $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
    Get-Domain -Credential $Cred
    .OUTPUTS
    System.DirectoryServices.ActiveDirectory.Domain
    A complex .NET domain object.
    .LINK
    http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
    #>
    
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[Get-Domain] Using alternate credentials for Get-Domain'

            if ($PSBoundParameters['Domain']) {
                $TargetDomain = $Domain
            }
            else {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-Domain] Extracted domain '$TargetDomain' from -Credential"
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-Domain] Error retrieving the current domain: $_"
            }
        }
    }
}

# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}

# A helper function used to reduce typing while defining struct
# fields.
function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
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
.PARAMETER Module
The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER FullName
The fully-qualified name of the struct.
.PARAMETER StructFields
A hashtable of fields. Use the 'field' helper function to ease
defining each field.
.PARAMETER PackingSize
Specifies the memory alignment of fields.
.PARAMETER ExplicitLayout
Indicates that an explicit offset for each field will be specified.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}
$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}
# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout
.NOTES
PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
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

function Convert-LDAPProperty {
    <#
    .SYNOPSIS
    Helper that converts specific LDAP property result fields and outputs
    a custom psobject.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    Converts a set of raw LDAP properties results from ADSI/LDAP searches
    into a proper PSObject. Used by several of the Get-Domain* function.
    .PARAMETER Properties
    Properties object to extract out LDAP fields for display.
    .OUTPUTS
    System.Management.Automation.PSCustomObject
    A custom PSObject with LDAP hashtable properties translated.
    #>
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                # convert all listed sids (i.e. if multiple are listed in sidHistory)
                $ObjectProperties[$_] = $Properties[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $GroupTypeEnum
            }
            elseif ($_ -eq 'samaccounttype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $SamAccountTypeEnum
            }
            elseif ($_ -eq 'objectguid') {
                # convert the GUID to a string
                $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $UACEnum
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                # $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if ($Descriptor.Owner) {
                    $ObjectProperties['Owner'] = $Descriptor.Owner
                }
                if ($Descriptor.Group) {
                    $ObjectProperties['Group'] = $Descriptor.Group
                }
                if ($Descriptor.DiscretionaryAcl) {
                    $ObjectProperties['DiscretionaryAcl'] = $Descriptor.DiscretionaryAcl
                }
                if ($Descriptor.SystemAcl) {
                    $ObjectProperties['SystemAcl'] = $Descriptor.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ObjectProperties[$_] = "NEVER"
                }
                else {
                    $ObjectProperties[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                # convert timestamps
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    # if we have a System.__ComObject
                    $Temp = $Properties[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    # otherwise just a string
                    $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # try to convert misc com objects
                $Prop = $Properties[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[Convert-LDAPProperty] error: $_"
                    $ObjectProperties[$_] = $Prop[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                $ObjectProperties[$_] = $Properties[$_][0]
            }
            else {
                $ObjectProperties[$_] = $Properties[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $ObjectProperties
    }
    catch {
        Write-Warning "[Convert-LDAPProperty] Error parsing LDAP properties : $_"
    }
}

Function New-DynamicParameter {
    <#
    .SYNOPSIS
    Helper function to simplify creating dynamic parameters.
        Adapated from https://beatcracker.wordpress.com/2015/08/10/dynamic-parameters-validateset-and-enums/.
        Originally released under the Microsoft Public License (Ms-PL).
    .DESCRIPTION
    Helper function to simplify creating dynamic parameters.
    Example use cases:
        Include parameters only if your environment dictates it
        Include parameters depending on the value of a user-specified parameter
        Provide tab completion and intellisense for parameters, depending on the environment
    Please keep in mind that all dynamic parameters you create, will not have corresponding variables created.
        Use New-DynamicParameter with 'CreateVariables' switch in your main code block,
        ('Process' for advanced functions) to create those variables.
        Alternatively, manually reference $PSBoundParameters for the dynamic parameter value.
    This function has two operating modes:
    1. All dynamic parameters created in one pass using pipeline input to the function. This mode allows to create dynamic parameters en masse,
    with one function call. There is no need to create and maintain custom RuntimeDefinedParameterDictionary.
    2. Dynamic parameters are created by separate function calls and added to the RuntimeDefinedParameterDictionary you created beforehand.
    Then you output this RuntimeDefinedParameterDictionary to the pipeline. This allows more fine-grained control of the dynamic parameters,
    with custom conditions and so on.
    .NOTES
    Credits to jrich523 and ramblingcookiemonster for their initial code and inspiration:
        https://github.com/RamblingCookieMonster/PowerShell/blob/master/New-DynamicParam.ps1
        http://ramblingcookiemonster.wordpress.com/2014/11/27/quick-hits-credentials-and-dynamic-parameters/
        http://jrich523.wordpress.com/2013/05/30/powershell-simple-way-to-add-dynamic-parameters-to-advanced-function/
    Credit to BM for alias and type parameters and their handling
    .PARAMETER Name
    Name of the dynamic parameter
    .PARAMETER Type
    Type for the dynamic parameter.  Default is string
    .PARAMETER Alias
    If specified, one or more aliases to assign to the dynamic parameter
    .PARAMETER Mandatory
    If specified, set the Mandatory attribute for this dynamic parameter
    .PARAMETER Position
    If specified, set the Position attribute for this dynamic parameter
    .PARAMETER HelpMessage
    If specified, set the HelpMessage for this dynamic parameter
    .PARAMETER DontShow
    If specified, set the DontShow for this dynamic parameter.
    This is the new PowerShell 4.0 attribute that hides parameter from tab-completion.
    http://www.powershellmagazine.com/2013/07/29/pstip-hiding-parameters-from-tab-completion/
    .PARAMETER ValueFromPipeline
    If specified, set the ValueFromPipeline attribute for this dynamic parameter
    .PARAMETER ValueFromPipelineByPropertyName
    If specified, set the ValueFromPipelineByPropertyName attribute for this dynamic parameter
    .PARAMETER ValueFromRemainingArguments
    If specified, set the ValueFromRemainingArguments attribute for this dynamic parameter
    .PARAMETER ParameterSetName
    If specified, set the ParameterSet attribute for this dynamic parameter. By default parameter is added to all parameters sets.
    .PARAMETER AllowNull
    If specified, set the AllowNull attribute of this dynamic parameter
    .PARAMETER AllowEmptyString
    If specified, set the AllowEmptyString attribute of this dynamic parameter
    .PARAMETER AllowEmptyCollection
    If specified, set the AllowEmptyCollection attribute of this dynamic parameter
    .PARAMETER ValidateNotNull
    If specified, set the ValidateNotNull attribute of this dynamic parameter
    .PARAMETER ValidateNotNullOrEmpty
    If specified, set the ValidateNotNullOrEmpty attribute of this dynamic parameter
    .PARAMETER ValidateRange
    If specified, set the ValidateRange attribute of this dynamic parameter
    .PARAMETER ValidateLength
    If specified, set the ValidateLength attribute of this dynamic parameter
    .PARAMETER ValidatePattern
    If specified, set the ValidatePattern attribute of this dynamic parameter
    .PARAMETER ValidateScript
    If specified, set the ValidateScript attribute of this dynamic parameter
    .PARAMETER ValidateSet
    If specified, set the ValidateSet attribute of this dynamic parameter
    .PARAMETER Dictionary
    If specified, add resulting RuntimeDefinedParameter to an existing RuntimeDefinedParameterDictionary.
    Appropriate for custom dynamic parameters creation.
    If not specified, create and return a RuntimeDefinedParameterDictionary
    Appropriate for a simple dynamic parameter creation.
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'DynamicParameter')]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [System.Type]$Type = [int],

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string[]]$Alias,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$Mandatory,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [int]$Position,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$HelpMessage,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$DontShow,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromPipeline,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromPipelineByPropertyName,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromRemainingArguments,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$ParameterSetName = '__AllParameterSets',

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowNull,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowEmptyString,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowEmptyCollection,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValidateNotNull,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValidateNotNullOrEmpty,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateCount,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateRange,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateLength,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$ValidatePattern,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$ValidateScript,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ValidateSet,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw 'Dictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object'
            }
            $true
        })]
        $Dictionary = $false,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [switch]$CreateVariables,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            # System.Management.Automation.PSBoundParametersDictionary is an internal sealed class,
            # so one can't use PowerShell's '-is' operator to validate type.
            if($_.GetType().Name -notmatch 'Dictionary') {
                Throw 'BoundParameters must be a System.Management.Automation.PSBoundParametersDictionary object'
            }
            $true
        })]
        $BoundParameters
    )

    Begin {
        $InternalDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function _temp { [CmdletBinding()] Param() }
        $CommonParameters = (Get-Command _temp).Parameters.Keys
    }

    Process {
        if($CreateVariables) {
            $BoundKeys = $BoundParameters.Keys | Where-Object { $CommonParameters -notcontains $_ }
            ForEach($Parameter in $BoundKeys) {
                if ($Parameter) {
                    Set-Variable -Name $Parameter -Value $BoundParameters.$Parameter -Scope 1 -Force
                }
            }
        }
        else {
            $StaleKeys = @()
            $StaleKeys = $PSBoundParameters.GetEnumerator() |
                        ForEach-Object {
                            if($_.Value.PSobject.Methods.Name -match '^Equals$') {
                                # If object has Equals, compare bound key and variable using it
                                if(!$_.Value.Equals((Get-Variable -Name $_.Key -ValueOnly -Scope 0))) {
                                    $_.Key
                                }
                            }
                            else {
                                # If object doesn't has Equals (e.g. $null), fallback to the PowerShell's -ne operator
                                if($_.Value -ne (Get-Variable -Name $_.Key -ValueOnly -Scope 0)) {
                                    $_.Key
                                }
                            }
                        }
            if($StaleKeys) {
                $StaleKeys | ForEach-Object {[void]$PSBoundParameters.Remove($_)}
            }

            # Since we rely solely on $PSBoundParameters, we don't have access to default values for unbound parameters
            $UnboundParameters = (Get-Command -Name ($PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |
                                        # Find parameters that are belong to the current parameter set
                                        Where-Object { $_.Value.ParameterSets.Keys -contains $PsCmdlet.ParameterSetName } |
                                            Select-Object -ExpandProperty Key |
                                                # Find unbound parameters in the current parameter set
                                                Where-Object { $PSBoundParameters.Keys -notcontains $_ }

            # Even if parameter is not bound, corresponding variable is created with parameter's default value (if specified)
            $tmp = $null
            ForEach ($Parameter in $UnboundParameters) {
                $DefaultValue = Get-Variable -Name $Parameter -ValueOnly -Scope 0
                if(!$PSBoundParameters.TryGetValue($Parameter, [ref]$tmp) -and $DefaultValue) {
                    $PSBoundParameters.$Parameter = $DefaultValue
                }
            }

            if($Dictionary) {
                $DPDictionary = $Dictionary
            }
            else {
                $DPDictionary = $InternalDictionary
            }

            # Shortcut for getting local variables
            $GetVar = {Get-Variable -Name $_ -ValueOnly -Scope 0}

            # Strings to match attributes and validation arguments
            $AttributeRegex = '^(Mandatory|Position|ParameterSetName|DontShow|HelpMessage|ValueFromPipeline|ValueFromPipelineByPropertyName|ValueFromRemainingArguments)$'
            $ValidationRegex = '^(AllowNull|AllowEmptyString|AllowEmptyCollection|ValidateCount|ValidateLength|ValidatePattern|ValidateRange|ValidateScript|ValidateSet|ValidateNotNull|ValidateNotNullOrEmpty)$'
            $AliasRegex = '^Alias$'
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute

            switch -regex ($PSBoundParameters.Keys) {
                $AttributeRegex {
                    Try {
                        $ParameterAttribute.$_ = . $GetVar
                    }
                    Catch {
                        $_
                    }
                    continue
                }
            }

            if($DPDictionary.Keys -contains $Name) {
                $DPDictionary.$Name.Attributes.Add($ParameterAttribute)
            }
            else {
                $AttributeCollection = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex ($PSBoundParameters.Keys) {
                    $ValidationRegex {
                        Try {
                            $ParameterOptions = New-Object -TypeName "System.Management.Automation.${_}Attribute" -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterOptions)
                        }
                        Catch { $_ }
                        continue
                    }
                    $AliasRegex {
                        Try {
                            $ParameterAlias = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterAlias)
                            continue
                        }
                        Catch { $_ }
                    }
                }
                $AttributeCollection.Add($ParameterAttribute)
                $Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $AttributeCollection)
                $DPDictionary.Add($Name, $Parameter)
            }
        }
    }

    End {
        if(!$CreateVariables -and !$Dictionary) {
            $DPDictionary
        }
    }
}

function Get-DomainComputer {
    <#
    .SYNOPSIS
    Return all computers or specific computer objects in AD.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  
    .DESCRIPTION
    Builds a directory searcher object using Get-DomainSearcher, builds a custom
    LDAP filter based on targeting/filter parameters, and searches for all objects
    matching the criteria. To only return specific properties, use
    "-Properties samaccountname,usnchanged,...". By default, all computer objects for
    the current domain are returned.
    .PARAMETER Identity
    A SamAccountName (e.g. WINDOWS10$), DistinguishedName (e.g. CN=WINDOWS10,CN=Computers,DC=testlab,DC=local),
    SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1124), GUID (e.g. 4f16b6bc-7010-4cbf-b628-f3cfe20f6994),
    or a dns host name (e.g. windows10.testlab.local). Wildcards accepted.
    .PARAMETER UACFilter
    Dynamic parameter that accepts one or more values from $UACEnum, including
    "NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.
    .PARAMETER Unconstrained
    Switch. Return computer objects that have unconstrained delegation.
    .PARAMETER TrustedToAuth
    Switch. Return computer objects that are trusted to authenticate for other principals.
    .PARAMETER Printers
    Switch. Return only printers.
    .PARAMETER SPN
    Return computers with a specific service principal name, wildcards accepted.
    .PARAMETER OperatingSystem
    Return computers with a specific operating system, wildcards accepted.
    .PARAMETER ServicePack
    Return computers with a specific service pack, wildcards accepted.
    .PARAMETER SiteName
    Return computers in the specific AD Site name, wildcards accepted.
    .PARAMETER Ping
    Switch. Ping each host to ensure it's up before enumerating.
    .PARAMETER Domain
    Specifies the domain to use for the query, defaults to the current domain.
    .PARAMETER LDAPFilter
    Specifies an LDAP query string that is used to filter Active Directory objects.
    .PARAMETER Properties
    Specifies the properties of the output object to retrieve from the server.
    .PARAMETER SearchBase
    The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
    Useful for OU queries.
    .PARAMETER Server
    Specifies an Active Directory server (domain controller) to bind to.
    .PARAMETER SearchScope
    Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).
    .PARAMETER ResultPageSize
    Specifies the PageSize to set for the LDAP searcher object.
    .PARAMETER ServerTimeLimit
    Specifies the maximum amount of time the server spends searching. Default of 120 seconds.
    .PARAMETER SecurityMasks
    Specifies an option for examining security information of a directory object.
    One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.
    .PARAMETER Tombstone
    Switch. Specifies that the searcher should also return deleted/tombstoned objects.
    .PARAMETER FindOne
    Only return one result object.
    .PARAMETER Credential
    A [Management.Automation.PSCredential] object of alternate credentials
    for connection to the target domain.
    .PARAMETER Raw
    Switch. Return raw results instead of translating the fields into a custom PSObject.
    .EXAMPLE
    Get-DomainComputer
    Returns the current computers in current domain.
    .EXAMPLE
    Get-DomainComputer -SPN mssql* -Domain testlab.local
    Returns all MS SQL servers in the testlab.local domain.
    .EXAMPLE
    Get-DomainComputer -UACFilter TRUSTED_FOR_DELEGATION,SERVER_TRUST_ACCOUNT -Properties dnshostname
    Return the dns hostnames of servers trusted for delegation.
    .EXAMPLE
    Get-DomainComputer -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -Unconstrained
    Search the specified OU for computeres that allow unconstrained delegation.
    .EXAMPLE
    $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
    Get-DomainComputer -Credential $Cred
    .OUTPUTS
    PowerView.Computer
    Custom PSObject with translated computer property fields.
    PowerView.Computer.Raw
    The raw DirectoryServices.SearchResult object, if -Raw is enabled.
    #>
    
    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $Identity,

        [Switch]
        $Unconstrained,

        [Switch]
        $TrustedToAuth,

        [Switch]
        $Printers,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        $SPN,

        [ValidateNotNullOrEmpty()]
        [String]
        $OperatingSystem,

        [ValidateNotNullOrEmpty()]
        [String]
        $ServicePack,

        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,

        [Switch]
        $Ping,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        # add in the negations
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $CompSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }

        if ($CompSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainComputer] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $CompSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $CompSearcher) {
                            Write-Warning "[Get-DomainComputer] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                else {
                    $IdentityFilter += "(name=$IdentityInstance)"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['Unconstrained']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers with for unconstrained delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['Printers']) {
                Write-Verbose '[Get-DomainComputer] Searching for printers'
                $Filter += '(objectCategory=printQueue)'
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if ($PSBoundParameters['OperatingSystem']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with operating system: $OperatingSystem"
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if ($PSBoundParameters['ServicePack']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with service pack: $ServicePack"
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }
            if ($PSBoundParameters['SiteName']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with site name: $SiteName"
                $Filter += "(serverreferencebl=$SiteName)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainComputer] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $CompSearcher.filter = "(&(samAccountType=805306369)$Filter)"
            Write-Verbose "[Get-DomainComputer] Get-DomainComputer filter string: $($CompSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $CompSearcher.FindOne() }
            else { $Results = $CompSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                $Up = $True
                if ($PSBoundParameters['Ping']) {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                }
                if ($Up) {
                    if ($PSBoundParameters['Raw']) {
                        # return raw result objects
                        $Computer = $_
                        $Computer.PSObject.TypeNames.Insert(0, 'PowerView.Computer.Raw')
                    }
                    else {
                        $Computer = Convert-LDAPProperty -Properties $_.Properties
                        $Computer.PSObject.TypeNames.Insert(0, 'PowerView.Computer')
                    }
                    $Computer
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainComputer] Error disposing of the Results object: $_"
                }
            }
            $CompSearcher.dispose()
        }
    }
}

function Get-DomainSearcher {
    <#
    .SYNOPSIS
    Helper used by various functions that builds a custom AD searcher object.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: Get-Domain  
    .DESCRIPTION
    Takes a given domain and a number of customizations and returns a
    System.DirectoryServices.DirectorySearcher object. This function is used
    heavily by other LDAP/ADSI searcher functions (Verb-Domain*).
    .PARAMETER Domain
    Specifies the domain to use for the query, defaults to the current domain.
    .PARAMETER LDAPFilter
    Specifies an LDAP query string that is used to filter Active Directory objects.
    .PARAMETER Properties
    Specifies the properties of the output object to retrieve from the server.
    .PARAMETER SearchBase
    The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
    Useful for OU queries.
    .PARAMETER SearchBasePrefix
    Specifies a prefix for the LDAP search string (i.e. "CN=Sites,CN=Configuration").
    .PARAMETER Server
    Specifies an Active Directory server (domain controller) to bind to for the search.
    .PARAMETER SearchScope
    Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).
    .PARAMETER ResultPageSize
    Specifies the PageSize to set for the LDAP searcher object.
    .PARAMETER ResultPageSize
    Specifies the PageSize to set for the LDAP searcher object.
    .PARAMETER ServerTimeLimit
    Specifies the maximum amount of time the server spends searching. Default of 120 seconds.
    .PARAMETER SecurityMasks
    Specifies an option for examining security information of a directory object.
    One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.
    .PARAMETER Tombstone
    Switch. Specifies that the searcher should also return deleted/tombstoned objects.
    .PARAMETER Credential
    A [Management.Automation.PSCredential] object of alternate credentials
    for connection to the target domain.
    .EXAMPLE
    Get-DomainSearcher -Domain testlab.local
    Return a searcher for all objects in testlab.local.
    .EXAMPLE
    Get-DomainSearcher -Domain testlab.local -LDAPFilter '(samAccountType=805306368)' -Properties 'SamAccountName,lastlogon'
    Return a searcher for user objects in testlab.local and only return the SamAccountName and LastLogon properties.
    .EXAMPLE
    Get-DomainSearcher -SearchBase "LDAP://OU=secret,DC=testlab,DC=local"
    Return a searcher that searches through the specific ADS/LDAP search base (i.e. OU).
    .OUTPUTS
    System.DirectoryServices.DirectorySearcher
    #>
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $TargetDomain = $Domain

            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                # see if we can grab the user DNS logon domain from environment variables
                $UserDomain = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $UserDomain) {
                    $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$UserDomain"
                }
            }
        }
        elseif ($PSBoundParameters['Credential']) {
            # if not -Domain is specified, but -Credential is, try to retrieve the current domain name with Get-Domain
            $DomainObject = Get-Domain -Credential $Credential
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            # see if we can grab the user DNS logon domain from environment variables
            $TargetDomain = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomain) {
                $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
        }
        else {
            # otherwise, resort to Get-Domain to retrieve the current domain object
            write-verbose "get-domain"
            $DomainObject = Get-Domain
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }

        if ($PSBoundParameters['Server']) {
            # if there's not a specified server to bind to, try to pull a logon server from ENV variables
            $BindServer = $Server
        }

        $SearchString = 'LDAP://'

        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }

        if ($PSBoundParameters['SearchBasePrefix']) {
            $SearchString += $SearchBasePrefix + ','
        }

        if ($PSBoundParameters['SearchBase']) {
            if ($SearchBase -Match '^GC://') {
                # if we're searching the global catalog, get the path in the right format
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match '^LDAP://') {
                    if ($SearchBase -match "LDAP://.+/.+") {
                        $SearchString = ''
                        $DN = $SearchBase
                    }
                    else {
                        $DN = $SearchBase.SubString(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            # transform the target domain name into a distinguishedName if an ADS search base is not specified
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        $SearchString += $DN
        Write-Verbose "[Get-DomainSearcher] search base: $SearchString"

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[Get-DomainSearcher] Using alternate credentials for LDAP connection"
            # bind to the inital search object using alternate credentials
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            # bind to the inital object using the current credentials
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters['ServerTimeLimit']) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }

        if ($PSBoundParameters['Tombstone']) {
            $Searcher.Tombstone = $True
        }

        if ($PSBoundParameters['LDAPFilter']) {
            $Searcher.filter = $LDAPFilter
        }

        if ($PSBoundParameters['SecurityMasks']) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters['Properties']) {
            # handle an array of properties to load w/ the possibility of comma-separated strings
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(',') }
            $Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}

function Test-AdminAccess {
    <#
    .SYNOPSIS
    Tests if the current user has administrative access to the local (or a remote) machine.
    Idea stolen from the local_admin_search_enum post module in Metasploit written by:  
        'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'  
        'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'  
        'Royce Davis "r3dy" <rdavis[at]accuvant.com>'  
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  
    .DESCRIPTION
    This function will use the OpenSCManagerW Win32API call to establish
    a handle to the remote host. If this succeeds, the current user context
    has local administrator acess to the target.
    .PARAMETER ComputerName
    Specifies the hostname to check for local admin access (also accepts IP addresses).
    Defaults to 'localhost'.
    .PARAMETER Credential
    A [Management.Automation.PSCredential] object of alternate credentials
    for connection to the remote system using Invoke-UserImpersonation.
    .EXAMPLE
    Test-AdminAccess -ComputerName sqlserver
    Returns results indicating whether the current user has admin access to the 'sqlserver' host.
    .EXAMPLE
    Get-DomainComputer | Test-AdminAccess
    Returns what machines in the domain the current user has access to.
    .EXAMPLE
    $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
    Test-AdminAccess -ComputerName sqlserver -Credential $Cred
    .OUTPUTS
    PowerView.AdminAccess
    A PSCustomObject containing the ComputerName and 'IsAdmin' set to whether
    the current user has local admin rights, along with the ComputerName added.
    .LINK
    https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
    http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
    #>
    
    [OutputType('PowerView.AdminAccess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # 0xF003F - SC_MANAGER_ALL_ACCESS
            #   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
            $Handle = $Advapi32::OpenSCManagerW("\\$Computer", 'ServicesActive', 0xF003F);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            $IsAdmin = New-Object PSObject
            $IsAdmin | Add-Member Noteproperty 'ComputerName' $Computer

            # if we get a non-zero handle back, everything was successful
            if ($Handle -ne 0) {
                $Null = $Advapi32::CloseServiceHandle($Handle)
                $IsAdmin | Add-Member Noteproperty 'IsAdmin' $True
            }
            else {
                Write-Verbose "[Test-AdminAccess] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                $IsAdmin | Add-Member Noteproperty 'IsAdmin' $False
            }
            $IsAdmin.PSObject.TypeNames.Insert(0, 'PowerView.AdminAccess')
            $IsAdmin
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}

function New-ThreadedFunction {
    # Helper used by any threaded host enumeration functions
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        $ComputerName,

        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 2)]
        [Hashtable]
        $ScriptParameters,

        [Int]
        [ValidateRange(1,  100)]
        $Threads = 20,

        [Switch]
        $NoImports
    )

    BEGIN {
        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        # # $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        # force a single-threaded apartment state (for token-impersonation stuffz)
        $SessionState.ApartmentState = [System.Threading.ApartmentState]::STA

        # import the current session state's variables and functions so the chained PowerView
        #   functionality can be used by the threaded blocks
        if (-not $NoImports) {
            # grab all the current variables for this runspace
            $MyVars = Get-Variable -Scope 2

            # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
            $VorbiddenVars = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')

            # add Variables from Parent Scope (current runspace) into the InitialSessionState
            ForEach ($Var in $MyVars) {
                if ($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            # add Functions from current runspace to the InitialSessionState
            ForEach ($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        #   Thanks Carlos!

        # create a pool of maxThread runspaces
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        # do some trickery to get the proper BeginInvoke() method that allows for an output queue
        $Method = $Null
        ForEach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' }) {
            $MethodParameters = $M.GetParameters()
            if (($MethodParameters.Count -eq 2) -and $MethodParameters[0].Name -eq 'input' -and $MethodParameters[1].Name -eq 'output') {
                $Method = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $Jobs = @()
        $ComputerName = $ComputerName | Where-Object {$_ -and $_.Trim()}
        Write-Verbose "[New-ThreadedFunction] Total number of hosts: $($ComputerName.count)"

        # partition all hosts from -ComputerName into $Threads number of groups
        if ($Threads -ge $ComputerName.Length) {
            $Threads = $ComputerName.Length
        }
        $ElementSplitSize = [Int]($ComputerName.Length/$Threads)
        $ComputerNamePartitioned = @()
        $Start = 0
        $End = $ElementSplitSize

        for($i = 1; $i -le $Threads; $i++) {
            $List = New-Object System.Collections.ArrayList
            if ($i -eq $Threads) {
                $End = $ComputerName.Length
            }
            $List.AddRange($ComputerName[$Start..($End-1)])
            $Start += $ElementSplitSize
            $End += $ElementSplitSize
            $ComputerNamePartitioned += @(,@($List.ToArray()))
        }

        Write-Verbose "[New-ThreadedFunction] Total number of threads/partitions: $Threads"

        ForEach ($ComputerNamePartition in $ComputerNamePartitioned) {
            # create a "powershell pipeline runner"
            $PowerShell = [PowerShell]::Create()
            $PowerShell.runspacepool = $Pool

            # add the script block + arguments with the given computer partition
            $Null = $PowerShell.AddScript($ScriptBlock).AddParameter('ComputerName', $ComputerNamePartition)
            if ($ScriptParameters) {
                ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                    $Null = $PowerShell.AddParameter($Param.Name, $Param.Value)
                }
            }

            # create the output queue
            $Output = New-Object Management.Automation.PSDataCollection[Object]

            # kick off execution using the BeginInvok() method that allows queues
            $Jobs += @{
                PS = $PowerShell
                Output = $Output
                Result = $Method.Invoke($PowerShell, @($Null, [Management.Automation.PSDataCollection[Object]]$Output))
            }
        }
    }

    END {
        Write-Verbose "[New-ThreadedFunction] Threads executing"

        # continuously loop through each job queue, consuming output as appropriate
        Do {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While (($Jobs | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)

        $SleepSeconds = 100
        Write-Verbose "[New-ThreadedFunction] Waiting $SleepSeconds seconds for final cleanup..."

        # cleanup- make sure we didn't miss anything
        for ($i=0; $i -lt $SleepSeconds; $i++) {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
                $Job.PS.Dispose()
            }
            Start-Sleep -S 1
        }

        $Pool.Dispose()
        Write-Verbose "[New-ThreadedFunction] all threads completed"
    }
}

function Find-LocalAdminAccess {
    <#
    .SYNOPSIS
    Finds machines on the local domain where the current user has local administrator access.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Test-AdminAccess, New-ThreadedFunction  
    .DESCRIPTION
    This function enumerates all machines on the current (or specified) domain
    using Get-DomainComputer, and for each computer it checks if the current user
    has local administrator access using Test-AdminAccess. If -Credential is passed,
    then Invoke-UserImpersonation is used to impersonate the specified user
    before enumeration, reverting after with Invoke-RevertToSelf.
    Idea adapted from the local_admin_search_enum post module in Metasploit written by:
        'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'
        'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'
        'Royce Davis "r3dy" <rdavis[at]accuvant.com>'
    .PARAMETER ComputerName
    Specifies an array of one or more hosts to enumerate, passable on the pipeline.
    If -ComputerName is not passed, the default behavior is to enumerate all machines
    in the domain returned by Get-DomainComputer.
    .PARAMETER ComputerDomain
    Specifies the domain to query for computers, defaults to the current domain.
    .PARAMETER ComputerLDAPFilter
    Specifies an LDAP query string that is used to search for computer objects.
    .PARAMETER ComputerSearchBase
    Specifies the LDAP source to search through for computers,
    e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.
    .PARAMETER ComputerOperatingSystem
    Search computers with a specific operating system, wildcards accepted.
    .PARAMETER ComputerServicePack
    Search computers with a specific service pack, wildcards accepted.
    .PARAMETER ComputerSiteName
    Search computers in the specific AD Site name, wildcards accepted.
    .PARAMETER CheckShareAccess
    Switch. Only display found shares that the local user has access to.
    .PARAMETER Server
    Specifies an Active Directory server (domain controller) to bind to.
    .PARAMETER SearchScope
    Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).
    .PARAMETER ResultPageSize
    Specifies the PageSize to set for the LDAP searcher object.
    .PARAMETER ServerTimeLimit
    Specifies the maximum amount of time the server spends searching. Default of 120 seconds.
    .PARAMETER Tombstone
    Switch. Specifies that the searcher should also return deleted/tombstoned objects.
    .PARAMETER Credential
    A [Management.Automation.PSCredential] object of alternate credentials
    for connection to the target domain and target systems.
    .PARAMETER Delay
    Specifies the delay (in seconds) between enumerating hosts, defaults to 0.
    .PARAMETER Jitter
    Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3
    .PARAMETER Threads
    The number of threads to use for user searching, defaults to 20.
    .EXAMPLE
    Find-LocalAdminAccess
    Finds machines in the current domain the current user has admin access to.
    .EXAMPLE
    Find-LocalAdminAccess -Domain dev.testlab.local
    Finds machines in the dev.testlab.local domain the current user has admin access to.
    .EXAMPLE
    $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
    Find-LocalAdminAccess -Domain testlab.local -Credential $Cred
    Finds machines in the testlab.local domain that the user with the specified -Credential
    has admin access to.
    .OUTPUTS
    String
    Computer dnshostnames the current user has administrative access to.
    #>
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Switch]
        $CheckShareAccess,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $ComputerSearcherArguments['Domain'] = $ComputerDomain }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $ComputerSearcherArguments['LDAPFilter'] = $ComputerLDAPFilter }
        if ($PSBoundParameters['ComputerSearchBase']) { $ComputerSearcherArguments['SearchBase'] = $ComputerSearchBase }
        if ($PSBoundParameters['Unconstrained']) { $ComputerSearcherArguments['Unconstrained'] = $Unconstrained }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $ComputerSearcherArguments['OperatingSystem'] = $OperatingSystem }
        if ($PSBoundParameters['ComputerServicePack']) { $ComputerSearcherArguments['ServicePack'] = $ServicePack }
        if ($PSBoundParameters['ComputerSiteName']) { $ComputerSearcherArguments['SiteName'] = $SiteName }
        if ($PSBoundParameters['Server']) { $ComputerSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ComputerSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ComputerSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ComputerSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ComputerSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ComputerSearcherArguments['Credential'] = $Credential }

        if ($PSBoundParameters['ComputerName']) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose '[Find-LocalAdminAccess] Querying computers in the domain'
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-LocalAdminAccess] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw '[Find-LocalAdminAccess] No hosts found to enumerate'
        }

        # the host enumeration block we're using to enumerate all servers
        $HostEnumBlock = {
            Param($ComputerName, $TokenHandle)

            if ($TokenHandle) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    # check if the current user has local admin access to this server
                    $Access = Test-AdminAccess -ComputerName $TargetComputer
                    if ($Access.IsAdmin) {
                        $TargetComputer
                    }
                }
            }

            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-LocalAdminAccess] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-LocalAdminAccess] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[Find-LocalAdminAccess] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $LogonToken
            }
        }
        else {
            Write-Verbose "[Find-LocalAdminAccess] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            $ScriptParams = @{
                'TokenHandle' = $LogonToken
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}

########################################################
#
# Expose the Win32API functions and datastructures below
# using PSReflect.
# Warning: Once these are executed, they are baked in
# and can't be changed while the script is running!
#
########################################################

$Mod = New-InMemoryModule -ModuleName Win32

# [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', Scope='Function', Target='psenum')]

# used to parse the 'samAccountType' property for users/computers/groups
$SamAccountTypeEnum = psenum $Mod PowerView.SamAccountTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   '0x00000000'
    GROUP_OBJECT                    =   '0x10000000'
    NON_SECURITY_GROUP_OBJECT       =   '0x10000001'
    ALIAS_OBJECT                    =   '0x20000000'
    NON_SECURITY_ALIAS_OBJECT       =   '0x20000001'
    USER_OBJECT                     =   '0x30000000'
    MACHINE_ACCOUNT                 =   '0x30000001'
    TRUST_ACCOUNT                   =   '0x30000002'
    APP_BASIC_GROUP                 =   '0x40000000'
    APP_QUERY_GROUP                 =   '0x40000001'
    ACCOUNT_TYPE_MAX                =   '0x7fffffff'
}

# used to parse the 'grouptype' property for groups
$GroupTypeEnum = psenum $Mod PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   '0x00000001'
    GLOBAL_SCOPE                    =   '0x00000002'
    DOMAIN_LOCAL_SCOPE              =   '0x00000004'
    UNIVERSAL_SCOPE                 =   '0x00000008'
    APP_BASIC                       =   '0x00000010'
    APP_QUERY                       =   '0x00000020'
    SECURITY                        =   '0x80000000'
} -Bitfield

# used to parse the 'userAccountControl' property for users/groups
$UACEnum = psenum $Mod PowerView.UACEnum UInt32 @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH                =   4194304
    PASSWORD_EXPIRED                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -Bitfield

# enum used by $WTS_SESSION_INFO_1 below
$WTSConnectState = psenum $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}

# the WTSEnumerateSessionsEx result structure
$WTS_SESSION_INFO_1 = struct $Mod PowerView.RDPSessionInfo @{
    ExecEnvId = field 0 UInt32
    State = field 1 $WTSConnectState
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @('LPWStr')
    pHostName = field 4 String -MarshalAs @('LPWStr')
    pUserName = field 5 String -MarshalAs @('LPWStr')
    pDomainName = field 6 String -MarshalAs @('LPWStr')
    pFarmName = field 7 String -MarshalAs @('LPWStr')
}

# the particular WTSQuerySessionInformation result structure
$WTS_CLIENT_ADDRESS = struct $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @('ByValArray', 20)
}

# the NetShareEnum result structure
$SHARE_INFO_1 = struct $Mod PowerView.ShareInfo @{
    Name = field 0 String -MarshalAs @('LPWStr')
    Type = field 1 UInt32
    Remark = field 2 String -MarshalAs @('LPWStr')
}

# the NetWkstaUserEnum result structure
$WKSTA_USER_INFO_1 = struct $Mod PowerView.LoggedOnUserInfo @{
    UserName = field 0 String -MarshalAs @('LPWStr')
    LogonDomain = field 1 String -MarshalAs @('LPWStr')
    AuthDomains = field 2 String -MarshalAs @('LPWStr')
    LogonServer = field 3 String -MarshalAs @('LPWStr')
}

# the NetSessionEnum result structure
$SESSION_INFO_10 = struct $Mod PowerView.SessionInfo @{
    CName = field 0 String -MarshalAs @('LPWStr')
    UserName = field 1 String -MarshalAs @('LPWStr')
    Time = field 2 UInt32
    IdleTime = field 3 UInt32
}

# enum used by $LOCALGROUP_MEMBERS_INFO_2 below
$SID_NAME_USE = psenum $Mod SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}

# the NetLocalGroupEnum result structure
$LOCALGROUP_INFO_1 = struct $Mod LOCALGROUP_INFO_1 @{
    lgrpi1_name = field 0 String -MarshalAs @('LPWStr')
    lgrpi1_comment = field 1 String -MarshalAs @('LPWStr')
}

# the NetLocalGroupGetMembers result structure
$LOCALGROUP_MEMBERS_INFO_2 = struct $Mod LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 $SID_NAME_USE
    lgrmi2_domainandname = field 2 String -MarshalAs @('LPWStr')
}

# enums used in DS_DOMAIN_TRUSTS
$DsDomainFlag = psenum $Mod DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
$DsDomainTrustType = psenum $Mod DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$DsDomainTrustAttributes = psenum $Mod DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}

# the DsEnumerateDomainTrusts result structure
$DS_DOMAIN_TRUSTS = struct $Mod DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = field 0 String -MarshalAs @('LPWStr')
    DnsDomainName = field 1 String -MarshalAs @('LPWStr')
    Flags = field 2 $DsDomainFlag
    ParentIndex = field 3 UInt32
    TrustType = field 4 $DsDomainTrustType
    TrustAttributes = field 5 $DsDomainTrustAttributes
    DomainSid = field 6 IntPtr
    DomainGuid = field 7 Guid
}

# used by WNetAddConnection2W
$NETRESOURCEW = struct $Mod NETRESOURCEW @{
    dwScope =         field 0 UInt32
    dwType =          field 1 UInt32
    dwDisplayType =   field 2 UInt32
    dwUsage =         field 3 UInt32
    lpLocalName =     field 4 String -MarshalAs @('LPWStr')
    lpRemoteName =    field 5 String -MarshalAs @('LPWStr')
    lpComment =       field 6 String -MarshalAs @('LPWStr')
    lpProvider =      field 7 String -MarshalAs @('LPWStr')
}

# all of the Win32 API functions we need
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (func advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 RevertToSelf ([Bool]) @() -SetLastError),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func Mpr WNetAddConnection2W ([Int]) @($NETRESOURCEW, [String], [String], [UInt32])),
    (func Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
$Advapi32 = $Types['advapi32']
$Wtsapi32 = $Types['wtsapi32']
$Mpr = $Types['Mpr']
$Kernel32 = $Types['kernel32']

Set-Alias Get-IPAddress Resolve-IPAddress
Set-Alias Convert-NameToSid ConvertTo-SID
Set-Alias Convert-SidToName ConvertFrom-SID
Set-Alias Request-SPNTicket Get-DomainSPNTicket
Set-Alias Get-DNSZone Get-DomainDNSZone
Set-Alias Get-DNSRecord Get-DomainDNSRecord
Set-Alias Get-NetDomain Get-Domain
Set-Alias Get-NetDomainController Get-DomainController
Set-Alias Get-NetForest Get-Forest
Set-Alias Get-NetForestDomain Get-ForestDomain
Set-Alias Get-NetForestCatalog Get-ForestGlobalCatalog
Set-Alias Get-NetUser Get-DomainUser
Set-Alias Get-UserEvent Get-DomainUserEvent
Set-Alias Get-NetComputer Get-DomainComputer
Set-Alias Get-ADObject Get-DomainObject
Set-Alias Set-ADObject Set-DomainObject
Set-Alias Get-ObjectAcl Get-DomainObjectAcl
Set-Alias Add-ObjectAcl Add-DomainObjectAcl
Set-Alias Invoke-ACLScanner Find-InterestingDomainAcl
Set-Alias Get-GUIDMap Get-DomainGUIDMap
Set-Alias Get-NetOU Get-DomainOU
Set-Alias Get-NetSite Get-DomainSite
Set-Alias Get-NetSubnet Get-DomainSubnet
Set-Alias Get-NetGroup Get-DomainGroup
Set-Alias Find-ManagedSecurityGroups Get-DomainManagedSecurityGroup
Set-Alias Get-NetGroupMember Get-DomainGroupMember
Set-Alias Get-NetFileServer Get-DomainFileServer
Set-Alias Get-DFSshare Get-DomainDFSShare
Set-Alias Get-NetGPO Get-DomainGPO
Set-Alias Get-NetGPOGroup Get-DomainGPOLocalGroup
Set-Alias Find-GPOLocation Get-DomainGPOUserLocalGroupMapping
Set-Alias Find-GPOComputerAdmin Get-DomainGPOComputerLocalGroupMapping
Set-Alias Get-LoggedOnLocal Get-RegLoggedOn
Set-Alias Invoke-CheckLocalAdminAccess Test-AdminAccess
Set-Alias Get-SiteName Get-NetComputerSiteName
Set-Alias Get-Proxy Get-WMIRegProxy
Set-Alias Get-LastLoggedOn Get-WMIRegLastLoggedOn
Set-Alias Get-CachedRDPConnection Get-WMIRegCachedRDPConnection
Set-Alias Get-RegistryMountedDrive Get-WMIRegMountedDrive
Set-Alias Get-NetProcess Get-WMIProcess
Set-Alias Invoke-ThreadedFunction New-ThreadedFunction
Set-Alias Invoke-UserHunter Find-DomainUserLocation
Set-Alias Invoke-ProcessHunter Find-DomainProcess
Set-Alias Invoke-EventHunter Find-DomainUserEvent
Set-Alias Invoke-ShareFinder Find-DomainShare
Set-Alias Invoke-FileFinder Find-InterestingDomainShareFile
Set-Alias Invoke-EnumerateLocalAdmin Find-DomainLocalGroupMember
Set-Alias Get-NetDomainTrust Get-DomainTrust
Set-Alias Get-NetForestTrust Get-ForestTrust
Set-Alias Find-ForeignUser Get-DomainForeignUser
Set-Alias Find-ForeignGroup Get-DomainForeignGroupMember
Set-Alias Invoke-MapDomainTrust Get-DomainTrustMapping
Set-Alias Get-DomainPolicy Get-DomainPolicyData

Find-LocalAdminAccess -Threads 100