# This code was derived from https://github.com/jaredcatkinson/PSReflect-Functions

function field {
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
function struct{ 

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
function psenum {
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
function ConvertSidToStringSid {
	[OutputType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $SidPointer    
    )
	$DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib')
	$AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
	$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False)
	$TypeBuilder = $ModuleBuilder.DefineType('Advapi32', 'Public, Class')
	$PInvokeMethod = $TypeBuilder.DefineMethod(
		'ConvertSidToStringSid',
		[Reflection.MethodAttributes] 'Public, Static',
		 [bool],
		 [Type[]] @([IntPtr], [IntPtr].MakeByRefType())) 
	$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'),
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
    )
	 $FieldValueArray = [Object[]] @( 
        'ConvertSidToStringSid', 
        $True, 
        $True, 
        [Runtime.InteropServices.CallingConvention]::Winapi, 
        [Runtime.InteropServices.CharSet]::Unicode 
    ) 
	$SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, 
                                                                                     @('Advapi32.dll'), 
                                                                                     $FieldArray, 
                                                                                     $FieldValueArray)
	
	$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute) 
    $Advapi32 = $TypeBuilder.CreateType() 

    
    $StringPtr = [IntPtr]::Zero
    $Success = $Advapi32::ConvertSidToStringSid($SidPointer, [ref]$StringPtr); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Verbose "ConvertSidToStringSid Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($StringPtr))
}
function OpenProcess {
	[CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ProcessId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('PROCESS_TERMINATE','PROCESS_CREATE_THREAD','PROCESS_VM_OPERATION','PROCESS_VM_READ','PROCESS_VM_WRITE','PROCESS_DUP_HANDLE','PROCESS_CREATE_PROCESS','PROCESS_SET_QUOTA','PROCESS_SET_INFORMATION','PROCESS_QUERY_INFORMATION','PROCESS_SUSPEND_RESUME','PROCESS_QUERY_LIMITED_INFORMATION','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','PROCESS_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $InheritHandle = $false
    )
	$DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib')
	$AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
	$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False)
	$TypeBuilder = $ModuleBuilder.DefineType('Kernel32', 'Public, Class')
	$PInvokeMethod = $TypeBuilder.DefineMethod(
		'OpenProcess',
		[Reflection.MethodAttributes] 'Public, Static',
		 [IntPtr],
		 [Type[]] @([UInt32],[bool],[UInt32])) 
	$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'),
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
    )
	 $FieldValueArray = [Object[]] @( 
        'OpenProcess', 
        $True, 
        $True, 
        [Runtime.InteropServices.CallingConvention]::Winapi, 
        [Runtime.InteropServices.CharSet]::Unicode 
    ) 
	$SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, 
                                                                                     @('Kernel32.dll'), 
                                                                                     $FieldArray, 
                                                                                     $FieldValueArray)
	
	$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute) 
    $Kernel32 = $TypeBuilder.CreateType() 
    # Calculate Desired Access Value
    $dwDesiredAccess = 0
	$PROCESS_ACCESS = psenum $ModuleBuilder PROCESS_ACCESS UInt32 @{
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
    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $PROCESS_ACCESS::$val
    }

    $hProcess = $Kernel32::OpenProcess($dwDesiredAccess, $InheritHandle, $ProcessId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hProcess -eq 0) 
    {
        throw "OpenProcess Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hProcess
}
function OpenProcessToken { 
	[OutputType([IntPtr])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_IMPERSONATE','TOKEN_QUERY','TOKEN_QUERY_SOURCE','TOKEN_ADJUST_PRIVILEGES','TOKEN_ADJUST_GROUPS','TOKEN_ADJUST_DEFAULT','TOKEN_ADJUST_SESSIONID','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','STANDARD_RIGHTS_REQUIRED','TOKEN_ALL_ACCESS')]
        [string[]]
        $DesiredAccess  
    )
	$DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib')
	$AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
	$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False)
	$TypeBuilder = $ModuleBuilder.DefineType('Advapi32', 'Public, Class')
	$PInvokeMethod = $TypeBuilder.DefineMethod(
		'OpenProcessToken',
		[Reflection.MethodAttributes] 'Public, Static',
		 [bool],
		 [Type[]] @([IntPtr],[UInt32],[IntPtr].MakeByRefType())) 
	$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'),
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
    )
	 $FieldValueArray = [Object[]] @( 
        'OpenProcessToken', 
        $True, 
        $True, 
        [Runtime.InteropServices.CallingConvention]::Winapi, 
        [Runtime.InteropServices.CharSet]::Unicode 
    ) 
	$SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, 
                                                                                     @('Advapi32.dll'), 
                                                                                     $FieldArray, 
                                                                                     $FieldValueArray)
	
	$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute) 
    $Advapi32 = $TypeBuilder.CreateType()
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0
	$TOKEN_ACCESS = psenum $ModuleBuilder TOKEN_ACCESS UInt32 @{
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
	} -Bitfield
    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val
    }

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenProcessToken($ProcessHandle, $dwDesiredAccess, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        throw "OpenProcessToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hToken
}
function siduser {
	$DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib')
	$AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
	$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False)
	$TypeBuilder = $ModuleBuilder.DefineType('Advapi32', 'Public, Class')
	$PInvokeMethod = $TypeBuilder.DefineMethod(
		'GetTokenInformation',
		[Reflection.MethodAttributes] 'Public, Static',
		 [Int],
		 [Type[]] @([IntPtr],[Int32], [IntPtr],[UInt32],[UInt32].MakeByRefType())) 
	$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'),
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
    )
	 $FieldValueArray = [Object[]] @( 
        'GetTokenInformation', 
        $True, 
        $True, 
        [Runtime.InteropServices.CallingConvention]::Winapi, 
        [Runtime.InteropServices.CharSet]::Unicode 
    ) 
	$SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, 
                                                                                     @('Advapi32.dll'), 
                                                                                     $FieldArray, 
                                                                                     $FieldValueArray)
	
	$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute) 
    $Advapi32 = $TypeBuilder.CreateType()
	$TOKEN_INFORMATION_CLASS = psenum $ModuleBuilder TOKEN_INFORMATION_CLASS UInt16 @{ 
		TokenUser                            = 1
		TokenGroups                          = 2
		TokenPrivileges                      = 3
		TokenOwner                           = 4
		TokenPrimaryGroup                    = 5
		TokenDefaultDacl                     = 6
		TokenSource                          = 7
		TokenType                            = 8
		TokenImpersonationLevel              = 9
		TokenStatistics                      = 10
		TokenRestrictedSids                  = 11
		TokenSessionId                       = 12
		TokenGroupsAndPrivileges             = 13
		TokenSessionReference                = 14
		TokenSandBoxInert                    = 15
		TokenAuditPolicy                     = 16
		TokenOrigin                          = 17
		TokenElevationType                   = 18
		TokenLinkedToken                     = 19
		TokenElevation                       = 20
		TokenHasRestrictions                 = 21
		TokenAccessInformation               = 22
		TokenVirtualizationAllowed           = 23
		TokenVirtualizationEnabled           = 24
		TokenIntegrityLevel                  = 25
		TokenUIAccess                        = 26
		TokenMandatoryPolicy                 = 27
		TokenLogonSid                        = 28
		TokenIsAppContainer                  = 29
		TokenCapabilities                    = 30
		TokenAppContainerSid                 = 31
		TokenAppContainerNumber              = 32
		TokenUserClaimAttributes             = 33
		TokenDeviceClaimAttributes           = 34
		TokenRestrictedUserClaimAttributes   = 35
		TokenRestrictedDeviceClaimAttributes = 36
		TokenDeviceGroups                    = 37
		TokenRestrictedDeviceGroups          = 38
		TokenSecurityAttributes              = 39
		TokenIsRestricted                    = 40
		MaxTokenInfoClass                    = 41
	}
	$TOKEN_OWNER = struct $ModuleBuilder TOKEN_OWNER @{Owner = field 0 IntPtr}
	$TokenPtrSize = 0
	$TokenInformationClass = 'TokenOwner'
	$hProcess = OpenProcess -ProcessId $PID -DesiredAccess PROCESS_QUERY_LIMITED_INFORMATION
	$hToken = OpenProcessToken -ProcessHandle $hProcess -DesiredAccess TOKEN_QUERY
	$Success = $Advapi32::GetTokenInformation($hToken, $TOKEN_INFORMATION_CLASS::$TokenInformationClass, 0, $TokenPtrSize, [ref]$TokenPtrSize)
	[IntPtr]$TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)
	$Success = $Advapi32::GetTokenInformation($hToken, $TOKEN_INFORMATION_CLASS::$TokenInformationClass, $TokenPtr, $TokenPtrSize, [ref]$TokenPtrSize); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
	if($Success) {
		$TokenOwner = $TokenPtr -as $TOKEN_OWNER
		if($TokenOwner.Owner -ne $null) {
			$OwnerSid = ConvertSidToStringSid -SidPointer $TokenOwner.Owner
			$Sid = New-Object System.Security.Principal.SecurityIdentifier($OwnerSid)
			$OwnerName = $Sid.Translate([System.Security.Principal.NTAccount])
			$obj = New-Object -TypeName psobject
			$obj | Add-Member -MemberType NoteProperty -Name Sid -Value $OwnerSid
			$obj | Add-Member -MemberType NoteProperty -Name Name -Value $OwnerName
			Write-Output $obj
		}
		else {
			Write-Output "Fail"
		}
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPtr)
	}
	else {
		Write-Debug "[GetTokenInformation] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
	}
}