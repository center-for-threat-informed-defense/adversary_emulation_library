package discovery

import (
	"fmt"
	"os/user"

	"golang.org/x/sys/windows/registry"
)

// GetCurrentUserName returns the current username
func GetCurrentUserName() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}
	return currentUser.Username, err
}

// GetOSInfo gets Windows version information by querying the registry
func GetOSInfo() (string, error) {
	registryKeyHandle, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer registryKeyHandle.Close()

	productName, _, err := registryKeyHandle.GetStringValue("ProductName")
	if err != nil {
		return "", err
	}

	majorVersion, _, err := registryKeyHandle.GetIntegerValue("CurrentMajorVersionNumber")
	if err != nil {
		return "", err
	}

	minorVersion, _, err := registryKeyHandle.GetIntegerValue("CurrentMinorVersionNumber")
	if err != nil {
		return "", err
	}

	buildNumber, _, err := registryKeyHandle.GetStringValue("CurrentBuild")
	if err != nil {
		return "", err
	}

	osVer := fmt.Sprintf("OS Info: %v %v %v %v", productName, majorVersion, minorVersion, buildNumber)

	return osVer, err
}
