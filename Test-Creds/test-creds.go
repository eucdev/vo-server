package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// Retrieve both username and password from Credential Manager
func getCredsFromCredManager(target string) (string, string, error) {
	// Get username
	userCmd := fmt.Sprintf(`(Get-StoredCredential -Target "%s").UserName`, target)
	userOut, err := exec.Command("powershell", "-Command", userCmd).Output()
	if err != nil {
		return "", "", fmt.Errorf("PowerShell error getting username: %w", err)
	}
	username := strings.TrimSpace(string(userOut))

	// Get plaintext password
	passCmd := fmt.Sprintf(`$cred = Get-StoredCredential -Target "%s"; [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password))`, target)
	passOut, err := exec.Command("powershell", "-Command", passCmd).Output()
	if err != nil {
		return "", "", fmt.Errorf("PowerShell error getting password: %w", err)
	}
	password := strings.TrimSpace(string(passOut))

	return username, password, nil
}


func main() {
	target := "BrownCloudSQL"

	username, password, err := getCredsFromCredManager(target)
	if err != nil {
		fmt.Printf("❌ Failed to get credentials for '%s': %v\n", target, err)
	} else {
		fmt.Printf("✅ Retrieved credentials for '%s':\n", target)
		fmt.Printf("   👤 Username: %s\n", username)
		fmt.Printf("   🔑 Password: %s\n", password)
	}
}
