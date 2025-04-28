package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

func main() {
    ctx := context.Background()

    // ➡️ Load credentials from Windows Credential Manager using PowerShell
    username, parentFolderID, err := getCredsFromCredManager("ReportsVMInventory")
    if err != nil {
        log.Fatalf("Unable to retrieve Windows Credential: %v", err)
    }

    // ➡️ Build service account key path from username
    secretFolder := "S:\\vo-server\\secure"
    serviceAccountKeyFile := filepath.Join(secretFolder, username+".json")

    // ➡️ Local CSV Path (hardcoded)
    localCSVPath := "C:\\Code\\vo-server\\Get-VMInventory\\archive\\2025-04-14_00-50-26_vm_snapshot_20250414_0045.csv"

    googleSheetName := generateSheetName(localCSVPath)

    srv, err := drive.NewService(ctx, option.WithCredentialsFile(serviceAccountKeyFile))
    if err != nil {
        log.Fatalf("Unable to create Drive service: %v", err)
    }

    f, err := os.Open(localCSVPath)
    if err != nil {
        log.Fatalf("Unable to open CSV file: %v", err)
    }
    defer f.Close()

    fileMetadata := &drive.File{
        Name:    googleSheetName,
        Parents: []string{parentFolderID},
        MimeType: "application/vnd.google-apps.spreadsheet",
    }

    file, err := srv.Files.Create(fileMetadata).
        Media(f, googleapi.ContentType("text/csv")).
        Fields("id", "name").
        Do()
    if err != nil {
        log.Fatalf("Unable to upload file: %v", err)
    }

    fmt.Printf("✅ File '%s' uploaded successfully! File ID: %s\n", file.Name, file.Id)
}

// Helper function: load stored credentials via PowerShell
func getCredsFromCredManager(target string) (string, string, error) {
    // Get Username
    userCmd := fmt.Sprintf(`(Get-StoredCredential -Target "%s").UserName`, target)
    userOut, err := exec.Command("powershell", "-Command", userCmd).Output()
    if err != nil {
        return "", "", fmt.Errorf("PowerShell error getting username: %w", err)
    }
    username := strings.TrimSpace(string(userOut))

    // Get Password (decrypted from SecureString)
    passCmd := fmt.Sprintf(`$cred = Get-StoredCredential -Target "%s"; [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password))`, target)
    passOut, err := exec.Command("powershell", "-Command", passCmd).Output()
    if err != nil {
        return "", "", fmt.Errorf("PowerShell error getting password: %w", err)
    }
    password := strings.TrimSpace(string(passOut))

    return username, password, nil
}

// Helper: Generate a clean sheet name from the CSV filename
func generateSheetName(filePath string) string {
    base := filepath.Base(filePath)
    name := strings.TrimSuffix(base, filepath.Ext(base))
    return name
}
