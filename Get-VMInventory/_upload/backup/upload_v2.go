package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

func main() {
    ctx := context.Background()

    serviceAccountKeyFile := "S:\\vo-server\\secure\\svc-pwsh.json"
    localCSVPath := "C:\\Code\\vo-server\\Get-VMInventory\\archive\\2025-04-14_00-50-26_vm_snapshot_20250414_0045.csv"
    parentFolderID := "1-_9I3UjqPWHwhD7ojHKQMHkJWv2PuWNI"

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
        MimeType: "application/vnd.google-apps.spreadsheet", // Tells Drive to convert it
    }

    file, err := srv.Files.Create(fileMetadata).
        Media(f, googleapi.ContentType("text/csv")). // Very important
        Fields("id", "name").
        Do()
    if err != nil {
        log.Fatalf("Unable to upload file: %v", err)
    }

    fmt.Printf("✅ File '%s' uploaded successfully! File ID: %s\n", file.Name, file.Id)
}

func generateSheetName(filePath string) string {
    base := filepath.Base(filePath)
    name := strings.TrimSuffix(base, filepath.Ext(base))
    return name
}
