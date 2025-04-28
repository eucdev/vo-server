/*
Export VMs to MySQL and Google Drive
Author: Sohaib Khan (sohaib_khan@brown.edu)
Created: April 27, 2025
Description:
  - Inserts VM CSVs into MySQL
  - Uploads CSVs as Google Sheets
  - Moves files older than 1 day to archive
  - Deletes archive files older than 30 days
*/
package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	_ "github.com/go-sql-driver/mysql"
)

func getCredsFromCredManager(target string) (string, string, error) {
	userCmd := fmt.Sprintf(`(Get-StoredCredential -Target "%s").UserName`, target)
	userOut, err := exec.Command("powershell", "-Command", userCmd).Output()
	if err != nil {
		return "", "", fmt.Errorf("PowerShell error getting username: %w", err)
	}
	username := strings.TrimSpace(string(userOut))

	passCmd := fmt.Sprintf(`$cred = Get-StoredCredential -Target "%s"; [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password))`, target)
	passOut, err := exec.Command("powershell", "-Command", passCmd).Output()
	if err != nil {
		return "", "", fmt.Errorf("PowerShell error getting password: %w", err)
	}
	password := strings.TrimSpace(string(passOut))

	return username, password, nil
}

func main() {
	// SQL Credentials
	username, password, err := getCredsFromCredManager("BrownCloudSQL")
	if err != nil {
		log.Fatalf("Failed to get stored credential: %v", err)
	}

	// Google Drive Credentials
	serviceAccountUser, parentFolderID, err := getCredsFromCredManager("ReportsVMInventory")
	if err != nil {
		log.Fatalf("Failed to get Google Drive credential: %v", err)
	}
	secretFolder := "S:\\vo-server\\secure"
	serviceAccountKeyFile := filepath.Join(secretFolder, serviceAccountUser+".json")

	_, archiveFolderID, err := getCredsFromCredManager("ReportsVMInventoryArchive")
	if err != nil {
		log.Fatalf("Failed to get Archive Folder credential: %v", err)
	}

	dsn := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/OIT-VO?parseTime=true", username, password)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("DB connection error: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Ping failed: %v", err)
	}
	fmt.Println("Connected to MySQL!")

	ctx := context.Background()
	driveService, err := drive.NewService(ctx, option.WithCredentialsFile(serviceAccountKeyFile))
	if err != nil {
		log.Fatalf("Unable to create Drive service: %v", err)
	}

	moveOldFiles(driveService, parentFolderID, archiveFolderID)
	deleteOldFilesFromArchive(driveService, archiveFolderID)

	baseDir, _ := os.Getwd()
	dataDir := filepath.Join(baseDir, "data")
	archiveDir := filepath.Join(baseDir, "archive")
	os.MkdirAll(archiveDir, os.ModePerm)

	uploadArchivedFiles(archiveDir, driveService, parentFolderID)

	files, err := os.ReadDir(dataDir)
	if err != nil {
		log.Fatalf("Failed to read data directory: %v", err)
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".csv") {
			continue
		}

		filePath := filepath.Join(dataDir, f.Name())
		successDB := insertCSV(filePath, db)
		successDrive := false

		if successDB {
			successDrive = uploadToDrive(filePath, driveService, parentFolderID)
		}

		if successDB && successDrive {
			// Both succeeded, delete file
			if err := os.Remove(filePath); err == nil {
				fmt.Printf("Deleted file after success: %s\n", filePath)
			} else {
				fmt.Printf("Could not delete file: %s\n", err)
			}
		} else {
			// If either failed, archive it
			archivePath := filepath.Join(archiveDir, filepath.Base(filePath))
			if err := os.Rename(filePath, archivePath); err == nil {
				fmt.Printf("Moved to archive: %s\n", archivePath)
			} else {
				fmt.Printf("Could not move to archive: %s\n", err)
			}
		}
	}
}

func insertCSV(csvFile string, db *sql.DB) bool {
	file, err := os.Open(csvFile)
	if err != nil {
		log.Printf("Failed to open CSV: %v", err)
		return false
	}
	defer file.Close()

	reader := csv.NewReader(bufio.NewReader(file))
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		log.Printf("Invalid or empty CSV: %v", err)
		return false
	}

	headersRaw := records[0]
	headers := make([]string, len(headersRaw))
	columns := make([]string, len(headersRaw))
	columnTypes := make(map[string]string)

	for i, h := range headersRaw {
		raw := h
		if i == 0 {
			raw = strings.TrimPrefix(raw, "\ufeff")
		}
		cleaned := strings.Trim(raw, `"`)
		headers[i] = cleaned
		columns[i] = fmt.Sprintf("`%s`", cleaned)

		var dataType string
		query := fmt.Sprintf(`SELECT DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'vm_inventory' AND COLUMN_NAME = '%s' AND TABLE_SCHEMA = 'OIT-VO'`, cleaned)
		if err := db.QueryRow(query).Scan(&dataType); err != nil {
			log.Fatalf("Failed getting type for column '%s': %v", cleaned, err)
		}
		columnTypes[cleaned] = dataType
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("Transaction error: %v", err)
		return false
	}

	success := 0
	for _, row := range records[1:] {
		values := make([]string, len(row))
		for i, val := range row {
			val = strings.Trim(val, `"`)
			switch strings.ToLower(columnTypes[headers[i]]) {
			case "tinyint":
				if strings.EqualFold(val, "true") {
					values[i] = "1"
				} else if strings.EqualFold(val, "false") || val == "" {
					values[i] = "0"
				} else {
					values[i] = val
				}
			case "int", "bigint", "decimal", "float", "double":
				if val == "" {
					values[i] = "NULL"
				} else {
					values[i] = val
				}
			case "datetime", "timestamp":
				if val == "" {
					values[i] = "NULL"
				} else {
					values[i] = fmt.Sprintf("'%s'", val)
				}
			default:
				if val == "" {
					values[i] = "NULL"
				} else {
					escaped := strings.ReplaceAll(val, "\\", "\\\\")
					escaped = strings.ReplaceAll(escaped, "'", "\\'")
					values[i] = fmt.Sprintf("'%s'", escaped)
				}
			}
		}

		query := fmt.Sprintf(
			"INSERT INTO `OIT-VO`.`vm_inventory` (%s) VALUES (%s);",
			strings.Join(columns, ", "),
			strings.Join(values, ", "),
		)

		if _, err := tx.Exec(query); err != nil {
			log.Printf("Insert failed: %v\nQuery: %s\n", err, query)
			tx.Rollback()
			return false
		}
		success++
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Commit error: %v", err)
		return false
	}

	fmt.Printf("Inserted %d rows from %s\n", success, filepath.Base(csvFile))
	return true
}

func uploadToDrive(localCSVPath string, driveService *drive.Service, parentFolderID string) bool {
	file, err := os.Open(localCSVPath)
	if err != nil {
		log.Printf("Failed to open CSV for Drive upload: %v", err)
		return false
	}
	defer file.Close()

	originalFileName := strings.TrimSuffix(filepath.Base(localCSVPath), filepath.Ext(localCSVPath))

	fileMetadata := &drive.File{
		Name:     originalFileName,
		Parents:  []string{parentFolderID},
		MimeType: "application/vnd.google-apps.spreadsheet",
	}

	_, err = driveService.Files.Create(fileMetadata).
		Media(file, googleapi.ContentType("text/csv")).
		Fields("id", "name").
		Do()

	if err != nil {
		log.Printf("Failed uploading to Drive: %v", err)
		return false
	}

	fmt.Printf("Uploaded %s to Google Drive\n", filepath.Base(localCSVPath))
	return true
}

func uploadArchivedFiles(archiveDir string, driveService *drive.Service, parentFolderID string) {
	files, err := os.ReadDir(archiveDir)
	if err != nil {
		log.Printf("Failed to read archive directory: %v", err)
		return
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".csv") {
			continue
		}

		filePath := filepath.Join(archiveDir, f.Name())
		success := uploadToDrive(filePath, driveService, parentFolderID)

		if success {
			if err := os.Remove(filePath); err == nil {
				fmt.Printf("Deleted archived file after successful upload: %s\n", filePath)
			} else {
				fmt.Printf("Could not delete archived file: %s\n", err)
			}
		} else {
			fmt.Printf("Upload failed, keeping archived file for next round: %s\n", filePath)
		}
	}
}


func moveOldFiles(driveService *drive.Service, parentFolderID, archiveFolderID string) {
	fmt.Println("Checking and moving old files to archive...")

	yesterday := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)

	// yesterday := time.Now().Add(-5 * time.Minute).Format(time.RFC3339)

	query := fmt.Sprintf("('%s' in parents) and (mimeType != 'application/vnd.google-apps.folder') and createdTime < '%s' and trashed = false", parentFolderID, yesterday)

	files, err := driveService.Files.List().
			Q(query).
			Fields("files(id, name, parents)").
			PageSize(1000).
			Do()
	if err != nil {
			log.Printf("Failed to list files for moving: %v", err)
			return
	}

	if len(files.Files) == 0 {
			fmt.Println("No old files found to move.")
			return
	}

	for _, file := range files.Files {
			_, err := driveService.Files.Update(file.Id, nil).
					AddParents(archiveFolderID).
					RemoveParents(parentFolderID).
					Fields("id, parents").
					Do()
			if err != nil {
					log.Printf("Failed to move file %s: %v", file.Name, err)
			} else {
					fmt.Printf("Moved old file: %s to archive\n", file.Name)
			}
	}
}


func deleteOldFilesFromArchive(driveService *drive.Service, archiveFolderID string) {
	fmt.Println("Checking and deleting old files from _archive...")

	thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339)

	query := fmt.Sprintf("('%s' in parents) and (mimeType != 'application/vnd.google-apps.folder') and (createdTime < '%s') and (trashed = false)", archiveFolderID, thirtyDaysAgo)

	files, err := driveService.Files.List().
			Q(query).
			Fields("files(id, name)").
			PageSize(1000).
			Do()
	if err != nil {
			log.Printf("Failed to list files for deletion: %v", err)
			return
	}

	if len(files.Files) == 0 {
			fmt.Println("No old files found to delete.")
			return
	}

	for _, file := range files.Files {
			err := driveService.Files.Delete(file.Id).Do()
			if err != nil {
					log.Printf("Failed to delete file %s: %v", file.Name, err)
			} else {
					fmt.Printf("Deleted old archived file: %s\n", file.Name)
			}
	}
}
