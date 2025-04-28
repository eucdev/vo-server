package main

import (
	"bufio"
	"database/sql"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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
	username, password, err := getCredsFromCredManager("BrownCloudSQL")
	if err != nil {
		log.Fatalf("Failed to get stored credential: %v", err)
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

	baseDir, _ := os.Getwd()
	dataDir := filepath.Join(baseDir, "data")
	archiveDir := filepath.Join(baseDir, "archive")
	os.MkdirAll(archiveDir, os.ModePerm)

	files, err := os.ReadDir(dataDir)
	if err != nil {
		log.Fatalf("Failed to read data directory: %v", err)
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".csv") {
			continue
		}
		filePath := filepath.Join(dataDir, f.Name())
		success := insertCSV(filePath, db)
		if success {
			archivePath := filepath.Join(archiveDir, time.Now().Format("2006-01-02_15-04-05")+"_"+f.Name())
			if err := os.Rename(filePath, archivePath); err == nil {
				fmt.Printf("📦 Moved to archive: %s\n", archivePath)
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
					// escaped := strings.ReplaceAll(val, "'", `\\'`)
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
