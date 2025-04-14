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

// Securely fetch username and password from Windows Credential Manager
func getCredsFromCredManager(target string) (string, string, error) {
	// Get username
	userCmd := fmt.Sprintf(`(Get-StoredCredential -Target "%s").UserName`, target)
	userOut, err := exec.Command("powershell", "-Command", userCmd).Output()
	if err != nil {
		return "", "", fmt.Errorf("PowerShell error getting username: %w", err)
	}
	username := strings.TrimSpace(string(userOut))

	// Get plaintext password from SecureString
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
		log.Fatalf("❌ Failed to get stored credential: %v", err)
	}

	dsn := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/OIT-VO?parseTime=true", username, password)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("❌ DB connection error: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("❌ Ping failed: %v", err)
	}
	fmt.Println("✅ Connected to MySQL!")

	// Paths
	baseDir, _ := os.Getwd()
	dataDir := filepath.Join(baseDir, "data")
	archiveDir := filepath.Join(baseDir, "archive")

	if _, err := os.Stat(archiveDir); os.IsNotExist(err) {
		os.Mkdir(archiveDir, os.ModePerm)
	}

	// Process CSVs in /data
	files, err := os.ReadDir(dataDir)
	if err != nil {
		log.Fatalf("❌ Failed to read data directory: %v", err)
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".csv") {
			continue
		}

		filePath := filepath.Join(dataDir, f.Name())
		processCSV(filePath, db)

		// Archive
		archivePath := filepath.Join(archiveDir, time.Now().Format("2006-01-02_15-04-05")+"_"+f.Name())
		err = os.Rename(filePath, archivePath)
		if err != nil {
			log.Printf("⚠️ Failed to archive %s: %v", f.Name(), err)
		} else {
			fmt.Printf("📦 Archived %s → %s\n", f.Name(), archivePath)
		}
	}
}

func processCSV(csvFile string, db *sql.DB) {
	file, err := os.Open(csvFile)
	if err != nil {
		log.Printf("❌ Failed to open CSV: %v", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(bufio.NewReader(file))
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		log.Printf("❌ Invalid or empty CSV: %v", err)
		return
	}

	headersRaw := records[0]
	headers := make([]string, len(headersRaw))
	columns := make([]string, len(headersRaw))

	for i, h := range headersRaw {
		cleaned := strings.TrimSpace(strings.Trim(h, `"`)) // removes surrounding quotes
		headers[i] = cleaned
		columns[i] = fmt.Sprintf("`%s`", cleaned) // backtick-quote MySQL-safe column names
	}


	placeholders := "(" + strings.TrimRight(strings.Repeat("?,", len(headers)), ",") + ")"
	insertQuery := fmt.Sprintf("INSERT INTO vm_inventory (%s) VALUES %s", strings.Join(columns, ", "), placeholders)


	fmt.Println("Insert Query Preview:")
	fmt.Println(insertQuery)

	fmt.Println("🔍 Cleaned Headers Preview:")
	for _, h := range headers {
		fmt.Println(h)
	}


	tx, err := db.Begin()
	if err != nil {
		log.Printf("❌ Transaction error: %v", err)
		return
	}

	stmt, err := tx.Prepare(insertQuery)
	if err != nil {
		log.Printf("❌ Prepare error: %v", err)
		return
	}
	defer stmt.Close()

	success := 0
	for i, row := range records[1:] {
		values := make([]interface{}, len(row))
		for j := range row {
			values[j] = row[j]
		}
		if _, err := stmt.Exec(values...); err != nil {
			log.Printf("⚠️ Row %d insert failed: %v", i+1, err)
			continue
		}
		success++
	}

	if err := tx.Commit(); err != nil {
		log.Printf("❌ Commit error: %v", err)
	} else {
		fmt.Printf("✅ Inserted %d rows from %s\n", success, filepath.Base(csvFile))
	}
}
