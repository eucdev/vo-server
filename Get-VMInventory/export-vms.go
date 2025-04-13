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

func getPasswordFromCredManager(target string) (string, error) {
	psCmd := fmt.Sprintf(`(Get-StoredCredential -Target "%s").Password`, target)
	out, err := exec.Command("powershell", "-Command", psCmd).Output()
	if err != nil {
		return "", fmt.Errorf("PowerShell error: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func main() {
	username := "root"
	password, err := getPasswordFromCredManager("BrownCloudSQL")
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
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		log.Printf("❌ Invalid or empty CSV: %v", err)
		return
	}

	headers := records[0]
	placeholders := "(" + strings.TrimRight(strings.Repeat("?,", len(headers)), ",") + ")"
	insertQuery := fmt.Sprintf("INSERT INTO vm_inventory (%s) VALUES %s", strings.Join(headers, ", "), placeholders)

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
