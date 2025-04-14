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

	var dbName string
	if err := db.QueryRow("SELECT DATABASE()").Scan(&dbName); err != nil {
		log.Fatalf("Failed to query current database: %v", err)
	}
	fmt.Printf("🔍 Connected to database: %s\n", dbName)

	baseDir, _ := os.Getwd()
	dataDir := filepath.Join(baseDir, "data")

	files, err := os.ReadDir(dataDir)
	if err != nil {
		log.Fatalf("Failed to read data directory: %v", err)
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".csv") {
			continue
		}
		filePath := filepath.Join(dataDir, f.Name())
		printFirstInsertQuery(filePath, db)
		break
	}
}

func printFirstInsertQuery(csvFile string, db *sql.DB) {
	file, err := os.Open(csvFile)
	if err != nil {
		log.Fatalf("Failed to open CSV: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(bufio.NewReader(file))
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		log.Fatalf("Invalid or empty CSV: %v", err)
	}

	headersRaw := records[0]
	row := records[1]

	if len(headersRaw) != len(row) {
		log.Fatalf("Header count (%d) does not match value count (%d)", len(headersRaw), len(row))
	}

	headers := make([]string, len(headersRaw))
	columns := make([]string, len(headersRaw))
	values := make([]string, len(row))
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

		val := strings.Trim(row[i], `"`)
		switch strings.ToLower(dataType) {
		case "tinyint":
			if strings.EqualFold(val, "true") {
				values[i] = "1"
			} else if strings.EqualFold(val, "false") {
				values[i] = "0"
			} else if val == "" {
				values[i] = "NULL"
			} else {
				values[i] = val
			}
		case "int", "bigint", "decimal", "float", "double":
			if val == "" {
				values[i] = "NULL"
			} else {
				values[i] = val
			}
		default:
			if val == "" {
				values[i] = "NULL"
			} else {
				// escaped := strings.ReplaceAll(val, "'", `\\'`)
				escaped := strings.ReplaceAll(val, "\\", "\\\\")         // escape backslashes
				escaped = strings.ReplaceAll(escaped, "'", "\\'")        // escape single quotes
				
				values[i] = fmt.Sprintf("'%s'", escaped)
			}
		}
	}

	insertQuery := fmt.Sprintf(
		"INSERT INTO `OIT-VO`.`vm_inventory` (%s) VALUES (%s);",
		strings.Join(columns, ", "),
		strings.Join(values, ", "),
	)
	fmt.Println("\n Final INSERT Statement:")
	fmt.Println(insertQuery)

	if _, err := db.Exec(insertQuery); err != nil {
		log.Fatalf("Failed to execute insert: %v", err)
	} else {
		fmt.Println("Insert executed successfully!")
	}
}

