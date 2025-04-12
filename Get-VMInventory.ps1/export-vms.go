package main

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	// Path to your CSV file
	csvFile := "C:\\temp\\vm_snapshot.csv"

	// Open the file
	file, err := os.Open(csvFile)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	// MySQL connection string
	// Replace with your actual credentials and IP
	dbUser := "youruser"
	dbPass := "yourpassword"
	dbName := "yourdbname"
	dbHost := "34.82.xxx.xxx" // GCP Cloud SQL Public IP or 127.0.0.1 if using auth proxy
	connStr := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", dbUser, dbPass, dbHost, dbName)

	db, err := sql.Open("mysql", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	defer db.Close()

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true
	headers, err := reader.Read()
	if err != nil {
		log.Fatalf("Failed to read headers: %v", err)
	}

	// Prepare an insert query with placeholders
	placeholders := make([]string, len(headers))
	for i := range placeholders {
		placeholders[i] = "?"
	}

	insertStmt := fmt.Sprintf(
		"INSERT INTO vm_inventory (%s) VALUES (%s)",
		strings.Join(headers, ", "),
		strings.Join(placeholders, ", "),
	)

	// Prepare the statement
	stmt, err := db.Prepare(insertStmt)
	if err != nil {
		log.Fatalf("Failed to prepare statement: %v", err)
	}
	defer stmt.Close()

	// Read each row and insert into DB
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Printf("Error reading row: %v", err)
			continue
		}

		vals := make([]interface{}, len(record))
		for i, v := range record {
			vals[i] = v
		}

		_, err = stmt.Exec(vals...)
		if err != nil {
			log.Printf("Failed to insert row: %v", err)
		}
	}

	fmt.Println("CSV data imported successfully into MySQL.")
}
