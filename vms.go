package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func main() {
	// Run PowerShell command to get processor information
	cmd := exec.Command("powershell", "-Command", "Get-CimInstance Win32_Processor | Select-Object Name | Format-Table -HideTableHeaders")
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Error retrieving processor info: %v", err)
	}

	// Convert output to string and clean up whitespace
	processorInfo := strings.TrimSpace(string(output))

	// Define output file path
	outputFile := "C:\\temp\\processors.txt"

	// Write to file
	err = os.WriteFile(outputFile, []byte(processorInfo), 0644)
	if err != nil {
		log.Fatalf("Error writing to file: %v", err)
	}

	fmt.Printf("Processor information saved to %s\n", outputFile)
}
