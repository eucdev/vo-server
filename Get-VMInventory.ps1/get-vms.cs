// C# Version of your PowerShell script - Simplified
// Assumes data is already exported from PowerShell or SCVMM API to JSON or is accessible via some API

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using CsvHelper;

public class VmSnapshot
{
    public string Name { get; set; }
    public string VMId { get; set; }
    public string Status { get; set; }
    public string VMHost { get; set; }
    public string ClusterName { get; set; }
    public string Environment { get; set; }
    public string OperatingSystem { get; set; }
    public int MemoryAssignedMB { get; set; }
    public int CPUUtilization { get; set; }
    public string Owner { get; set; }
    public string Timestamp { get; set; }
    // Add other fields you need...
}

class Program
{
    static void Main()
    {
        var envMap = new Dictionary<string, string>
        {
            {"CIT", "phvmmcit"},
            {"ANMA", "pvmmanma"},
            {"QA", "qvmmcit"},
        };

        var allFlattenedVMs = new List<VmSnapshot>();
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
        var fileTimestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmm");

        // Simulated VM data (replace with SCVMM API logic if available)
        foreach (var env in envMap.Keys)
        {
            Console.WriteLine($"Processing environment: {env}");
            for (int i = 1; i <= 5; i++) // Simulate 5 VMs per env
            {
                allFlattenedVMs.Add(new VmSnapshot
                {
                    Name = $"vm-{env.ToLower()}-{i:D2}",
                    VMId = Guid.NewGuid().ToString(),
                    Status = "Running",
                    VMHost = $"host-{i}",
                    ClusterName = $"Cluster-{env}",
                    Environment = env,
                    OperatingSystem = "Windows Server 2022",
                    MemoryAssignedMB = 4096,
                    CPUUtilization = new Random().Next(0, 100),
                    Owner = "svc_user",
                    Timestamp = timestamp
                });
            }
        }

        var csvFolder = "C:/temp/vm-data";
        Directory.CreateDirectory(csvFolder);
        var csvPath = Path.Combine(csvFolder, $"vm_snapshot_{fileTimestamp}.csv");

        using (var writer = new StreamWriter(csvPath))
        using (var csv = new CsvWriter(writer, CultureInfo.InvariantCulture))
        {
            csv.WriteRecords(allFlattenedVMs);
        }

        Console.WriteLine($"Export complete. File saved to: {csvPath}");
    }
}