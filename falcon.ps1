# Define the VMMs
$vmms = @("phvmmcit", "pvmmanma", "qvmmcit")

# Initialize an empty list
$allHyperVHosts = @()

# Loop through each VMM and get the Hyper-V hosts
foreach ($vmm in $vmms) {
  $hyperVHosts = Get-SCVMHost -VMMServer $vmm | Select-Object Name, OperatingSystem
  foreach ($hyperVHost in $hyperVHosts) {
    # Determine if the host is running Server Core or GUI
    $OSInfo = Invoke-Command -ComputerName $hyperVHost.Name -ScriptBlock {
            (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallationType
    }

    # Check if CrowdStrike Falcon Sensor or Sensor Platform is installed
    $FalconInfo = Invoke-Command -ComputerName $hyperVHost.Name -ScriptBlock {
      $FalconSensor = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
      Where-Object { $_.DisplayName -like "*CrowdStrike Windows Sensor*" } |
      Select-Object DisplayName, InstallDate, DisplayVersion

      $SensorPlatform = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
      Where-Object { $_.DisplayName -like "*CrowdStrike Sensor Platform*" } |
      Select-Object DisplayName, InstallDate, DisplayVersion

      [PSCustomObject]@{
        FalconStatus              = if ($FalconSensor) { "Installed" } else { "Not Installed" }
        FalconVersion             = if ($FalconSensor) { $FalconSensor.DisplayVersion } else { "N/A" }
        FalconInstallDate         = if ($FalconSensor) { $FalconSensor.InstallDate } else { "N/A" }
                
        SensorPlatformStatus      = if ($SensorPlatform) { "Installed" } else { "Not Installed" }
        SensorPlatformVersion     = if ($SensorPlatform) { $SensorPlatform.DisplayVersion } else { "N/A" }
        SensorPlatformInstallDate = if ($SensorPlatform) { $SensorPlatform.InstallDate } else { "N/A" }
      }
    }

    # Store results
    $allHyperVHosts += [PSCustomObject]@{
      FQDN                      = $hyperVHost.Name
      OperatingSystem           = $hyperVHost.OperatingSystem
      OS_Type                   = $OSInfo
      FalconStatus              = $FalconInfo.FalconStatus
      FalconVersion             = $FalconInfo.FalconVersion
      FalconInstallDate         = $FalconInfo.FalconInstallDate
      SensorPlatformStatus      = $FalconInfo.SensorPlatformStatus
      SensorPlatformVersion     = $FalconInfo.SensorPlatformVersion
      SensorPlatformInstallDate = $FalconInfo.SensorPlatformInstallDate
    }
  }
}

# Display the list
$allHyperVHosts | Format-Table -AutoSize
