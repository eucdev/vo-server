$vms = Get-SCVirtualMachine -VMMServer "qvmmcit" -All
$vm = $vms | select * -First 1
$vm | clip


# Define your environments and associated VMM servers
$envMap = @{
  "CIT"  = "phvmmcit"
  "ANMA" = "pvmmanma"
  "QA"   = "qvmmcit"
}

# Create a folder to store the CSVs
$csvFolder = "C:\vm-data"
if (-not (Test-Path $csvFolder)) {
  New-Item -ItemType Directory -Path $csvFolder | Out-Null
}

# Current timestamp for filenames and inserts
$timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
$fileTimestamp = Get-Date -Format "yyyyMMdd_HHmm"

# Master array to hold all flattened VM data
$allFlattenedVMs = @()

foreach ($env in $envMap.Keys) {
  Write-Host "Processing environment: $env"

  $vmmServer = $envMap[$env]
  try {
    $vms = Get-SCVirtualMachine -VMMServer $vmmServer -All
  }
  catch {
    Write-Warning "Failed to connect to VMM server: $vmmServer for environment $env"
    continue
  }
  foreach ($vm in $vms) {
    $allFlattenedVMs += [PSCustomObject]@{
      VMCPath                             = $vm.VMCPath
      MarkedAsTemplate                    = $vm.MarkedAsTemplate
      OwnerIdentifier                     = $vm.OwnerIdentifier
      VMId                                = $vm.VMId
      VMConfigResourceStatus              = $vm.VMConfigResourceStatus
      VMResource                          = $vm.VMResource
      VMResourceStatus                    = $vm.VMResourceStatus
      DiskResources                       = ($vm.DiskResources | ForEach-Object { $_.ToString() }) -join ','
      UnsupportedReason                   = $vm.UnsupportedReason
      VirtualMachineState                 = $vm.VirtualMachineState
      Version                             = $vm.Version
      SecuritySummary                     = $vm.SecuritySummary
      HostGroupPath                       = $vm.HostGroupPath
      TotalSize                           = $vm.TotalSize
      MemoryAssignedMB                    = $vm.MemoryAssignedMB
      MemoryAvailablePercentage           = $vm.MemoryAvailablePercentage
      DynamicMemoryDemandMB               = $vm.DynamicMemoryDemandMB
      DynamicMemoryStatus                 = $vm.DynamicMemoryStatus
      HasSharedStorage                    = $vm.HasSharedStorage
      Status                              = $vm.Status
      IsOrphaned                          = $vm.IsOrphaned
      HasSavedState                       = $vm.HasSavedState
      StatusString                        = $vm.StatusString
      StartAction                         = $vm.StartAction
      StopAction                          = $vm.StopAction
      BiosGuid                            = $vm.BiosGuid
      CPUUtilization                      = $vm.CPUUtilization
      PerfCPUUtilization                  = $vm.PerfCPUUtilization
      PerfMemory                          = $vm.PerfMemory
      PerfDiskBytesRead                   = $vm.PerfDiskBytesRead
      PerfDiskBytesWrite                  = $vm.PerfDiskBytesWrite
      PerfNetworkBytesRead                = $vm.PerfNetworkBytesRead
      PerfNetworkBytesWrite               = $vm.PerfNetworkBytesWrite
      VirtualizationPlatform              = $vm.VirtualizationPlatform
      ComputerNameString                  = $vm.ComputerNameString
      CreationSource                      = $vm.CreationSource
      IsUndergoingLiveMigration           = $vm.IsUndergoingLiveMigration
      SourceObjectType                    = $vm.SourceObjectType
      OperatingSystemShutdownEnabled      = $vm.OperatingSystemShutdownEnabled
      TimeSynchronizationEnabled          = $vm.TimeSynchronizationEnabled
      DataExchangeEnabled                 = $vm.DataExchangeEnabled
      HeartbeatEnabled                    = $vm.HeartbeatEnabled
      BackupEnabled                       = $vm.BackupEnabled
      GuestServiceInterfaceEnabled        = $vm.GuestServiceInterfaceEnabled
      ClusterNonPossibleOwner             = $vm.ClusterNonPossibleOwner
      ClusterPreferredOwner               = $vm.ClusterPreferredOwner
      AvailabilitySetNames                = $vm.AvailabilitySetNames
      LiveCloningEnabled                  = $vm.LiveCloningEnabled
      MostRecentTaskID                    = $vm.MostRecentTaskID
      MostRecentTaskUIState               = $vm.MostRecentTaskUIState
      MostRecentTask                      = $vm.MostRecentTask
      Location                            = $vm.Location
      CreationTime                        = $vm.CreationTime
      OperatingSystem                     = $vm.OperatingSystem
      HasVMAdditions                      = $vm.HasVMAdditions
      VMAddition                          = $vm.VMAddition
      NumLockEnabled                      = $vm.NumLockEnabled
      CPUCount                            = $vm.CPUCount
      IsHighlyAvailable                   = $vm.IsHighlyAvailable
      HAVMPriority                        = $vm.HAVMPriority
      LimitCPUFunctionality               = $vm.LimitCPUFunctionality
      LimitCPUForMigration                = $vm.LimitCPUForMigration
      Memory                              = $vm.Memory
      DynamicMemoryEnabled                = $vm.DynamicMemoryEnabled
      DynamicMemoryMaximumMB              = $vm.DynamicMemoryMaximumMB
      DynamicMemoryBufferPercentage       = $vm.DynamicMemoryBufferPercentage
      MemoryWeight                        = $vm.MemoryWeight
      BootOrder                           = $vm.BootOrder
      FirstBootDevice                     = $vm.FirstBootDevice
      SecureBootEnabled                   = $vm.SecureBootEnabled
      SecureBootTemplate                  = $vm.SecureBootTemplate
      ComputerName                        = $vm.ComputerName
      UseHardwareAssistedVirtualization   = $vm.UseHardwareAssistedVirtualization
      EnabledNestedVirtualization         = $vm.EnabledNestedVirtualization
      IsTagEmpty                          = $vm.IsTagEmpty
      Tag                                 = $vm.Tag
      CustomProperties                    = ($vm.CustomProperties | ForEach-Object { $_ }) -join ','
      CustomProperty                      = ($vm.CustomProperty | ForEach-Object { $_ }) -join ','
      CPUType                             = $vm.CPUType
      ExpectedCPUUtilization              = $vm.ExpectedCPUUtilization
      DiskIO                              = $vm.DiskIO
      NetworkUtilization                  = $vm.NetworkUtilization
      RelativeWeight                      = $vm.RelativeWeight
      CPUReserve                          = $vm.CPUReserve
      CPUMax                              = $vm.CPUMax
      CPUPerVirtualNumaNodeMaximum        = $vm.CPUPerVirtualNumaNodeMaximum
      MemoryPerVirtualNumaNodeMaximumMB   = $vm.MemoryPerVirtualNumaNodeMaximumMB
      VirtualNumaNodesPerSocketMaximum    = $vm.VirtualNumaNodesPerSocketMaximum
      DynamicMemoryMinimumMB              = $vm.DynamicMemoryMinimumMB
      NumaIsolationRequired               = $vm.NumaIsolationRequired
      Generation                          = $vm.Generation
      AutomaticCriticalErrorAction        = $vm.AutomaticCriticalErrorAction
      AutomaticCriticalErrorActionTimeout = $vm.AutomaticCriticalErrorActionTimeout
      CheckpointType                      = $vm.CheckpointType
      VirtualDVDDrives                    = ($vm.VirtualDVDDrives | ForEach-Object { $_ }) -join ','
      VirtualHardDisks                    = ($vm.VirtualHardDisks | ForEach-Object { $_ }) -join ','
      VirtualDiskDrives                   = ($vm.VirtualDiskDrives | ForEach-Object { $_ }) -join ','
      ShareSCSIBus                        = $vm.ShareSCSIBus
      VirtualNetworkAdapters              = ($vm.VirtualNetworkAdapters | ForEach-Object { $_ }) -join ','
      HasVirtualFibreChannelAdapters      = $vm.HasVirtualFibreChannelAdapters
      VirtualSCSIAdapters                 = ($vm.VirtualSCSIAdapters | ForEach-Object { $_ }) -join ','
      CapabilityProfile                   = $vm.CapabilityProfile
      CapabilityProfileCompatibilityState = $vm.CapabilityProfileCompatibilityState
      OSDiskID                            = $vm.OSDiskID
      HostId                              = $vm.HostId
      HostType                            = $vm.HostType
      HostName                            = $vm.HostName
      VMHost                              = $vm.VMHost.Name
      UserRoleID                          = $vm.UserRoleID
      UserRole                            = $vm.UserRole
      Owner                               = $vm.Owner
      ObjectType                          = $vm.ObjectType
      Accessibility                       = $vm.Accessibility
      Name                                = $vm.Name
      IsViewOnly                          = $vm.IsViewOnly
      AddedTime                           = $vm.AddedTime
      ModifiedTime                        = $vm.ModifiedTime
      Enabled                             = $vm.Enabled
      ID                                  = $vm.ID
      MarkedForDeletion                   = $vm.MarkedForDeletion
      IsFullyCached                       = $vm.IsFullyCached
      MostRecentTaskIfLocal               = $vm.MostRecentTaskIfLocal
      Timestamp                           = $timestamp
    }
  }
}

# Export to CSV
$csvPath = Join-Path $csvFolder "vm_snapshot_$fileTimestamp.csv"
$allFlattenedVMs | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "Export complete. File saved to: $csvPath"





