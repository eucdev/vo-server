<#
.SYNOPSIS
  Collects & consolidates SQL Server inventory across instances with de-dup + env detection.

.NOTES
  - PowerShell 5+ compatible (no PS 7 parallelism required).
  - Requires: SqlServer module (optional; falls back to .NET SqlClient).
#>


param(
  <#
  [string[]]$Instances = @(
    'PSQL-02', 'PSQL-04', 'PSQL-06',  # CIT Prod (even)
    'PSQL-01', 'PSQL-03', 'PSQL-05',  # ANMA Prod (odd)
    'QSQL-02', 'QSQL-04', 'QSQL-06'   # QA
  ),#>


  [string[]]$Instances = @(
    'PSQL-02.hvi.brown.edu', 'PSQL-04.hvi.brown.edu', 'PSQL-06.hvi.brown.edu',  # CIT Prod (even)
    'PSQL-01.hvi.brown.edu', 'PSQL-03.hvi.brown.edu', 'PSQL-05.hvi.brown.edu',  # ANMA Prod (odd)
    'QSQL-02.hvi.brown.edu', 'QSQL-04.hvi.brown.edu', 'QSQL-06.hvi.brown.edu'   # QA
  ),

  # Optional override map; if key is contained in hostname, value is used
  [hashtable]$EnvironmentMap = @{ CIT = 'CIT'; ANMA = 'ANMA'; QA = 'QA' },

  # Base output folder (a timestamped subfolder will be created)
  [string]$OutDir = 'C:\Code\vo-server\SQLServers'
)
Set-Location "C:\Code\vo-server\SQLServers"
# ---- Helpers ---------------------------------------------------------------

# Timestamped, consistent output dir
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutDir = Join-Path -Path $OutDir -ChildPath "Inventory_$stamp"
$null = New-Item -ItemType Directory -Path $OutDir -Force

# Minimal logger
$LogPath = Join-Path $OutDir 'inventory.log'
function Write-Log([string]$msg, [string]$level = 'INFO') {
  $line = ('{0} [{1}] {2}' -f (Get-Date -Format s), $level, $msg)
  $line | Tee-Object -FilePath $LogPath -Append
}

# Normalize host (strip instance name & domain)
function Normalize-Host([string]$name) {
  ($name -split '\\')[0].Split('.')[0].ToUpper()
}


$EnvByPattern = @(
  @{ Pattern = '^(QSQL-\d+)(?:\D|$)'; Env = 'QA' },
  @{ Pattern = '^(PSQL-(02|04|06))(?:\D|$)'; Env = 'CIT' },
  @{ Pattern = '^(PSQL-(01|03|05))(?:\D|$)'; Env = 'ANMA' }
)

# Environment detection (robust + override support)
function Get-EnvLabel {
  param([string]$Instance)

  $node = Normalize-Host $Instance  # strips domain & instance name, uppercases

  foreach ($rule in $EnvByPattern) {
    if ($node -match $rule.Pattern) { return $rule.Env }
  }

  foreach ($k in $EnvironmentMap.Keys) {
    if ($node -like "*$($k.ToUpper())*") { return [string]$EnvironmentMap[$k] }
  }

  return 'UNKNOWN'
}

# T-SQL invoker with graceful fallback + optional "expect object" presence check
function Invoke-TSql {
  param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$Query
  )
  try {
    Import-Module SqlServer -ErrorAction SilentlyContinue | Out-Null
    return Invoke-Sqlcmd -ServerInstance $Server -Query $Query -TrustServerCertificate -QueryTimeout 45 -ErrorAction Stop
  }
  catch {
    Write-Log "Invoke-Sqlcmd failed on $Server (${($_.Exception.Message)}); trying .NET SqlClient" 'WARN'
    try {
      $connStr = "Server=$Server;Integrated Security=SSPI;TrustServerCertificate=True"
      $conn = New-Object System.Data.SqlClient.SqlConnection $connStr
      $cmd = $conn.CreateCommand()
      $cmd.CommandText = $Query
      $cmd.CommandTimeout = 45
      $conn.Open()
      $da = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
      $dt = New-Object System.Data.DataTable
      [void]$da.Fill($dt)
      $conn.Close()
      return $dt
    }
    catch {
      Write-Log "SqlClient also failed on $Server (${($_.Exception.Message)})" 'ERROR'
      return @() # empty result
    }
  }
}

# Run query only if a DMV/table exists (avoids errors on non-AG instances)
function Test-ObjectIdExists {
  param([string]$Server, [string]$DbScopedName)
  $q = @"
SELECT CASE WHEN OBJECT_ID('$DbScopedName') IS NOT NULL THEN 1 ELSE 0 END AS ExistsFlag;
"@
  $r = Invoke-TSql -Server $Server -Query $q
  if ($r -and $r.Rows.Count -gt 0) { return ($r[0].ExistsFlag -eq 1) }
  return $false
}

# Deduplicate any table with a deterministic key (Sort-Object -Unique works with concrete properties)
function Dedup([object[]]$rows, [string[]]$keyProps) {
  if ($null -eq $rows) { return @() }             # <-- ensure array, not $null
  if (-not $keyProps) { return @($rows) }       # keep shape
  try {
    return @($rows) | Sort-Object -Property $keyProps -Unique
  }
  catch {
    return @($rows)
  }
}

# ---- T-SQL blocks (your originals) ----------------------------------------

$Q_ServerInfo = @"
SELECT
  @@SERVERNAME                              AS InstanceName,
  SERVERPROPERTY('MachineName')             AS MachineName,
  SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS NetBIOS,
  SERVERPROPERTY('InstanceName')            AS InstanceNameOnly,
  SERVERPROPERTY('ProductVersion')          AS ProductVersion,
  SERVERPROPERTY('ProductLevel')            AS ProductLevel,
  SERVERPROPERTY('Edition')                 AS Edition,
  SERVERPROPERTY('IsClustered')             AS IsClustered,
  SERVERPROPERTY('HadrManagerStatus')       AS HadrManagerStatus
"@

$Q_Host = @"
IF OBJECT_ID('sys.dm_os_windows_info') IS NOT NULL
AND OBJECT_ID('sys.dm_os_host_info')   IS NOT NULL
BEGIN
    SELECT wi.windows_release,
           wi.windows_sku,
           wi.os_language_version,
           hi.host_platform,
           hi.host_distribution,
           hi.host_release,
           hi.host_service_pack_level
    FROM sys.dm_os_windows_info AS wi
    CROSS JOIN sys.dm_os_host_info   AS hi;
END
ELSE IF OBJECT_ID('sys.dm_os_windows_info') IS NOT NULL
BEGIN
    SELECT wi.windows_release,
           wi.windows_sku,
           wi.os_language_version,
           NULL AS host_platform,
           NULL AS host_distribution,
           NULL AS host_release,
           NULL AS host_service_pack_level
    FROM sys.dm_os_windows_info AS wi;
END
ELSE IF OBJECT_ID('sys.dm_os_host_info') IS NOT NULL
BEGIN
    SELECT NULL AS windows_release,
           NULL AS windows_sku,
           NULL AS os_language_version,
           hi.host_platform,
           hi.host_distribution,
           hi.host_release,
           hi.host_service_pack_level
    FROM sys.dm_os_host_info AS hi;
END
ELSE
BEGIN
    SELECT NULL AS windows_release,
           NULL AS windows_sku,
           NULL AS os_language_version,
           NULL AS host_platform,
           NULL AS host_distribution,
           NULL AS host_release,
           NULL AS host_service_pack_level;
END
"@

$Q_Services = @"
SELECT servicename, startup_type_desc, status_desc, last_startup_time, service_account
FROM sys.dm_server_services
"@

$Q_Cluster = "SELECT cluster_name FROM sys.dm_hadr_cluster"
$Q_ClusterMembers = "SELECT member_name, member_type_desc, member_state_desc FROM sys.dm_hadr_cluster_members"
$Q_AGSummary = @"
SELECT ag.name AS AGName,
       ag.automated_backup_preference_desc AS BackupPreference,
       ag.db_failover AS DBFailoverOn,
       ag.failure_condition_level AS FailureConditionLevel,
       ag.health_check_timeout AS HealthCheckTimeoutSec
FROM sys.availability_groups ag
"@
$Q_AGPrimary = @"
SELECT ag.name AS AGName, ags.primary_replica AS PrimaryReplica
FROM sys.availability_groups ag
JOIN sys.dm_hadr_availability_group_states ags ON ags.group_id = ag.group_id
"@
$Q_Replicas = @"
SELECT ag.name AS AGName,
       ar.replica_server_name AS ReplicaServer,
       ars.role_desc AS Role,
       ar.failover_mode_desc AS FailoverMode,
       ar.availability_mode_desc AS AvailabilityMode,
       ar.secondary_role_allow_connections_desc AS ReadableSecondary,
       ar.seeding_mode_desc AS SeedingMode,
       ars.operational_state_desc AS OperationalState,
       ars.connected_state_desc AS ConnectedState,
       ars.synchronization_health_desc AS SyncHealth,
       ar.endpoint_url AS EndpointUrl
FROM sys.availability_replicas ar
JOIN sys.availability_groups ag ON ag.group_id = ar.group_id
JOIN sys.dm_hadr_availability_replica_states ars ON ars.replica_id = ar.replica_id
"@
$Q_Listeners = @"
DECLARE @maskcol nvarchar(200);

IF COL_LENGTH('sys.availability_group_listener_ip_addresses','subnet_mask') IS NOT NULL
    SET @maskcol = N'ip.subnet_mask AS SubnetMask';
ELSE IF COL_LENGTH('sys.availability_group_listener_ip_addresses','prefix_length') IS NOT NULL
    SET @maskcol = N'ip.prefix_length AS PrefixLength';
else
    SET @maskcol = N'CAST(NULL AS nvarchar(64)) AS SubnetMaskOrPrefix';

DECLARE @sql nvarchar(max) = N'
SELECT ag.name AS AGName,
       l.dns_name AS ListenerDNS,
       l.port     AS ListenerPort,
       ip.ip_address AS ListenerIP,
       ' + @maskcol + N',
       ip.state_desc AS StateDesc
FROM sys.availability_group_listeners AS l
JOIN sys.availability_groups AS ag ON ag.group_id = l.group_id
LEFT JOIN sys.availability_group_listener_ip_addresses AS ip
       ON ip.listener_id = l.listener_id
ORDER BY ag.name, ListenerDNS;';

EXEC sp_executesql @sql;
"@
$Q_AGDatabases = @"
SELECT ag.name AS AGName, adc.database_name AS DatabaseName
FROM sys.availability_databases_cluster adc
JOIN sys.availability_groups ag ON ag.group_id = adc.group_id
"@

# ---- Collect ---------------------------------------------------------------

$now = Get-Date
$allServer = @(); $allHost = @(); $allSvc = @()
$allCluster = @(); $allMembers = @()
$allAG = @(); $allAGPrimary = @(); $allReplicas = @(); $allListeners = @(); $allAGDb = @()

foreach ($inst in $Instances) {
  $env = Get-EnvLabel $inst
  $hostnode = Normalize-Host $inst
  Write-Log "Querying $inst (Host=$hostnode, Env=$env) ..."

  # Always-available DMVs (on supported SQL versions)
  foreach ($row in (Invoke-TSql -Server $inst -Query $Q_ServerInfo)) {
    $row | Add-Member -NotePropertyName env -NotePropertyValue $env -PassThru |
    Add-Member SourceInstance $inst -PassThru |
    Add-Member NormalizedHost $hostnode -PassThru |
    Add-Member Collected $now -PassThru | ForEach-Object { $allServer += $_ }
  }

  foreach ($row in (Invoke-TSql -Server $inst -Query $Q_Host)) {
    $row | Add-Member env $env -PassThru |
    Add-Member SourceInstance $inst -PassThru |
    Add-Member NormalizedHost $hostnode -PassThru |
    Add-Member Collected $now -PassThru | ForEach-Object { $allHost += $_ }
  }

  foreach ($row in (Invoke-TSql -Server $inst -Query $Q_Services)) {
    $row | Add-Member env $env -PassThru |
    Add-Member SourceInstance $inst -PassThru |
    Add-Member NormalizedHost $hostnode -PassThru |
    Add-Member Collected $now -PassThru | ForEach-Object { $allSvc += $_ }
  }

  # AG/Cluster bits — only if the DMVs exist
  # $hasClusterDMV = Test-ObjectIdExists -Server $inst -DbScopedName 'sys.dm_hadr_cluster'
  # $hasAGDMV = Test-ObjectIdExists -Server $inst -DbScopedName 'sys.availability_groups'
  $hasClusterDMV = $hasAGDMV = $true
  if ($hasClusterDMV) {
    foreach ($row in (Invoke-TSql -Server $inst -Query $Q_Cluster)) {
      $row | Add-Member env $env -PassThru |
      Add-Member SourceInstance $inst -PassThru |
      Add-Member NormalizedHost $hostnode -PassThru |
      Add-Member Collected $now -PassThru | ForEach-Object { $allCluster += $_ }
    }
    foreach ($row in (Invoke-TSql -Server $inst -Query $Q_ClusterMembers)) {
      $row | Add-Member env $env -PassThru |
      Add-Member SourceInstance $inst -PassThru |
      Add-Member NormalizedHost $hostnode -PassThru |
      Add-Member Collected $now -PassThru | ForEach-Object { $allMembers += $_ }
    }
  }
  else {
    Write-Log "Skipping cluster DMVs on $inst (not present)" 'WARN'
  }

  if ($hasAGDMV) {
    foreach ($row in (Invoke-TSql -Server $inst -Query $Q_AGSummary)) {
      $row | Add-Member env $env -PassThru |
      Add-Member SourceInstance $inst -PassThru |
      Add-Member NormalizedHost $hostnode -PassThru |
      Add-Member Collected $now -PassThru | ForEach-Object { $allAG += $_ }
    }
    foreach ($row in (Invoke-TSql -Server $inst -Query $Q_AGPrimary)) {
      $row | Add-Member env $env -PassThru |
      Add-Member SourceInstance $inst -PassThru |
      Add-Member NormalizedHost $hostnode -PassThru |
      Add-Member Collected $now -PassThru | ForEach-Object { $allAGPrimary += $_ }
    }
    foreach ($row in (Invoke-TSql -Server $inst -Query $Q_Replicas)) {
      $row | Add-Member env $env -PassThru |
      Add-Member SourceInstance $inst -PassThru |
      Add-Member NormalizedHost $hostnode -PassThru |
      Add-Member Collected $now -PassThru | ForEach-Object { $allReplicas += $_ }
    }
    foreach ($row in (Invoke-TSql -Server $inst -Query $Q_Listeners)) {
      $row | Add-Member env $env -PassThru |
      Add-Member SourceInstance $inst -PassThru |
      Add-Member NormalizedHost $hostnode -PassThru |
      Add-Member Collected $now -PassThru | ForEach-Object { $allListeners += $_ }
    }
    foreach ($row in (Invoke-TSql -Server $inst -Query $Q_AGDatabases)) {
      $row | Add-Member env $env -PassThru |
      Add-Member SourceInstance $inst -PassThru |
      Add-Member NormalizedHost $hostnode -PassThru |
      Add-Member Collected $now -PassThru | ForEach-Object { $allAGDb += $_ }
    }
  }
  else {
    Write-Log "Skipping AG DMVs on $inst (not present)" 'WARN'
  }
}

# ---- Deduplicate (deterministic keys per dataset) --------------------------

$serverDedupKeys = @('NormalizedHost', 'InstanceNameOnly', 'Edition', 'ProductVersion')
$hostnodeDedupKeys = @('NormalizedHost', 'windows_release', 'host_platform', 'host_release')
$svcDedupKeys = @('NormalizedHost', 'servicename', 'service_account')
$clusterDedupKeys = @('NormalizedHost', 'cluster_name')
$membersDedupKeys = @('NormalizedHost', 'member_name', 'member_type_desc')
$agDedupKeys = @('NormalizedHost', 'AGName', 'BackupPreference', 'FailureConditionLevel')
$agPrimDedupKeys = @('NormalizedHost', 'AGName', 'PrimaryReplica')
$repDedupKeys = @('NormalizedHost', 'AGName', 'ReplicaServer', 'Role', 'AvailabilityMode', 'ReadableSecondary')
$listenersKeys = @('NormalizedHost', 'AGName', 'ListenerDNS', 'ListenerIP', 'ListenerPort')
$agDbKeys = @('NormalizedHost', 'AGName', 'DatabaseName')

$allServer = Dedup $allServer $serverDedupKeys
$allHost = Dedup $allHost $hostnodeDedupKeys
$allSvc = Dedup $allSvc $svcDedupKeys
$allCluster = Dedup $allCluster $clusterDedupKeys
$allMembers = Dedup $allMembers $membersDedupKeys
$allAG = Dedup $allAG $agDedupKeys
$allAGPrimary = Dedup $allAGPrimary $agPrimDedupKeys
$allReplicas = Dedup $allReplicas $repDedupKeys
$allListeners = Dedup $allListeners $listenersKeys
$allAGDb = Dedup $allAGDb $agDbKeys

# ---- Quick consolidated summary -------------------------------------------

$summary = @(
  foreach ($s in $allServer) {
    [pscustomobject]@{
      Host         = $s.NormalizedHost
      Env          = $s.env
      InstanceName = if ($s.InstanceNameOnly) { $s.InstanceNameOnly } else { $s.InstanceName }
      Edition      = $s.Edition
      Version      = $s.ProductVersion
      Clustered    = $s.IsClustered
      HADR_Status  = $s.HadrManagerStatus
      Source       = $s.SourceInstance
      CollectedUtc = $s.Collected.ToUniversalTime().ToString('s')
    }
  }
) | Sort-Object Host, InstanceName -Unique

# ---- Export ---------------------------------------------------------------

$csv = {
  param($rows, $name)

  $path = Join-Path $OutDir $name

  # Normalize to array
  if ($null -eq $rows) { $rows = @() }

  if ($rows.Count -eq 0) {
    Write-Log "Skipping $name (no rows)" 'INFO'
    # If you want a placeholder file instead of skipping, uncomment:
    # New-Item -ItemType File -Path $path -Force | Out-Null
    return
  }

  $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Force -Path $path
  Write-Log "Wrote $name ($($rows.Count) rows)" 'INFO'
}

& $csv $summary '00_Summary.csv'
& $csv $allServer '01_ServerInfo.csv'
& $csv $allHost '02_HostOS.csv'
& $csv $allSvc '03_SqlServices.csv'
& $csv $allCluster '04_Cluster.csv'
& $csv $allMembers '05_ClusterMembers.csv'
& $csv $allAG '06_AG_Summary.csv'
& $csv $allAGPrimary '07_AG_Primary.csv'
& $csv $allReplicas '08_AG_Replicas.csv'
& $csv $allListeners '09_AG_Listeners.csv'
& $csv $allAGDb '10_AG_Databases.csv'

Write-Host "Done. CSVs in $OutDir" -ForegroundColor Green
Write-Log "Completed. Output: $OutDir"
