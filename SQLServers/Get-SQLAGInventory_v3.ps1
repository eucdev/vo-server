<#
.SYNOPSIS
  Collects SQL Server inventory, consolidates to 4 CSVs, and writes per-env folders (CIT/ANMA/QA).

.OUTPUT
  <OutDir>\Inventory_yyyyMMdd_HHmmss\
    \CIT\01_Servers.csv
         \02_Services.csv
         \03_Cluster.csv
         \04_AvailabilityGroups.csv
    \ANMA\...
    \QA\...
#>

param(
  [string[]]$Instances = @(
    # 'PSQL-02', 'PSQL-04', 'PSQL-06',  # CIT Prod
    # 'PSQL-01', 'PSQL-03', 'PSQL-05',  # ANMA Prod
    'QSQL-02', 'QSQL-04', 'QSQL-06'   # QA
  ),
  # Optional pattern fallback (kept for completeness; exact host map wins first)
  [hashtable]$EnvironmentMap = @{},
  [string]$OutDir = 'C:\Code\vo-server\SQLServers'
)

# -----------------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------------
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutDir = Join-Path -Path $OutDir -ChildPath "Inventory_$stamp"
$null = New-Item -ItemType Directory -Path $OutDir -Force

# Create per-env folders up front
# $EnvFolders = @('CIT', 'ANMA', 'QA')
$EnvFolders = @('QA')
foreach ($e in $EnvFolders) { $null = New-Item -ItemType Directory -Path (Join-Path $OutDir $e) -Force }

function Normalize-Host([string]$name) {
  $n = ($name -split '\\')[0].Split('.')[0]
  if ([string]::IsNullOrWhiteSpace($n)) { $n = $name }
  $n.ToUpper()
}
# Hard-coded environment labeling (exact hostnames)
$EnvByHost = @{
  # 'PSQL-02' = 'CIT'; 'PSQL-04' = 'CIT'; 'PSQL-06' = 'CIT'
  # 'PSQL-01' = 'ANMA'; 'PSQL-03' = 'ANMA'; 'PSQL-05' = 'ANMA'
  'QSQL-02' = 'QA'; 'QSQL-04' = 'QA'; 'QSQL-06' = 'QA'
}

function Get-EnvLabel {
  param([string]$Instance)
  $node = Normalize-Host $Instance
  if ($EnvByHost.ContainsKey($node)) { return $EnvByHost[$node] }
  foreach ($k in $EnvironmentMap.Keys) { if ($node -like "*$($k.ToUpper())*") { return $EnvironmentMap[$k] } }
  return 'UNKNOWN'
}

function Invoke-TSql {
  # Invoke-Sqlcmd with safe fallback
  param([string]$Server, [string]$Query)
  Import-Module SqlServer -ErrorAction SilentlyContinue | Out-Null
  try {
    return Invoke-Sqlcmd -ServerInstance $Server -Query $Query -TrustServerCertificate -QueryTimeout 45
  }
  catch {
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
    catch { return @() }
  }
}

function Dedup([object[]]$rows, [string[]]$keys) {
  if ($null -eq $rows) { return @() }
  try { return @($rows) | Sort-Object -Property $keys -Unique } catch { return @($rows) }
}

# -----------------------------------------------------------------------------
# Queries
# -----------------------------------------------------------------------------
$Q_ServerInfo = @"
SELECT
  @@SERVERNAME AS InstanceName,
  SERVERPROPERTY('MachineName') AS MachineName,
  SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS NetBIOS,
  SERVERPROPERTY('InstanceName') AS InstanceNameOnly,
  SERVERPROPERTY('ProductVersion') AS ProductVersion,
  SERVERPROPERTY('ProductLevel') AS ProductLevel,
  SERVERPROPERTY('Edition') AS Edition,
  SERVERPROPERTY('IsClustered') AS IsClustered,
  SERVERPROPERTY('HadrManagerStatus') AS HadrManagerStatus
"@

$Q_Host = @"
IF OBJECT_ID('sys.dm_os_windows_info') IS NOT NULL
AND OBJECT_ID('sys.dm_os_host_info')   IS NOT NULL
BEGIN
    SELECT wi.windows_release, wi.windows_sku, wi.os_language_version,
           hi.host_platform, hi.host_distribution, hi.host_release, hi.host_service_pack_level
    FROM sys.dm_os_windows_info AS wi
    CROSS JOIN sys.dm_os_host_info   AS hi;
END
ELSE IF OBJECT_ID('sys.dm_os_windows_info') IS NOT NULL
BEGIN
    SELECT wi.windows_release, wi.windows_sku, wi.os_language_version,
           NULL AS host_platform, NULL AS host_distribution, NULL AS host_release, NULL AS host_service_pack_level
    FROM sys.dm_os_windows_info AS wi;
END
ELSE IF OBJECT_ID('sys.dm_os_host_info') IS NOT NULL
BEGIN
    SELECT NULL AS windows_release, NULL AS windows_sku, NULL AS os_language_version,
           hi.host_platform, hi.host_distribution, hi.host_release, hi.host_service_pack_level
    FROM sys.dm_os_host_info AS hi;
END
ELSE
BEGIN
    SELECT NULL AS windows_release, NULL AS windows_sku, NULL AS os_language_version,
           NULL AS host_platform, NULL AS host_distribution, NULL AS host_release, NULL AS host_service_pack_level;
END
"@

$Q_Services = "SELECT servicename,startup_type_desc,status_desc,last_startup_time,service_account FROM sys.dm_server_services"
$Q_Cluster = "SELECT cluster_name FROM sys.dm_hadr_cluster"
$Q_ClusterMembers = "SELECT member_name,member_type_desc,member_state_desc FROM sys.dm_hadr_cluster_members"
$Q_AGSummary = "SELECT ag.name AS AGName, ag.automated_backup_preference_desc AS BackupPreference, ag.db_failover AS DBFailoverOn, ag.failure_condition_level AS FailureConditionLevel, ag.health_check_timeout AS HealthCheckTimeoutSec FROM sys.availability_groups ag"
$Q_AGPrimary = "SELECT ag.name AS AGName, ags.primary_replica AS PrimaryReplica FROM sys.availability_groups ag JOIN sys.dm_hadr_availability_group_states ags ON ags.group_id = ag.group_id"
$Q_Replicas = "SELECT ag.name AS AGName, ar.replica_server_name AS ReplicaServer, ars.role_desc AS Role, ar.failover_mode_desc AS FailoverMode, ar.availability_mode_desc AS AvailabilityMode, ar.secondary_role_allow_connections_desc AS ReadableSecondary, ar.seeding_mode_desc AS SeedingMode, ars.operational_state_desc AS OperationalState, ars.connected_state_desc AS ConnectedState, ars.synchronization_health_desc AS SyncHealth, ar.endpoint_url AS EndpointUrl FROM sys.availability_replicas ar JOIN sys.availability_groups ag ON ag.group_id = ar.group_id JOIN sys.dm_hadr_availability_replica_states ars ON ars.replica_id = ar.replica_id"
$Q_Listeners = @"
DECLARE @maskcol nvarchar(200);
IF COL_LENGTH('sys.availability_group_listener_ip_addresses','subnet_mask') IS NOT NULL
    SET @maskcol = N'ip.subnet_mask AS SubnetMask';
ELSE IF COL_LENGTH('sys.availability_group_listener_ip_addresses','prefix_length') IS NOT NULL
    SET @maskcol = N'ip.prefix_length AS PrefixLength';
ELSE
    SET @maskcol = N'CAST(NULL AS nvarchar(64)) AS SubnetMaskOrPrefix';
DECLARE @sql nvarchar(max) = N'
SELECT ag.name AS AGName, l.dns_name AS ListenerDNS, l.port AS ListenerPort, ip.ip_address AS ListenerIP,
       ' + @maskcol + N', ip.state_desc AS StateDesc
FROM sys.availability_group_listeners AS l
JOIN sys.availability_groups AS ag ON ag.group_id = l.group_id
LEFT JOIN sys.availability_group_listener_ip_addresses AS ip ON ip.listener_id = l.listener_id
ORDER BY ag.name, ListenerDNS;';
EXEC sp_executesql @sql;
"@
$Q_AGDatabases = "SELECT ag.name AS AGName, adc.database_name AS DatabaseName FROM sys.availability_databases_cluster adc JOIN sys.availability_groups ag ON ag.group_id = adc.group_id"

# -----------------------------------------------------------------------------
# Collect raw
# -----------------------------------------------------------------------------
$now = Get-Date
$server = @(); $hostnode = @(); $svc = @(); $cluster = @(); $members = @(); $ag = @(); $agPrimary = @(); $replicas = @(); $listeners = @(); $agDb = @()

foreach ($inst in $Instances) {
  $env = Get-EnvLabel $inst
  $node = Normalize-Host $inst
  Write-Host "Querying $inst (Env=$env, Host=$node)..."

  foreach ($r in Invoke-TSql $inst $Q_ServerInfo) { $r | Add-Member env $env -PassThru | Add-Member NormalizedHost $node -PassThru | Add-Member SourceInstance $inst -PassThru | Add-Member Collected $now -PassThru | % { $server += $_ } }
  foreach ($r in Invoke-TSql $inst $Q_Host) { $r | Add-Member env $env -PassThru | Add-Member NormalizedHost $node -PassThru | Add-Member Collected $now -PassThru | % { $hostnode += $_ } }
  foreach ($r in Invoke-TSql $inst $Q_Services) { $r | Add-Member env $env -PassThru | Add-Member NormalizedHost $node -PassThru | Add-Member Collected $now -PassThru | % { $svc += $_ } }
  foreach ($r in Invoke-TSql $inst $Q_Cluster) { $r | Add-Member env $env -PassThru | Add-Member NormalizedHost $node -PassThru | Add-Member Collected $now -PassThru | % { $cluster += $_ } }
  foreach ($r in Invoke-TSql $inst $Q_ClusterMembers) { $r | Add-Member env $env -PassThru | Add-Member NormalizedHost $node -PassThru | Add-Member Collected $now -PassThru | % { $members += $_ } }
  foreach ($r in Invoke-TSql $inst $Q_AGSummary) { $r | Add-Member env $env -PassThru | Add-Member NormalizedHost $node -PassThru | Add-Member Collected $now -PassThru | % { $ag += $_ } }
  foreach ($r in Invoke-TSql $inst $Q_AGPrimary) { $r | Add-Member env $env -PassThru | Add-Member NormalizedHost $node -PassThru | Add-Member Collected $now -PassThru | % { $agPrimary += $_ } }
  foreach ($r in Invoke-TSql $inst $Q_Replicas) { $r | Add-Member env $env -PassThru | Add-Member NormalizedHost $node -PassThru | Add-Member Collected $now -PassThru | % { $replicas += $_ } }
  foreach ($r in Invoke-TSql $inst $Q_Listeners) { $r | Add-Member env $env -PassThru | Add-Member NormalizedHost $node -PassThru | Add-Member Collected $now -PassThru | % { $listeners += $_ } }
  foreach ($r in Invoke-TSql $inst $Q_AGDatabases) { $r | Add-Member env $env -PassThru | Add-Member NormalizedHost $node -PassThru | Add-Member Collected $now -PassThru | % { $agDb += $_ } }
}

# Dedup raw for stable joins
$server = Dedup $server @('NormalizedHost', 'InstanceNameOnly', 'Edition', 'ProductVersion')
$hostnode = Dedup $hostnode @('NormalizedHost', 'windows_release', 'host_platform', 'host_release')
$svc = Dedup $svc @('NormalizedHost', 'servicename', 'service_account')
$cluster = Dedup $cluster @('NormalizedHost', 'cluster_name')
$members = Dedup $members @('NormalizedHost', 'member_name', 'member_type_desc')
$ag = Dedup $ag @('NormalizedHost', 'AGName', 'BackupPreference', 'FailureConditionLevel')
$agPrimary = Dedup $agPrimary@('NormalizedHost', 'AGName', 'PrimaryReplica')
$replicas = Dedup $replicas @('NormalizedHost', 'AGName', 'ReplicaServer', 'Role', 'AvailabilityMode', 'ReadableSecondary')
$listeners = Dedup $listeners@('NormalizedHost', 'AGName', 'ListenerDNS', 'ListenerIP', 'ListenerPort')
$agDb = Dedup $agDb @('NormalizedHost', 'AGName', 'DatabaseName')

# -----------------------------------------------------------------------------
# Consolidation (4 datasets)
# -----------------------------------------------------------------------------

# 1) SERVERS: merge ServerInfo + first Host row for that node
$servers = @(
  foreach ($s in $server) {
    $h = $hostnode | Where-Object { $_.NormalizedHost -eq $s.NormalizedHost } | Select-Object -First 1
    [pscustomobject]@{
      Env               = $s.env
      Host              = $s.NormalizedHost
      InstanceName      = if ($s.InstanceNameOnly) { $s.InstanceNameOnly } else { $s.InstanceName }
      Edition           = $s.Edition
      ProductVersion    = $s.ProductVersion
      ProductLevel      = $s.ProductLevel
      MachineName       = $s.MachineName
      NetBIOS           = $s.NetBIOS
      IsClustered       = $s.IsClustered
      HadrManagerStatus = $s.HadrManagerStatus
      WindowsRelease    = $h.windows_release
      WindowsSKU        = $h.windows_sku
      OS_Language       = $h.os_language_version
      HostPlatform      = $h.host_platform
      HostDistribution  = $h.host_distribution
      HostRelease       = $h.host_release
      HostSPLevel       = $h.host_service_pack_level
      SourceInstance    = $s.SourceInstance
      Collected         = $s.Collected
    }
  }
) | Sort-Object Env, Host, InstanceName -Unique


# 2) SERVICES (as-is, but only properties we care about)
$services = $svc | ForEach-Object {
  [pscustomobject]@{
    Env             = $_.env
    Host            = $_.NormalizedHost
    ServiceName     = $_.servicename
    StartupType     = $_.startup_type_desc
    Status          = $_.status_desc
    LastStartupTime = $_.last_startup_time
    ServiceAccount  = $_.service_account
    SourceInstance  = $_.SourceInstance
    Collected       = $_.Collected
  }
} | Sort-Object Env, Host, ServiceName -Unique

# 3) CLUSTER: one row per member including cluster name (lookup by host)
#    Compute cluster name by host (there may be one per host)
$clusterByHost = @{}
foreach ($c in $cluster) {
  if ($c.NormalizedHost) { $clusterByHost[$c.NormalizedHost] = $c.cluster_name }
}

$clusters = @(
  foreach ($m in $members) {
    $clusterName = $null
    if ($m.NormalizedHost -and $clusterByHost.ContainsKey($m.NormalizedHost)) {
      $clusterName = $clusterByHost[$m.NormalizedHost]
    }
    [pscustomobject]@{
      Env         = $m.env
      Host        = $m.NormalizedHost
      Cluster     = $clusterName
      MemberName  = $m.member_name
      MemberType  = $m.member_type_desc
      MemberState = $m.member_state_desc
      Collected   = $m.Collected
    }
  }
) | Sort-Object Env, Cluster, MemberName -Unique


# 4) AVAILABILITY GROUPS: Long format
#    Build an index per (Env, Host, AGName) to collect primary, summary, replicas, listeners, dbs
$agIndex = @{}

function Ensure-AgKey([string]$env, [string]$hostnode, [string]$agName) {
  $key = "$env|$hostnode|$agName"
  if (-not $agIndex.ContainsKey($key)) {
    $agIndex[$key] = [pscustomobject]@{
      Env = $env; Host = $hostnode; AGName = $agName
      BackupPreference = $null; DBFailoverOn = $null; FailureConditionLevel = $null; HealthCheckTimeoutSec = $null
      PrimaryReplica = $null
      Replicas = New-Object System.Collections.ArrayList
      Listeners = New-Object System.Collections.ArrayList
      Databases = New-Object System.Collections.ArrayList
      Collected = $null
      SourceInstance = $null
    }
  }
  return $agIndex[$key]
}

foreach ($x in $ag) {
  $e = Ensure-AgKey $x.env $x.NormalizedHost $x.AGName
  $e.BackupPreference = $x.BackupPreference
  $e.DBFailoverOn = $x.DBFailoverOn
  $e.FailureConditionLevel = $x.FailureConditionLevel
  $e.HealthCheckTimeoutSec = $x.HealthCheckTimeoutSec
  $e.Collected = $x.Collected
  $e.SourceInstance = $x.SourceInstance
}
foreach ($x in $agPrimary) {
  $e = Ensure-AgKey $x.env $x.NormalizedHost $x.AGName
  $e.PrimaryReplica = $x.PrimaryReplica
  $e.Collected = $x.Collected
  $e.SourceInstance = $x.SourceInstance
}
foreach ($x in $replicas) {
  $e = Ensure-AgKey $x.env $x.NormalizedHost $x.AGName
  [void]$e.Replicas.Add([pscustomobject]@{
      ReplicaServer = $x.ReplicaServer; Role = $x.Role; FailoverMode = $x.FailoverMode
      AvailabilityMode = $x.AvailabilityMode; ReadableSecondary = $x.ReadableSecondary
      SeedingMode = $x.SeedingMode; OperationalState = $x.OperationalState
      ConnectedState = $x.ConnectedState; SyncHealth = $x.SyncHealth; EndpointUrl = $x.EndpointUrl
    })
  $e.Collected = $x.Collected
}
foreach ($x in $listeners) {
  $e = Ensure-AgKey $x.env $x.NormalizedHost $x.AGName
  [void]$e.Listeners.Add([pscustomobject]@{
      ListenerDNS = $x.ListenerDNS; ListenerPort = $x.ListenerPort; ListenerIP = $x.ListenerIP
      SubnetMask = $x.SubnetMask; PrefixLength = $x.PrefixLength; StateDesc = $x.StateDesc
    })
  $e.Collected = $x.Collected
}
foreach ($x in $agDb) {
  $e = Ensure-AgKey $x.env $x.NormalizedHost $x.AGName
  [void]$e.Databases.Add($x.DatabaseName)
  $e.Collected = $x.Collected
}

# Expand to long rows
$ags = @()
foreach ($entry in $agIndex.Values) {
  $repList = if ($entry.Replicas.Count -gt 0) { @($entry.Replicas) } else { @([pscustomobject]@{ ReplicaServer = $null; Role = $null; FailoverMode = $null; AvailabilityMode = $null; ReadableSecondary = $null; SeedingMode = $null; OperationalState = $null; ConnectedState = $null; SyncHealth = $null; EndpointUrl = $null }) }
  $lisList = if ($entry.Listeners.Count -gt 0) { @($entry.Listeners) } else { @([pscustomobject]@{ ListenerDNS = $null; ListenerPort = $null; ListenerIP = $null; SubnetMask = $null; PrefixLength = $null; StateDesc = $null }) }
  $dbList = if ($entry.Databases.Count -gt 0) { @($entry.Databases) } else { @($null) }

  foreach ($r in $repList) {
    foreach ($l in $lisList) {
      foreach ($d in $dbList) {
        $ags += [pscustomobject]@{
          Env               = $entry.Env
          Host              = $entry.Host
          AGName            = $entry.AGName
          PrimaryReplica    = $entry.PrimaryReplica
          ReplicaServer     = $r.ReplicaServer
          Role              = $r.Role
          FailoverMode      = $r.FailoverMode
          AvailabilityMode  = $r.AvailabilityMode
          ReadableSecondary = $r.ReadableSecondary
          SeedingMode       = $r.SeedingMode
          OperationalState  = $r.OperationalState
          ConnectedState    = $r.ConnectedState
          SyncHealth        = $r.SyncHealth
          EndpointUrl       = $r.EndpointUrl
          ListenerDNS       = $l.ListenerDNS
          ListenerPort      = $l.ListenerPort
          ListenerIP        = $l.ListenerIP
          SubnetMask        = $l.SubnetMask
          PrefixLength      = $l.PrefixLength
          ListenerState     = $l.StateDesc
          DatabaseName      = $d
          BackupPreference  = $entry.BackupPreference
          DBFailoverOn      = $entry.DBFailoverOn
          FailureCondition  = $entry.FailureConditionLevel
          HealthTimeoutSec  = $entry.HealthCheckTimeoutSec
          SourceInstance    = $entry.SourceInstance
          Collected         = $entry.Collected
        }
      }
    }
  }
}
$ags = $ags | Sort-Object Env, AGName, ReplicaServer, DatabaseName, ListenerDNS -Unique

# -----------------------------------------------------------------------------
# Write per-environment CSVs
# -----------------------------------------------------------------------------
function Write-Csv {
  param([object[]]$rows, [string]$folder, [string]$file)
  $path = Join-Path (Join-Path $OutDir $folder) $file
  if ($rows -and $rows.Count -gt 0) {
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Force -Path $path
  }
  else {
    New-Item -ItemType File -Path $path -Force | Out-Null
  }
  Write-Host "Wrote $folder\$file"
}

foreach ($env in $EnvFolders) {
  $serversEnv = $servers  | Where-Object { $_.Env -eq $env }
  $servicesEnv = $services | Where-Object { $_.Env -eq $env }
  $clustersEnv = $clusters | Where-Object { $_.Env -eq $env }
  $agsEnv = $ags      | Where-Object { $_.Env -eq $env }

  Write-Csv -rows $serversEnv -folder $env -file '01_Servers.csv'
  Write-Csv -rows $servicesEnv -folder $env -file '02_Services.csv'
  Write-Csv -rows $clustersEnv -folder $env -file '03_Cluster.csv'
  Write-Csv -rows $agsEnv -folder $env -file '04_AvailabilityGroups.csv'
}

Write-Host "Done. Output in $OutDir\{CIT, ANMA, QA}" -ForegroundColor Green
