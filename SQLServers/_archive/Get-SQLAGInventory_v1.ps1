<#
param(
  [string[]]$Instances = @(
    'PSQL-02', 'PSQL-04', 'PSQL-06',
    'PSQL-01', 'PSQL-03', 'PSQL-05',
    'QSQL-02', 'QSQL-04', 'QSQL-06'
  ),
  [hashtable]$EnvironmentMap = @{ CIT = 'CIT'; ANMA = 'ANMA'; QA = 'QA' },
  [string]$OutDir = 'C:\Code\vo-server\SQLServers'
)
#>


param(
  [string[]]$Instances = @(
    'PSQL-02', 'PSQL-04', 'PSQL-06',
    'PSQL-01', 'PSQL-03', 'PSQL-05',
    'QSQL-02', 'QSQL-04', 'QSQL-06'
  ),
  [hashtable]$EnvironmentMap = @{},
  [string]$OutDir = 'C:\Code\vo-server\SQLServers'
)
# $Instances = 'QSQL-02', 'QSQL-04', 'QSQL-06'
# $EnvironmentMap = @{ QSQL = 'QA' }   # matches any instance name containing "QSQL"
$outDir = 'C:\Code\vo-server\SQLServers\QA_' + (Get-Date -Format yyyyMMdd_HHmm)


$null = New-Item -ItemType Directory -Path $OutDir -Force

function Get-EnvLabel {
  param([string]$Instance)

  # Normalize: strip named instance and domain, make uppercase
  $hostnode = ($Instance -split '\\')[0]          # remove \InstanceName if present
  $hostnode = $hostnode.Split('.')[0].ToUpper()       # remove domain if FQDN

  # QA: any node starting with Q (e.g., QSQL-02)
  if ($hostnode -match '^Q[A-Z]*-') { return 'QA' }

  # Prod: nodes starting with P, decide by node number (even=CIT, odd=ANMA)
  if ($hostnode -match '^P[A-Z]*-(\d+)$') {
    $n = [int]$Matches[1]
    return (if ($n % 2 -eq 0) { 'CIT' } else { 'ANMA' })
  }

  # Fallback to your hashtable (if you keep EnvironmentMap)
  foreach ($k in $EnvironmentMap.Keys) {
    if ($hostnode -like "*$($k.ToUpper())*") { return $EnvironmentMap[$k] }
  }

  return 'UNKNOWN'
}

function Invoke-TSql {
  param([string]$Server, [string]$Query)
  Import-Module SqlServer -ErrorAction SilentlyContinue | Out-Null
  try {
    Invoke-Sqlcmd -ServerInstance $Server -Query $Query -TrustServerCertificate -QueryTimeout 30
  }
  catch {
    # Fallback to .NET SqlClient if Invoke-Sqlcmd fails
    $connStr = "Server=$Server;Integrated Security=SSPI;TrustServerCertificate=True"
    $conn = New-Object System.Data.SqlClient.SqlConnection $connStr
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = $Query
    $conn.Open()
    $da = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
    $dt = New-Object System.Data.DataTable
    [void]$da.Fill($dt)
    $conn.Close()
    $dt
  }
}

# ---------- T-SQL blocks ----------
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
$Q_ClusterMembers = @"
SELECT member_name, member_type_desc, member_state_desc
FROM sys.dm_hadr_cluster_members
"@

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
ELSE
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

# ---------- Collect ----------
$now = Get-Date
$allServer = @(); $allHost = @(); $allSvc = @()
$allCluster = @(); $allMembers = @()
$allAG = @(); $allAGPrimary = @(); $allReplicas = @(); $allListeners = @(); $allAGDb = @()

foreach ($inst in $Instances) {
  $envLabel = Get-EnvLabel $inst

  Write-Host "Querying $inst ..." -ForegroundColor Cyan

  foreach ($row in Invoke-TSql $inst $Q_ServerInfo) { $row | Add-Member env $envLabel -PassThru | Add-Member SourceInstance $inst -PassThru | Add-Member Collected $now -PassThru | ForEach-Object { $allServer += $_ } }
  foreach ($row in Invoke-TSql $inst $Q_Host) { $row | Add-Member env $envLabel -PassThru | Add-Member SourceInstance $inst -PassThru | Add-Member Collected $now -PassThru | ForEach-Object { $allHost += $_ } }
  foreach ($row in Invoke-TSql $inst $Q_Services) { $row | Add-Member env $envLabel -PassThru | Add-Member SourceInstance $inst -PassThru | Add-Member Collected $now -PassThru | ForEach-Object { $allSvc += $_ } }

  foreach ($row in Invoke-TSql $inst $Q_Cluster) { $row | Add-Member env $envLabel -PassThru | Add-Member SourceInstance $inst -PassThru | Add-Member Collected $now -PassThru | ForEach-Object { $allCluster += $_ } }
  foreach ($row in Invoke-TSql $inst $Q_ClusterMembers) { $row | Add-Member env $envLabel -PassThru | Add-Member SourceInstance $inst -PassThru | Add-Member Collected $now -PassThru | ForEach-Object { $allMembers += $_ } }

  foreach ($row in Invoke-TSql $inst $Q_AGSummary) { $row | Add-Member env $envLabel -PassThru | Add-Member SourceInstance $inst -PassThru | Add-Member Collected $now -PassThru | ForEach-Object { $allAG += $_ } }
  foreach ($row in Invoke-TSql $inst $Q_AGPrimary) { $row | Add-Member env $envLabel -PassThru | Add-Member SourceInstance $inst -PassThru | Add-Member Collected $now -PassThru | ForEach-Object { $allAGPrimary += $_ } }
  foreach ($row in Invoke-TSql $inst $Q_Replicas) { $row | Add-Member env $envLabel -PassThru | Add-Member SourceInstance $inst -PassThru | Add-Member Collected $now -PassThru | ForEach-Object { $allReplicas += $_ } }
  foreach ($row in Invoke-TSql $inst $Q_Listeners) { $row | Add-Member env $envLabel -PassThru | Add-Member SourceInstance $inst -PassThru | Add-Member Collected $now -PassThru | ForEach-Object { $allListeners += $_ } }
  foreach ($row in Invoke-TSql $inst $Q_AGDatabases) { $row | Add-Member env $envLabel -PassThru | Add-Member SourceInstance $inst -PassThru | Add-Member Collected $now -PassThru | ForEach-Object { $allAGDb += $_ } }
}
# ---------- Export ----------
$allServer   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir '01_ServerInfo.csv')
$allHost     | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir '02_HostOS.csv')
$allSvc      | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir '03_SqlServices.csv')
$allCluster  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir '04_Cluster.csv')
$allMembers  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir '05_ClusterMembers.csv')
$allAG       | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir '06_AG_Summary.csv')
$allAGPrimary | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir '07_AG_Primary.csv')
$allReplicas | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir '08_AG_Replicas.csv')
$allListeners | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir '09_AG_Listeners.csv')
$allAGDb     | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir '10_AG_Databases.csv')

Write-Host "Done. CSVs in $OutDir" -ForegroundColor Green