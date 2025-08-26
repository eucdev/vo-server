function Invoke-Sc {
  param(
    [string]$Computer = '.',
    [Parameter(Mandatory)][string]$Args
  )
  $target = if ($Computer -eq '.' -or $Computer -eq $env:COMPUTERNAME) { '' } else { "\\$Computer " }
  $cmd = "sc.exe $target$Args"
  # Capture stdout+stderr reliably (avoids null temp-file paths)
  $out = & cmd.exe /c $cmd 2>&1
  return ($out -join [Environment]::NewLine)
}

function Get-ServiceSddl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][string]$ServiceName   # 'SCMANAGER' or service
  )

  $raw = Invoke-Sc -Computer $ComputerName -Args "sdshow $ServiceName"
  if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

  # sdshow can include headers; extract the SDDL that starts with D: or O:
  $lines = $raw -split "`r?`n"
  $sddlLine = $lines | Where-Object { $_ -match '^[DO]:' } | Select-Object -First 1
  if (-not $sddlLine) {
    # sometimes the whole blob is on one line; try to regex extract
    if ($raw -match '([DO]:\(.+)$') { $sddlLine = $Matches[1] }
  }
  return $sddlLine
}

function Backup-ServiceSddl {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][string]$ServiceName,
    [string]$Path = "C:\Temp\ServiceSDDL-Backups"
  )
  if ([string]::IsNullOrWhiteSpace($Path)) { $Path = "C:\Temp\ServiceSDDL-Backups" }
  if ($PSCmdlet.ShouldProcess("$ComputerName\$ServiceName", "Backup SDDL to $Path")) {
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    $sddl = Get-ServiceSddl -ComputerName $ComputerName -ServiceName $ServiceName
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $file = Join-Path $Path "$($ComputerName)_$($ServiceName)_$stamp.sddl.txt"
    $sddl | Out-File -FilePath $file -Encoding ASCII
    Write-Host "[$ComputerName] Backed up $ServiceName SDDL to $file"
    return $file
  }
}

function Set-OEMSqlServiceAcl {
  <#
    Applies vendor SDDL to SCMANAGER, SQL service, and SQL Agent.
    Defaults to YOUR AD group (safer). Use -UseAuthenticatedUsers to match vendor doc.
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][string[]]$ComputerName,
    [string]$InstanceName,                               # empty = default instance
    [string]$Principal = 'HVI\SQL_OEM_ServiceControl',   # <-- domain-qualified group
    [switch]$UseAuthenticatedUsers,
    [string]$BackupPath = "C:\Temp\ServiceSDDL-Backups",
    [switch]$SkipBackup
  )

  # Resolve target identity for SDDL
  $id = if ($UseAuthenticatedUsers) { 'AU' } else { Get-SddlSid -Principal $Principal }

  # SDDL templates (replace {ID})
  $SDDL_SCM = 'D:(A;;CCLCRPRC;;;{ID})(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)'
  $SDDL_SVC = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;{ID})(A;;CCLCSWRPWPDTLOCRRC;;;PU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'

  $svcName = if ([string]::IsNullOrWhiteSpace($InstanceName)) { 'MSSQLSERVER' } else { "MSSQL`$$InstanceName" }
  $agentName = if ([string]::IsNullOrWhiteSpace($InstanceName)) { 'SQLSERVERAGENT' } else { "SQLAgent`$$InstanceName" }

  $doBackup = -not ($SkipBackup -or $WhatIfPreference)

  foreach ($c in $ComputerName) {
    try {
      if ($doBackup) {
        Backup-ServiceSddl -ComputerName $c -ServiceName 'SCMANAGER' -Path $BackupPath | Out-Null
        Backup-ServiceSddl -ComputerName $c -ServiceName $svcName -Path $BackupPath | Out-Null
        Backup-ServiceSddl -ComputerName $c -ServiceName $agentName -Path $BackupPath | Out-Null
      }
      else {
        Write-Verbose "[$c] Skipping backups (WhatIf/SkipBackup)."
      }

      $scmNew = $SDDL_SCM -replace '\{ID\}', $id
      $svcNew = $SDDL_SVC -replace '\{ID\}', $id
      $agentNew = $svcNew

      if ($PSCmdlet.ShouldProcess("$c", "Set SCMANAGER SDDL")) {
        $out = Invoke-Sc -Computer $c -Args ("sdset SCMANAGER ""{0}""" -f $scmNew)
        Write-Host "[$c] SCMANAGER set.`n$out"
      }
      if ($PSCmdlet.ShouldProcess("$c", "Set $svcName SDDL")) {
        $out = Invoke-Sc -Computer $c -Args ("sdset {0} ""{1}""" -f $svcName, $svcNew)
        Write-Host "[$c] $svcName set.`n$out"
      }
      if ($PSCmdlet.ShouldProcess("$c", "Set $agentName SDDL")) {
        $out = Invoke-Sc -Computer $c -Args ("sdset {0} ""{1}""" -f $agentName, $agentNew)
        Write-Host "[$c] $agentName set.`n$out"
      }
    }
    catch {
      Write-Warning "[$c] $_"
    }
  }
}

function Test-OEMSqlServiceAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string[]]$ComputerName,
    [string]$InstanceName,
    [string]$Principal = 'HVI\SQL_OEM_ServiceControl',
    [switch]$UseAuthenticatedUsers
  )

  # Resolve principal to SID (or AU)
  $id = if ($UseAuthenticatedUsers) { 'AU' } else { Get-SddlSid -Principal $Principal }

  # Service names
  $svcName = if ([string]::IsNullOrWhiteSpace($InstanceName)) { 'MSSQLSERVER' } else { "MSSQL`$$InstanceName" }
  $agentName = if ([string]::IsNullOrWhiteSpace($InstanceName)) { 'SQLSERVERAGENT' } else { "SQLAgent`$$InstanceName" }

  # Required rights (order doesn't matter; superset is OK)
  $needSvc = @('CC', 'LC', 'SW', 'RP', 'WP', 'DT', 'LO', 'CR', 'RC')   # CCLCSWRPWPDTLOCRRC
  $needScm = @('CC', 'LC', 'RP', 'PR', 'RC')                       # CCLCRPRC

  # Parse ACEs: (Type;Flags;Rights;Obj;Inh;Sid)
  [regex]$aceRx = '\(([A-Z]);([^;]*);([^;]*);([^;]*);([^;]*);([^)]+)\)'

  function Test-One {
    param($computer, $target, $sddl, [string[]]$need)

    $hasId = $false; $hasRights = $false

    if ($sddl) {
      foreach ($m in $aceRx.Matches($sddl)) {
        $rights = $m.Groups[3].Value
        $sid = $m.Groups[6].Value

        if ($sid -eq $id) {
          $hasId = $true

          # Check each required token is present as a substring in the rights field
          # (rights may be in any order; we don't care about extras)
          $missing = $need | Where-Object { $rights -notlike "*$_*" }
          if ($missing.Count -eq 0) { $hasRights = $true; break }
        }
      }
    }

    [pscustomobject]@{
      Computer  = $computer
      Target    = $target
      PASS      = $hasRights
      HasIdAce  = $hasId
      HasRights = $hasRights
    }
  }

  foreach ($c in $ComputerName) {
    $scm = Get-ServiceSddl -ComputerName $c -ServiceName 'SCMANAGER'
    $svc = Get-ServiceSddl -ComputerName $c -ServiceName $svcName
    $agent = Get-ServiceSddl -ComputerName $c -ServiceName $agentName

    Test-One $c 'SCMANAGER' $scm $needScm
    Test-One $c $svcName $svc $needSvc
    Test-One $c $agentName $agent $needSvc
  }
}

# Safer: grant to your AD group (recommended from security prespective)
$servers = 'qsql-02', 'qsql-04', 'qsql-06'
Set-OEMSqlServiceAcl -ComputerName $servers -Principal 'HVI\SQL_OEM_ServiceControl' -WhatIf   # preview
Set-OEMSqlServiceAcl -ComputerName $servers -Principal 'HVI\SQL_OEM_ServiceControl' -Confirm:$false

# Verify
Test-OEMSqlServiceAcl -ComputerName qsql-02 -Principal 'HVI\SQL_OEM_ServiceControl' | ft Computer, Target, PASS, HasIdAce, HasRights -Auto

# If we just want to see the SID in the raw SDDL
Get-SddlSid 'HVI\SQL_OEM_ServiceControl'
Get-ServiceSddl -ComputerName 'qsql-02' -ServiceName 'SCMANAGER'
Get-ServiceSddl -ComputerName 'qsql-02' -ServiceName 'MSSQLSERVER'
Get-ServiceSddl -ComputerName 'qsql-02' -ServiceName 'SQLSERVERAGENT'

# SQL Team / Oracle wants to allow all Authenticated Users. Instead VO is going to do just the principal
# Set-OEMSqlServiceAcl -ComputerName $servers -UseAuthenticatedUsers -Confirm:$false
# Test-OEMSqlServiceAcl -ComputerName $servers -UseAuthenticatedUsers | ft -Auto
