function Get-WmiNamespaces {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [string]$Start = 'root'
  )
  $queue = New-Object System.Collections.Generic.Queue[string]
  $seen  = New-Object System.Collections.Generic.HashSet[string]
  $queue.Enqueue($Start); [void]$seen.Add($Start)
  while ($queue.Count) {
    $ns = $queue.Dequeue()
    $ns
    try {
      (Get-CimInstance -ComputerName $ComputerName -Namespace $ns -Class __NAMESPACE -ErrorAction Stop) |
        ForEach-Object {
          $child = "$ns\$($_.Name)"
          if (-not $seen.Contains($child)) { $queue.Enqueue($child); [void]$seen.Add($child) }
        }
    } catch { }
  }
}

function Test-WmiRightsDynamic {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string[]]$ComputerName,
    [Parameter(Mandatory)][string]$Account
  )

  # Required rights
  $ENABLE   = 0x0001  # Enable Account
  $EXECUTE  = 0x0002  # Execute Methods
  $REMOTE   = 0x0020  # Remote Enable
  $NEEDED   = $ENABLE -bor $EXECUTE -bor $REMOTE

  # Resolve SIDs that we’ll treat as granting access (account + common groups)
  $sidTargets = New-Object System.Collections.Generic.List[System.Security.Principal.SecurityIdentifier]
  $acctSid = (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier])
  $sidTargets.Add($acctSid)

  # Well‑known groups that frequently carry these rights
  $wellKnown = @(
    [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,
    [System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid,
    [System.Security.Principal.WellKnownSidType]::WorldSid,   # Everyone
    [System.Security.Principal.WellKnownSidType]::BuiltinUsersSid
  )
  foreach($wk in $wellKnown){
    try { $sidTargets.Add([System.Security.Principal.SecurityIdentifier]::new($wk,$null)) } catch { }
  }

  $rows = foreach($c in $ComputerName){
    foreach($ns in Get-WmiNamespaces -ComputerName $c){
      $scope = $null; $secClass = $null; $sd = $null
      $readSD = $true; $err = $null

      try {
        $scope   = New-Object System.Management.ManagementScope("\\$c\$ns"); $scope.Connect()
        $secClass= New-Object System.Management.ManagementClass($scope,(New-Object System.Management.ManagementPath("__SystemSecurity")),$null)
        $sd      = ($secClass.InvokeMethod("GetSecurityDescriptor",$null,$null)).Descriptor
      } catch {
        $readSD = $false; $err = $_.Exception.Message
      }

      if(-not $readSD){
        [pscustomobject]@{
          Computer=$c; Namespace=$ns; CanConnect=$false; HasEnable=$false; HasExecute=$false; HasRemote=$false; HasAll=$false; Notes=$err
        }
        continue
      }

      # Aggregate allowed mask for any matching ACE (account or well-known groups)
      $effectiveMask = 0
      foreach($ace in $sd.DACL){
        if(-not $ace.Trustee -or -not $ace.Trustee.SID){ continue }
        $sidBytes = [byte[]]$ace.Trustee.SID
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes,0)
        if($sidTargets.Exists({ param($s) $s.Equals($sid) })){
          # Only count ACCESS_ALLOWED ACEs (AceType 0)
          if($ace.AceType -eq 0){ $effectiveMask = $effectiveMask -bor $ace.AccessMask }
        }
      }

      $hasEnable  = (($effectiveMask -band $ENABLE) -ne 0)
      $hasExecute = (($effectiveMask -band $EXECUTE) -ne 0)
      $hasRemote  = (($effectiveMask -band $REMOTE) -ne 0)
      $hasAll     = (($effectiveMask -band $NEEDED) -eq $NEEDED)

      [pscustomobject]@{
        Computer=$c; Namespace=$ns; CanConnect=$true; HasEnable=$hasEnable; HasExecute=$hasExecute; HasRemote=$hasRemote; HasAll=$hasAll
        Notes= if($hasAll){''} else { 'Missing required right(s)' }
      }
    }
  }

  $rows | Sort-Object Computer,Namespace
}

# ------------------- EXAMPLES -------------------
# Show only namespaces where the account is fully good to go:
# Test-WmiRightsDynamic -ComputerName 'qsql-02' -Account 'AD\svc_oemagt' | Where-Object HasAll | Format-Table -Auto

# Show where it is missing something (your main ask):
# Test-WmiRightsDynamic -ComputerName 'qsql-02' -Account 'AD\svc_oemagt' | Where-Object { -not $_.HasAll } | Format-Table -Auto

$result = Test-WmiRightsDynamic -ComputerName 'qsql-02' -Account 'AD\svc_oemagt'

$result | Where-Object { -not $_.HasAll } | Format-Table -Auto
$result | Where-Object { -not $_.HasAll } | clip
$result | clip