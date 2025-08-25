function Test-WmiRightsExact {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string[]]$ComputerName,
    [Parameter(Mandatory)][string]$Account
  )
  $ENABLE = 0x1; $EXECUTE = 0x2; $REMOTE = 0x20; $NEEDED = $ENABLE -bor $EXECUTE -bor $REMOTE
  $acctSid = (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier])

  function Get-WmiNamespaces([string]$c, [string]$start = 'root') {
    $q = [System.Collections.Generic.Queue[string]]::new(); $seen = [System.Collections.Generic.HashSet[string]]::new()
    $q.Enqueue($start); $seen.Add($start) | Out-Null
    while ($q.Count) {
      $ns = $q.Dequeue(); $ns
      try {
        Get-CimInstance -ComputerName $c -Namespace $ns -Class __NAMESPACE -ErrorAction Stop |
        % { $child = "$ns\$($_.Name)"; if ($seen.Add($child)) { $q.Enqueue($child) } } 
      }
      catch {}
    }
  }

  foreach ($c in $ComputerName) {
    foreach ($ns in Get-WmiNamespaces $c) {
      $scope = New-Object System.Management.ManagementScope("\\$c\$ns")
      try {
        $scope.Connect()
        $secClass = New-Object System.Management.ManagementClass($scope, (New-Object System.Management.ManagementPath('__SystemSecurity')), $null)
        $sd = ($secClass.InvokeMethod('GetSecurityDescriptor', $null, $null)).Descriptor
      }
      catch {
        [pscustomobject]@{Computer = $c; Namespace = $ns; HasEnable = $false; HasExecute = $false; HasRemote = $false; HasAll = $false; Source = 'N/A'; Notes = $_.Exception.Message }
        continue
      }

      $mask = 0; $source = 'none'
      foreach ($ace in $sd.DACL) {
        if ($ace.AceType -ne 0 -or -not $ace.Trustee -or -not $ace.Trustee.SID) { continue }
        $sid = [System.Security.Principal.SecurityIdentifier]::new([byte[]]$ace.Trustee.SID, 0)
        if ($sid.Equals($acctSid)) { $mask = $mask -bor $ace.AccessMask; $source = 'EXPLICIT'; }
      }

      $he = ($mask -band $ENABLE) -ne 0
      $hx = ($mask -band $EXECUTE) -ne 0
      $hr = ($mask -band $REMOTE) -ne 0
      [pscustomobject]@{
        Computer = $c; Namespace = $ns; HasEnable = $he; HasExecute = $hx; HasRemote = $hr; HasAll = (($mask -band $NEEDED) -eq $NEEDED)
        Source = $source; Notes = if ($source -eq 'EXPLICIT') { 'Account has its own ACE here' } else { 'No explicit ACE for account (may be via group)' }
      }
    }
  }
}

# Example:
# Test-WmiRightsExact -ComputerName 'qsql-02' -Account 'AD\svc_oemagt' |
#   Where-Object HasAll | Format-Table -Auto


$TestWmiRightsExact = Test-WmiRightsExact -ComputerName 'qsql-02' -Account 'AD\svc_oemagt'
$TestWmiRightsExact | Where-Object HasAll | Format-Table -Auto
$TestWmiRightsExact | Where-Object HasAll | clip