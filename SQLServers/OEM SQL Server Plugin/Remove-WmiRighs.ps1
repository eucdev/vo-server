function Find-WmiAce {
  # This function does recurse through all namespaces under root
  # Find-WmiAce -ComputerName 'qsql-02' -Account 'AD\svc_oemagt' | Format-Table -Auto
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][string]$Account
  )
  $acctSid = (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier])
  $acctSidBytes = New-Object 'byte[]' ($acctSid.BinaryLength); $acctSid.GetBinaryForm($acctSidBytes, 0)
  $sidKey = ($acctSidBytes -join ',')

  function Get-WmiNamespaces([string]$c, [string]$start = 'root') {
    $q = [System.Collections.Generic.Queue[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
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

  foreach ($ns in Get-WmiNamespaces $ComputerName) {
    try {
      $scope = New-Object System.Management.ManagementScope("\\$ComputerName\$ns"); $scope.Connect()
      $secClass = New-Object System.Management.ManagementClass($scope, (New-Object System.Management.ManagementPath('__SystemSecurity')), $null)
      $sd = ($secClass.InvokeMethod('GetSecurityDescriptor', $null, $null)).Descriptor
      foreach ($ace in $sd.DACL) {
        if ($ace.Trustee -and $ace.Trustee.SID) {
          $thisKey = ([byte[]]$ace.Trustee.SID -join ',')
          if ($thisKey -eq $sidKey) {
            [pscustomobject]@{ Computer = $ComputerName; Namespace = $ns; AccessMask = $ace.AccessMask; AceFlags = $ace.AceFlags }
          }
        }
      }
    }
    catch { }
  }
}

function Remove-WmiAce {
  <#
    Removes the explicit ACE(s) for a given account from one or more WMI namespaces.
    - Default: removes ALL ACEs for that SID in the namespace DACL
    - $hits = Find-WmiAce -ComputerName 'qsql-02' -Account 'AD\svc_oemagt'
    - Remove-WmiAce -ComputerName 'qsql-02' -Account 'AD\svc_oemagt' -Namespace $hits.Namespace
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory)][string[]]$ComputerName,
    [Parameter(Mandatory)][string]$Account,
    [Parameter(Mandatory)][string[]]$Namespace,
    [switch]$KeepOtherRights  # (on by default conceptually; included for clarity)
  )

  $acctSid = (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier])
  $acctSidBytes = New-Object 'byte[]' ($acctSid.BinaryLength); $acctSid.GetBinaryForm($acctSidBytes, 0)
  $sidKey = ($acctSidBytes -join ',')

  foreach ($c in $ComputerName) {
    foreach ($ns in $Namespace) {

      $target = "\\$c\$ns for [$Account]"
      if (-not $PSCmdlet.ShouldProcess($target, "Remove explicit ACE(s)")) { continue }

      try {
        $scope = New-Object System.Management.ManagementScope("\\$c\$ns"); $scope.Connect()
        $secClass = New-Object System.Management.ManagementClass($scope, (New-Object System.Management.ManagementPath("__SystemSecurity")), $null)
        $get = $secClass.InvokeMethod("GetSecurityDescriptor", $null, $null)
        if ($get.ReturnValue -ne 0) { throw "GetSecurityDescriptor RV=$($get.ReturnValue)" }
        $sd = $get.Descriptor

        $orig = @($sd.DACL)
        if (-not $orig) { Write-Verbose "[$c][$ns] No DACL? Skipping."; continue }

        # Filter out ACEs that match our SID (explicit allow or deny)
        $new = New-Object System.Collections.ArrayList
        $removed = 0
        foreach ($ace in $orig) {
          $match = $false
          if ($ace.Trustee -and $ace.Trustee.SID) {
            $thisKey = ([byte[]]$ace.Trustee.SID -join ',')
            if ($thisKey -eq $sidKey) { $match = $true }
          }
          if ($match) { $removed++ } else { [void]$new.Add($ace) }
        }

        if ($removed -eq 0) {
          Write-Host "[$c] No explicit ACE found for $Account in $ns (nothing to do)."
          continue
        }

        $sd.DACL = @($new)

        $in = $secClass.GetMethodParameters("SetSecurityDescriptor")
        $in.Descriptor = $sd
        $set = $secClass.InvokeMethod("SetSecurityDescriptor", $in, $null)
        if ($set.ReturnValue -ne 0) { throw "SetSecurityDescriptor RV=$($set.ReturnValue)" }

        Write-Host "[$c] Removed $removed ACE(s) for $Account from $ns."
      }
      catch {
        Write-Warning "[$c][$ns] $_"
      }
    }
  }
}

# Here is how I cleaned out OEM permissions at root level. We need to grant it following least privilege
$hits = Find-WmiAce -ComputerName 'qsql-02' -Account 'AD\svc_oemagt'
Remove-WmiAce -ComputerName 'qsql-02' -Account 'AD\svc_oemagt' -Namespace $hits.Namespace


