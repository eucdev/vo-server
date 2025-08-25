function Get-WmiNamespaceTree {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$ComputerName,
    [string[]]$Roots = @('root\cimv2', 'root\DEFAULT')
  )

  $rows = @()
  foreach ($start in $Roots) {
    $q = New-Object System.Collections.Generic.Queue[psobject]
    $q.Enqueue([pscustomobject]@{ NS = $start; Depth = 0 })

    while ($q.Count) {
      $item = $q.Dequeue()

      $rows += [pscustomobject]@{
        Computer  = $ComputerName
        Namespace = $item.NS
        Depth     = $item.Depth
      }

      try {
        Get-CimInstance -ComputerName $ComputerName -Namespace $item.NS -Class __NAMESPACE -ErrorAction Stop |
        ForEach-Object {
          $child = "$($item.NS)\$($_.Name)"
          $q.Enqueue([pscustomobject]@{ NS = $child; Depth = $item.Depth + 1 })
        }
      }
      catch {
        # ignore nodes that don't enumerate
      }
    }
  }
  return $rows
}

function Show-WmiNamespaceTree {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$ComputerName,
    [string[]]$Roots = @('root\cimv2', 'root\DEFAULT', 'root\Microsoft\SqlServer'),
    [string]$Account,          # optional: annotate rights for this account
    [switch]$OnlyMissing       # when -Account is provided, show only nodes missing rights
  )

  $tree = Get-WmiNamespaceTree -ComputerName $ComputerName -Roots $Roots

  if ($PSBoundParameters.ContainsKey('Account')) {
    $ENABLE = 0x1; $EXECUTE = 0x2; $REMOTE = 0x20; $NEEDED = $ENABLE -bor $EXECUTE -bor $REMOTE
    $acctSid = (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier])

    foreach ($row in $tree) {
      try {
        $scope = New-Object System.Management.ManagementScope("\\$($row.Computer)\$($row.Namespace)")
        $scope.Connect()
        $secClass = New-Object System.Management.ManagementClass($scope, (New-Object System.Management.ManagementPath('__SystemSecurity')), $null)
        $sd = ($secClass.InvokeMethod('GetSecurityDescriptor', $null, $null)).Descriptor

        $mask = 0
        foreach ($ace in $sd.DACL) {
          if (-not $ace.Trustee -or -not $ace.Trustee.SID -or $ace.AceType -ne 0) { continue }
          $sid = New-Object System.Security.Principal.SecurityIdentifier([byte[]]$ace.Trustee.SID, 0)
          if ($sid.Equals($acctSid)) { $mask = $mask -bor $ace.AccessMask }
        }

        $row | Add-Member -NotePropertyName HasEnable -NotePropertyValue ((($mask -band $ENABLE) -ne 0)) -Force
        $row | Add-Member -NotePropertyName HasExecute -NotePropertyValue ((($mask -band $EXECUTE) -ne 0)) -Force
        $row | Add-Member -NotePropertyName HasRemote -NotePropertyValue ((($mask -band $REMOTE) -ne 0)) -Force
        $row | Add-Member -NotePropertyName HasAll -NotePropertyValue ((($mask -band $NEEDED) -eq $NEEDED)) -Force
        $row | Add-Member -NotePropertyName CanConnect -NotePropertyValue $true -Force
      }
      catch {
        $row | Add-Member -NotePropertyName HasEnable -NotePropertyValue $false -Force
        $row | Add-Member -NotePropertyName HasExecute -NotePropertyValue $false -Force
        $row | Add-Member -NotePropertyName HasRemote -NotePropertyValue $false -Force
        $row | Add-Member -NotePropertyName HasAll -NotePropertyValue $false -Force
        $row | Add-Member -NotePropertyName CanConnect -NotePropertyValue $false -Force
      }
    }

    if ($OnlyMissing) {
      $tree = $tree | Where-Object { -not $_.HasAll }
    }
  }

  foreach ($n in $tree | Sort-Object Namespace) {
    $prefix = ('  ' * $n.Depth)
    if ($n.Depth -gt 0) { $prefix += '└─ ' }

    if ($PSBoundParameters.ContainsKey('Account')) {
      $status = if ($n.HasAll) { '[OK]' } else { '[ ]' }
      Write-Output ("{0}{1}  {2}" -f $prefix, $n.Namespace, $status)
    }
    else {
      Write-Output ("{0}{1}" -f $prefix, $n.Namespace)
    }
  }
}
Show-WmiNamespaceTree -ComputerName qsql-02

<#
https://docs.oracle.com/cd/G27582_01/emptg/enterprise-manager-third-party-database-plug-troubleshooting-guide.pdf
24ai Release 1 (24.1)
F97216-01
December 2024

Baed on the content, no recursion needed. Granting rights at root\cimv2 itself is sufficient.
root\cimv2
  └─ root\cimv2\mdm
    └─ root\cimv2\mdm\dmmap
    └─ root\cimv2\mdm\MS_409
  └─ root\cimv2\ms_409
  └─ root\cimv2\power
    └─ root\cimv2\power\ms_409
  └─ root\cimv2\Security
    └─ root\cimv2\Security\MicrosoftTpm
  └─ root\cimv2\sms
  └─ root\cimv2\TerminalServices
    └─ root\cimv2\TerminalServices\ms_409

Baed on the content, no recursion needed. Granting rights at root\DEFAULT itself is sufficient.
root\DEFAULT
  └─ root\DEFAULT\ms_409

Baed on the content, we can apply recursion just in case Agent wants to query ServerEvents.
root\Microsoft\SqlServer
  └─ root\Microsoft\SqlServer\ComputerManagement16
    └─ root\Microsoft\SqlServer\ComputerManagement16\MS_409
  └─ root\Microsoft\SqlServer\ServerEvents
    └─ root\Microsoft\SqlServer\ServerEvents\MSSQLSERVER
#>