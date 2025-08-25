function Grant-WmiRights_OEMScope {
  <#
    Grants WMI rights for Oracle OEM SQL plug-in with scoped recursion:
      - root\cimv2   : Enable + Remote (optionally + Execute) [NON-RECURSIVE]
      - root\DEFAULT : Enable + Execute + Remote              [NON-RECURSIVE]
      - root\Microsoft\SqlServer : Enable + Execute + Remote  [RECURSIVE]
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory = $true)][string[]]$ComputerName,
    [Parameter(Mandatory = $true)][string]$Account,
    [switch]$IncludeExecuteOnCimv2
  )

  # --- Permission bitmasks ---
  $ENABLE = 0x0001   # Enable Account
  $EXECUTE = 0x0002   # Execute Methods
  $REMOTE = 0x0020   # Remote Enable

  function Set-WmiAceExact {
    param(
      [string]$Computer, [string]$Namespace, [string]$Account, [int]$Mask, [bool]$InheritToChildren = $false
    )

    $target = "\\$Computer\$Namespace for [$Account]"
    if (-not $PSCmdlet.ShouldProcess($target, "Set WMI ACL")) { return }

    $scope = New-Object System.Management.ManagementScope("\\$Computer\$Namespace")
    $scope.Connect()

    $secClass = New-Object System.Management.ManagementClass($scope, (New-Object System.Management.ManagementPath("__SystemSecurity")), $null)
    $out = $secClass.InvokeMethod("GetSecurityDescriptor", $null, $null)
    if ($out.ReturnValue -ne 0) { throw "GetSecurityDescriptor RV=$($out.ReturnValue)" }
    $sd = $out.Descriptor

    $nt = New-Object System.Security.Principal.NTAccount($Account)
    $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier])
    $sidBytes = New-Object 'byte[]' ($sid.BinaryLength); $sid.GetBinaryForm($sidBytes, 0)
    $sidKey = ($sidBytes -join ',')

    $trustee = ([wmiclass]"\\$Computer\root\cimv2:Win32_Trustee").CreateInstance()
    $trustee.SID = $sidBytes
    $trustee.Name = $nt.Value.Split('\')[-1]
    if ($nt.Value -like "*\*") { $trustee.Domain = $nt.Value.Split('\')[0] }

    $ace = ([wmiclass]"\\$Computer\root\cimv2:Win32_Ace").CreateInstance()
    $ace.AccessMask = $Mask
    if ($InheritToChildren) { $ace.AceFlags = 0x02 } else { $ace.AceFlags = 0x00 }
    $ace.AceType = 0
    $ace.Trustee = $trustee

    $newDacl = New-Object System.Collections.ArrayList
    $replaced = $false
    foreach ($e in @($sd.DACL)) {
      if ($e.Trustee -and $e.Trustee.SID) {
        $k = ([byte[]]$e.Trustee.SID -join ',')
        if ($k -eq $sidKey) {
          $e.AccessMask = $Mask
          if ($InheritToChildren) {
            $e.AceFlags = ($e.AceFlags -bor 0x02)
          }
          else {
            $e.AceFlags = ($e.AceFlags -band (-bnot 0x02))
          }
          $replaced = $true
        }
      }
      [void]$newDacl.Add($e)
    }
    if (-not $replaced) { [void]$newDacl.Add($ace) }
    $sd.DACL = @($newDacl)

    $in = $secClass.GetMethodParameters("SetSecurityDescriptor"); $in.Descriptor = $sd
    $rv = $secClass.InvokeMethod("SetSecurityDescriptor", $in, $null).ReturnValue
    if ($rv -ne 0) { throw "SetSecurityDescriptor RV=$rv" }
    Write-Verbose "[$Computer] Set ACE on $Namespace (Inherit=$InheritToChildren)"
  }

  function Get-ChildNamespaces {
    param([string]$Computer, [string]$RootNamespace)
    $q = New-Object System.Collections.Generic.Queue[string]
    $q.Enqueue($RootNamespace)
    $seen = New-Object System.Collections.Generic.HashSet[string]
    [void]$seen.Add($RootNamespace)
    $all = @()
    while ($q.Count) {
      $ns = $q.Dequeue()
      $all += $ns
      try {
        Get-CimInstance -ComputerName $Computer -Namespace $ns -Class __NAMESPACE -ErrorAction Stop |
        ForEach-Object {
          $child = "$ns\$($_.Name)"
          if ($seen.Add($child)) { $q.Enqueue($child) }
        }
      }
      catch { }
    }
    return $all
  }

  foreach ($c in $ComputerName) {
    try {
      Write-Verbose "Processing $c"

      # 1) root\cimv2  (no recurse)
      if ($IncludeExecuteOnCimv2) {
        $maskCimv2 = $ENABLE -bor $EXECUTE -bor $REMOTE
      }
      else {
        $maskCimv2 = $ENABLE -bor $REMOTE
      }
      Set-WmiAceExact -Computer $c -Namespace 'root\cimv2' -Account $Account -Mask $maskCimv2 -InheritToChildren:$false

      # 2) root\DEFAULT (no recurse; doc always includes Execute here)
      $maskDefault = $ENABLE -bor $EXECUTE -bor $REMOTE
      Set-WmiAceExact -Computer $c -Namespace 'root\DEFAULT' -Account $Account -Mask $maskDefault -InheritToChildren:$false

      # 3) root\Microsoft\SqlServer (recursive)
      $sqlRoot = 'root\Microsoft\SqlServer'
      try {
        $scope = New-Object System.Management.ManagementScope("\\$c\$sqlRoot"); $scope.Connect()
        $maskSql = $ENABLE -bor $EXECUTE -bor $REMOTE
        # put inheritable ACE at the branch
        Set-WmiAceExact -Computer $c -Namespace $sqlRoot -Account $Account -Mask $maskSql -InheritToChildren:$true

        # also stamp all children explicitly
        $allSql = Get-ChildNamespaces -Computer $c -RootNamespace $sqlRoot
        foreach ($ns in ($allSql | Where-Object { $_ -ne $sqlRoot })) {
          Set-WmiAceExact -Computer $c -Namespace $ns -Account $Account -Mask $maskSql -InheritToChildren:$false
        }
      }
      catch {
        Write-Warning "[$c] Could not access $sqlRoot : $_"
      }
    }
    catch {
      Write-Warning "[$c] $_"
    }
  }
}

function Grant-RegistryRights_OEM {
  <#
      Grants Read rights to the OEM service account on SQL Server registry keys.
      Works locally or against remote servers.
      Default: uses PowerShell Remoting (WinRM). Use -UseRemoteRegistry to use the Remote Registry API instead.
      Uses SetAccessRule which in .NET replaces an existing ACE for that identity/right with the new one instead of AddAccessRule
    #>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory = $true)][string]$Account,
    [string[]]$ComputerName = $env:COMPUTERNAME,
    [switch]$UseRemoteRegistry
  )

  $regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server',
    'HKLM:\SOFTWARE\Microsoft\MSSQLServer',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\MSSQLServer'
  )

  if (-not $UseRemoteRegistry) {
    # --- WinRM path (preferred) ---
    $sb = {
      param($Account, $Paths)
      $changed = 0
      foreach ($path in $Paths) {
        if (-not (Test-Path -Path $path)) { continue }
        try {
          $acl = Get-Acl -Path $path
          $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $Account,
            [System.Security.AccessControl.RegistryRights]::ReadKey,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
          )
          $acl.SetAccessRule($rule)
          Set-Acl -Path $path -AclObject $acl
          $changed++
          Write-Host "Granted ReadKey on $path to $Account"
        }
        catch {
          Write-Warning "Failed to set ACL on $path : $_"
        }
      }
      return $changed
    }

    foreach ($c in $ComputerName) {
      if ($PSCmdlet.ShouldProcess($c, "Grant SQL registry Read rights via WinRM")) {
        try {
          if ($c -eq $env:COMPUTERNAME) {
            & $sb $Account $regPaths | Out-Null
          }
          else {
            Invoke-Command -ComputerName $c -ScriptBlock $sb -ArgumentList $Account, $regPaths | Out-Null
          }
        }
        catch {
          Write-Warning "[$c] WinRM path failed: $_. Consider -UseRemoteRegistry."
        }
      }
    }
    return
  }

  # --- Remote Registry API path (no WinRM, requires Remote Registry service) ---
  Add-Type -AssemblyName 'Microsoft.Win32.Registry'

  function Set-RemoteRegRead {
    param([string]$Computer, [string]$Account, [string]$Path)

    # Parse hive + subkey
    if ($Path -notmatch '^HKLM:\\(.+)$') { return }  # this function handles HKLM only
    $subKey = $Matches[1]

    try {
      $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $Computer)
      # Open with rights to change permissions
      $key = $base.OpenSubKey($subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions)
      if (-not $key) { return }

      $rs = $key.GetAccessControl()
      $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
        $Account,
        [System.Security.AccessControl.RegistryRights]::ReadKey,
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
      )
      $rs.SetAccessRule($rule)
      $key.SetAccessControl($rs)
      $key.Close()
      Write-Host "[$Computer] Granted ReadKey on HKLM:\$subKey to $Account"
    }
    catch {
      Write-Warning "[$Computer] Failed on HKLM:\$subKey : $_"
    }
  }

  foreach ($c in $ComputerName) {
    if ($PSCmdlet.ShouldProcess($c, "Grant SQL registry Read rights via Remote Registry")) {
      foreach ($p in $regPaths) {
        # Only attempt keys that exist remotely (quick existence probe via API)
        try {
          if ($p -match '^HKLM:\\(.+)$') {
            $probeBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $c)
            $probe = $probeBase.OpenSubKey($Matches[1], $false)
            if ($probe) { $probe.Close(); Set-RemoteRegRead -Computer $c -Account $Account -Path $p }
          }
        }
        catch {
          Write-Warning "[$c] Unable to probe $p : $_"
        }
      }
    }
  }
}


function Get-WmiRightsForAccount {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$ComputerName,

    [Parameter(Mandatory)]
    [string]$Account,                 # e.g. 'HVI\SQL_OEM_WMI_DCOM' or 'AD\svc_oemagt'

    [string]$Namespace = 'root',      # start here
    [switch]$Recurse,                 # walk subnamespaces
    [switch]$ShowAll,                 # also list namespaces with no ACE for this account
    [pscredential]$Credential
  )

  # WMI namespace access bits
  $WBEM_EXECUTE = 0x0001  # Execute Methods
  $WBEM_FULLWRITE = 0x0002  # (rarely used)
  $WBEM_PARTIALWRITE = 0x0004  # (rarely used)
  $WBEM_PROVIDERWRITE = 0x0008  # (rarely used)
  $WBEM_ENABLE = 0x0010  # Enable Account
  $WBEM_REMOTEENABLE = 0x0020  # Remote Enable
  $ACE_CI = 0x02    # CONTAINER_INHERIT_ACE (apply to subnamespaces)
  $ACE_INHERITED = 0x10    # INHERITED_ACE

  $sb = {
    param($Account, $Namespace, $Recurse, $ShowAll,
      $WBEM_EXECUTE, $WBEM_ENABLE, $WBEM_REMOTEENABLE, $ACE_CI, $ACE_INHERITED)

    function Get-Namespaces([string]$base) {
      $list = New-Object System.Collections.Generic.List[string]
      $list.Add($base) | Out-Null
      if ($Recurse) {
        try {
          $subs = Get-CimInstance -Namespace $base -ClassName __NAMESPACE -ErrorAction Stop
          foreach ($n in $subs) {
            $child = "$base\$($n.Name)"
            $list.AddRange( (Get-Namespaces $child) )
          }
        }
        catch {}
      }
      return $list
    }

    # Resolve target SID
    try {
      $nt = New-Object System.Security.Principal.NTAccount($Account)
      $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier])
      $sidBytes = New-Object 'byte[]' ($sid.BinaryLength)
      $sid.GetBinaryForm($sidBytes, 0)
      $sidKey = ($sidBytes -join ',')
    }
    catch {
      throw "Cannot resolve [$Account] to a SID on $env:COMPUTERNAME: $($_.Exception.Message)"
    }

    $rows = @()
    foreach ($ns in (Get-Namespaces $Namespace)) {
      try {
        $scope = New-Object System.Management.ManagementScope("\\$env:COMPUTERNAME\$ns")
        $scope.Connect()
        $sec = New-Object System.Management.ManagementClass($scope, (New-Object System.Management.ManagementPath('__SystemSecurity')), $null)
        $out = $sec.InvokeMethod('GetSecurityDescriptor', $null, $null)
        if ($out.ReturnValue -ne 0 -or -not $out.Descriptor) { throw "GetSecurityDescriptor failed: $($out.ReturnValue)" }
        $dacl = @($out.Descriptor.DACL)

        $mask = 0; $flags = 0; $has = $false
        $src = $null
        foreach ($ace in $dacl) {
          if ($ace.Trustee -and $ace.Trustee.SID) {
            if ( ($ace.Trustee.SID -join ',') -eq $sidKey ) {
              $has = $true
              $mask = $mask  -bor ([int]$ace.AccessMask)
              $flags = $flags -bor ([int]$ace.AceFlags)
              if ( ([int]$ace.AceFlags -band $ACE_INHERITED) -eq 0 ) { $src = 'EXPLICIT' } elseif (-not $src) { $src = 'INHERITED' }
            }
          }
        }

        if ($has -or $ShowAll) {
          $rows += [pscustomobject]@{
            Computer           = $env:COMPUTERNAME
            Namespace          = $ns
            HasExecute         = [bool]($mask -band $WBEM_EXECUTE)
            HasEnable          = [bool]($mask -band $WBEM_ENABLE)
            HasRemote          = [bool]($mask -band $WBEM_REMOTEENABLE)
            HasAll             = [bool]( ($mask -band ($WBEM_EXECUTE -bor $WBEM_ENABLE -bor $WBEM_REMOTEENABLE)) -eq ($WBEM_EXECUTE -bor $WBEM_ENABLE -bor $WBEM_REMOTEENABLE))
            Source             = $(if ($has) { if ($src) { $src }else { 'INHERITED' } } else { 'NONE' })
            InheritsToChildren = [bool]( ($flags -band $ACE_CI) -ne 0 )
            AccessMaskHex      = ('0x{0:X}' -f $mask)
            AceFlagsHex        = ('0x{0:X}' -f $flags)
            Notes              = $( if ($has) { if ($src -eq 'EXPLICIT') { 'Account has its own ACE here' } else { 'ACE inherited from parent' } } else { 'No ACE for this account' } )
          }
        }
      }
      catch {
        $rows += [pscustomobject]@{
          Computer = $env:COMPUTERNAME; Namespace = $ns; HasExecute = $false; HasEnable = $false; HasRemote = $false; HasAll = $false
          Source = 'ERROR'; InheritsToChildren = $false; AccessMaskHex = $null; AceFlagsHex = $null; Notes = $_.Exception.Message
        }
      }
    }
    $rows
  }

  $args = @($Account, $Namespace, $Recurse.IsPresent, $ShowAll.IsPresent, $WBEM_EXECUTE, $WBEM_ENABLE, $WBEM_REMOTEENABLE, $ACE_CI, $ACE_INHERITED)
  $out = foreach ($c in $ComputerName) {
    try {
      $p = @{ ComputerName = $c; ScriptBlock = $sb; ArgumentList = $args }
      if ($Credential) { $p.Credential = $Credential }
      Invoke-Command @p
    }
    catch { Write-Warning "[$c] $_" }
  }
  $out
}


<#
# After adding SQL server to SQL_OEM_WMI_DCOM, we might need to Force refresh + refresh the computer account’s token:
# gpupdate /force
# klist -li 0x3e7 purge   # or reboot
# We can also see these settings getting applied at
# reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DCOM" /v MachineLaunchRestriction


# Check to confirm settings have been applied
$servers = 'qsql-02','qsql-04','qsql-06'
Show-DcomLaunchEffectiveRemote -ComputerName $servers -MatchAccount 'SQL_OEM_WMI_DCOM' |
  Format-Table Computer,Source,Account,RemoteLaunch,RemoteActivation -Auto
#>

# Grant-WmiRights_OEMScope
# monitoring only (no OEM job execution from cimv2)
# Grant-WmiRights_OEMScope -ComputerName 'qsql-02' -Account 'AD\svc_oemagt' -Confirm:$false # Ran this 
# Grant-WmiRights_OEMScope -ComputerName qsql-02,qsql-04,qsql-06 -Account 'AD\svc_oemagt' -Confirm:$false
# Or we can define array in the start
# $servers = @('qsql-02','qsql-04','qsql-06')
# Grant-WmiRights_OEMScope -ComputerName $servers -Account 'AD\svc_oemagt' -Confirm:$false
# Check with Chris if OEM will also execute jobs. If yes, re run the function and add Execute on cimv2 too
# Grant-WmiRights_OEMScope -ComputerName 'qsql-02' -Account 'AD\svc_oemagt' -IncludeExecuteOnCimv2 -Verbose -Confirm:$false


# Grant-RegistryRights_OEM
# One server
# Grant-RegistryRights_OEM -Account 'AD\svc_oemagt' -ComputerName qsql-02 -Confirm:$false # Ran this
# Grant-RegistryRights_OEM -Account 'AD\svc_oemagt' -ComputerName qsql-02 -UseRemoteRegistry -Confirm:$false
# Many servers
# Grant-RegistryRights_OEM -Account 'AD\svc_oemagt' -ComputerName qsql-02, qsql-04, qsql-06 -Confirm:$false



