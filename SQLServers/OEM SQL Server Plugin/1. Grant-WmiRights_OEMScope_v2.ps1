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

function Show-DcomLaunchEffectiveRemote {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$ComputerName,

    # Optional: only return rows where Account matches this text (e.g. 'SQL_OEM_WMI_DCOM')
    [string]$MatchAccount,

    # Optional creds if you need alternate auth
    [pscredential]$Credential
  )

  $sb = {
    param($MatchAccount)

    $rows = @()

    try {
      # --- POLICY (GPO) value: REG_SZ SDDL string ---
      $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DCOM'
      $polVal = (Get-ItemProperty $polKey -Name MachineLaunchRestriction -ErrorAction SilentlyContinue).MachineLaunchRestriction
      if ($polVal) {
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor $polVal
        $rows += $sd.DiscretionaryAcl |
        Where-Object AceQualifier -EQ 'AccessAllowed' |
        ForEach-Object {
          $m = [int]$_.AccessMask
          try { $acct = $_.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value }
          catch { $acct = $_.SecurityIdentifier.Value }
          [pscustomobject]@{
            Computer         = $env:COMPUTERNAME
            Source           = 'POLICY'
            Account          = $acct
            LocalLaunch      = ($m -band 0x2) -ne 0
            RemoteLaunch     = ($m -band 0x4) -ne 0
            LocalActivation  = ($m -band 0x8) -ne 0
            RemoteActivation = ($m -band 0x10) -ne 0
          }
        }
      }

      # --- LOCAL (dcomcnfg) value: REG_BINARY ---
      $locKey = 'HKLM:\SOFTWARE\Microsoft\Ole'
      $locBin = (Get-ItemProperty $locKey -Name MachineLaunchRestriction -ErrorAction SilentlyContinue).MachineLaunchRestriction
      if ($locBin) {
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor ($locBin, 0)
        $rows += $sd.DiscretionaryAcl |
        Where-Object AceQualifier -EQ 'AccessAllowed' |
        ForEach-Object {
          $m = [int]$_.AccessMask
          try { $acct = $_.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value }
          catch { $acct = $_.SecurityIdentifier.Value }
          [pscustomobject]@{
            Computer         = $env:COMPUTERNAME
            Source           = 'LOCAL'
            Account          = $acct
            LocalLaunch      = ($m -band 0x2) -ne 0
            RemoteLaunch     = ($m -band 0x4) -ne 0
            LocalActivation  = ($m -band 0x8) -ne 0
            RemoteActivation = ($m -band 0x10) -ne 0
          }
        }
      }

      if ($MatchAccount) {
        $rows = $rows | Where-Object { $_.Account -like "*$MatchAccount*" }
      }

      $rows | Sort-Object Source, Account
    }
    catch {
      [pscustomobject]@{
        Computer = ''; Source = 'ERROR'; Account = $null
        LocalLaunch = $false; RemoteLaunch = $false
        LocalActivation = $false; RemoteActivation = $false
        Note = $_.Exception.Message
      }
    }
  }

  $invokeParams = @{ ScriptBlock = $sb; ArgumentList = @($MatchAccount) }
  if ($Credential) { $invokeParams.Credential = $Credential }

  foreach ($c in $ComputerName) {
    try {
      Invoke-Command -ComputerName $c @invokeParams
    }
    catch {
      Write-Warning "[$c] $_"
    }
  }
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









function Test-WmiRights_OEMScope {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string[]]$ComputerName,
    [Parameter(Mandatory)][string]$Account,
    [switch]$IncludeExecuteOnCimv2,     # matches your Grant function
    [pscredential]$Credential
  )

  $BIT_EXECUTE = 0x0002
  $BIT_ENABLE = 0x0001
  $BIT_REMOTE = 0x0020
  $REQ_DEFAULT = $BIT_ENABLE -bor $BIT_EXECUTE -bor $BIT_REMOTE
  $REQ_SQL = $REQ_DEFAULT
  $REQ_CIMV2 = if ($IncludeExecuteOnCimv2) { $REQ_DEFAULT } else { $BIT_ENABLE -bor $BIT_REMOTE }

  $sb = {
    param($Account, $REQ_CIMV2, $REQ_DEFAULT, $REQ_SQL)

    function ReadAcl($ns) {
      try {
        $scope = New-Object System.Management.ManagementScope("\\$env:COMPUTERNAME\$ns"); $scope.Connect()
        $sec = New-Object System.Management.ManagementClass($scope, (New-Object System.Management.ManagementPath('__SystemSecurity')), $null)
        $ret = $sec.InvokeMethod('GetSecurityDescriptor', $null, $null)
        if ($ret.ReturnValue -ne 0 -or -not $ret.Descriptor) { return $null }
        return $ret.Descriptor
      }
      catch { return $null }
    }

    # Resolve SID
    try {
      $sid = (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier])
      $sidBytes = New-Object 'byte[]' ($sid.BinaryLength); $sid.GetBinaryForm($sidBytes, 0)
      $sidKey = ($sidBytes -join ',')
    }
    catch { throw "[$env:COMPUTERNAME] Cannot resolve [$Account] to SID: $($_.Exception.Message)" }

    function Eval-NS($ns, [int]$required, [bool]$expectPropagate) {
      $sd = ReadAcl $ns
      if (-not $sd) {
        return [pscustomobject]@{
          Computer = $env:COMPUTERNAME; Namespace = $ns; RequiredMask = ('0x{0:X}' -f $required)
          AccessMask = ''; HasRequired = $false; Source = 'ERROR'; Propagates = $false; ExpectPropagate = $expectPropagate
          PASS = $false; Note = 'Cannot read security descriptor'
        }
      }
      $mask = 0; $flags = 0; $src = 'INHERITED'; $hit = $false
      foreach ($ace in @($sd.DACL)) {
        if ($ace.Trustee -and $ace.Trustee.SID) {
          if ( ([byte[]]$ace.Trustee.SID -join ',') -eq $sidKey ) {
            $hit = $true; $mask = $mask -bor ([int]$ace.AccessMask); $flags = $flags -bor ([int]$ace.AceFlags)
            if ( ($ace.AceFlags -band 0x10) -eq 0 ) { $src = 'EXPLICIT' }  # not INHERITED
          }
        }
      }
      $hasReq = ( ($mask -band $required) -eq $required )
      $prop = ( ($flags -band 0x02) -ne 0 )  # CONTAINER_INHERIT_ACE
      $pass = $hasReq -and ( -not $expectPropagate -or $prop )

      [pscustomobject]@{
        Computer        = $env:COMPUTERNAME
        Namespace       = $ns
        RequiredMask    = ('0x{0:X}' -f $required)
        AccessMask      = ('0x{0:X}' -f $mask)
        HasRequired     = $hasReq
        Source          = $(if ($hit) { $src }else { 'NONE' })
        Propagates      = $prop
        ExpectPropagate = $expectPropagate
        PASS            = $pass
        Note            = $(if (-not $hit) { 'No ACE for this account' } else { if ($expectPropagate -and -not $prop) { 'Expected propagate flag at this level' } else { '' } })
      }
    }

    $rows = @()
    # Evaluate scopes
    $rows += Eval-NS 'root\cimv2' $REQ_CIMV2 $false
    $rows += Eval-NS 'root\DEFAULT' $REQ_DEFAULT $false
    $rows += Eval-NS 'root\Microsoft\SqlServer' $REQ_SQL $true

    # Children under SQL branch (2 levels deep is plenty for SQL WMI)
    try {
      $kids = Get-CimInstance -Namespace 'root\Microsoft\SqlServer' -Class __NAMESPACE -ErrorAction Stop |
      Select-Object -ExpandProperty Name
      foreach ($k in $kids) {
        $ns1 = "root\Microsoft\SqlServer\$k"
        $rows += Eval-NS $ns1 $REQ_SQL $false
        try {
          $kids2 = Get-CimInstance -Namespace $ns1 -Class __NAMESPACE -ErrorAction Stop |
          Select-Object -ExpandProperty Name
          foreach ($k2 in $kids2) {
            $ns2 = "$ns1\$k2"
            $rows += Eval-NS $ns2 $REQ_SQL $false
          }
        }
        catch {}
      }
    }
    catch {}

    $rows
  }

  foreach ($c in $ComputerName) {
    $p = @{ ComputerName = $c; ScriptBlock = $sb; ArgumentList = @($Account, $REQ_CIMV2, $REQ_DEFAULT, $REQ_SQL) }
    if ($Credential) { $p.Credential = $Credential }
    try {
      Invoke-Command @p |
      Sort-Object Namespace |
      Select-Object Computer, Namespace, Source, Propagates, ExpectPropagate, RequiredMask, AccessMask, PASS, Note
    }
    catch {
      Write-Warning "[$c] $_"
    }
  }
}


# Validate after running your grant functions
Test-WmiRights_OEMScope -ComputerName qsql-02 -Account 'AD\svc_oemagt' |
Format-Table -Auto

# Multiple servers
$servers = 'qsql-02', 'qsql-04'
Test-WmiRights_OEMScope -ComputerName $servers -Account 'AD\svc_oemagt' |
Sort-Object Computer, Namespace | ft -Auto





