function Add-NameBasedTags {
  param([string] $ComputerName = $env:COMPUTERNAME)

  if (-not $script:tags) { $script:tags = @{} }
  $cn = $ComputerName.Trim()
  $ci = [System.Globalization.CultureInfo]::InvariantCulture

  # Environment
  if ($cn.StartsWith('HVIQH', $true, $ci) -or $cn.StartsWith('Q', $true, $ci)) {
    $script:tags['Environment'] = 'QA'
  }
  elseif ($cn.StartsWith('HVIH', $true, $ci) -or $cn.StartsWith('P', $true, $ci)) {
    $script:tags['Environment'] = 'Production'
  }
  else {
    $null = $script:tags.Remove('Environment')
  }

  # HV tags only for HVI* (HVIH* or HVIQH*)
  $isHVI = $cn.StartsWith('HVIQH', $true, $ci) -or $cn.StartsWith('HVIH', $true, $ci)
  if ($isHVI) {
    $script:tags['Role'] = 'HV'
    $script:tags['AUM'] = 'FALSE'
    $script:tags['Cluster'] = 'TRUE'
  }
  else {
    foreach ($k in 'Role', 'AUM', 'Cluster') { $null = $script:tags.Remove($k) }
  }
  Set-Variable -Name 'tags' -Scope Script -Value $script:tags -Force
  return $script:tags
}
