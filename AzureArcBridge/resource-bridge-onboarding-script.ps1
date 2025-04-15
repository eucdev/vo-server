 #Requires -RunAsAdministrator
[CmdletBinding()]
Param(
    [switch] $Force
)
# Start Region: Set user inputs

$location = 'eastus'

$applianceSubscriptionId = '1d811949-f211-41d3-9a5d-df01d8c44397'
$applianceResourceGroupName = 'rg-arc-hv'
$applianceName = 'arcbridge-hv-cit-qa'

$customLocationSubscriptionId = '1d811949-f211-41d3-9a5d-df01d8c44397'
$customLocationResourceGroupName = 'rg-arc-hv'
$customLocationName = 'cl-hv-cit-qa'

$vmmserverSubscriptionId = '1d811949-f211-41d3-9a5d-df01d8c44397'
$vmmserverResourceGroupName = 'rg-arc-hv'
$vmmserverName = 'scvmm-hv-cit-qa'

# End Region: Set user inputs

function confirmationPrompt($msg) {
    Write-Host $msg
    while ($true) {
        $inp = Read-Host "Yes(y)/No(n)?"
        $inp = $inp.ToLower()
        if ($inp -eq 'y' -or $inp -eq 'yes') {
            return $true
        }
        elseif ($inp -eq 'n' -or $inp -eq 'no') {
            return $false
        }
    }
}

function enterToContinue($msg) {
    $inp = Read-Host $msg
    $inp = $inp.ToLower()
    # allow y,yes and empty string
    if ($inp -eq "" -or $inp -eq 'y' -or $inp -eq 'yes') {
        return $true
    }
    return $false
}

$logFile = Join-Path $PSScriptRoot "arcvmm-output.log"
$vmmConnectLogFile = "arcvmm-connect.log"

function logH1($msg) {
    $pattern = '0-' * 40
    $spaces = ' ' * (40 - $msg.length / 2)
    $nl = [Environment]::NewLine
    $msgFull = "$nl $nl $pattern $nl $spaces $msg $nl $pattern $nl"
    Write-Host -ForegroundColor Green $msgFull
    Add-Content -Value "$msgFull" -Path $logFile
}

function logH2($msg) {
    $msgFull = "==> $msg"
    Write-Host -ForegroundColor Magenta $msgFull
    Add-Content -Value "$msgFull" -Path $logFile
}

function logH3($msg) {
    $msgFull = "==> $msg"
    Write-Host -ForegroundColor Red $msgFull
    Add-Content -Value "$msgFull" -Path $logFile
}

function logH4($msg) {
    Write-Host -ForegroundColor Magenta $msg
}

function showSupportMsg($msg) {
	$pattern = '*' * 115
    $nl = [Environment]::NewLine
	$spaces = ' ' * 115
    $msgFull = "$nl $nl $pattern $nl $spaces $msg $nl $spaces $nl $pattern"
    Write-Host -ForegroundColor Green -BackgroundColor Black $msgFull
    Add-Content -Value "$msgFull" -Path $logFile
}

function logText($msg) {
    Write-Host "$msg"
    Add-Content -Value "$msg" -Path $logFile
}

function logWarn($msg) {
    Write-Host -ForegroundColor Yellow $msg
    Add-Content -Value "$msg" -Path $logFile
}


function createRG($subscriptionId, $rgName) {
    $group = (az group show --subscription $subscriptionId -n $rgName)
    if (!$group) {
        logText "Resource Group $rgName does not exist in subscription $subscriptionId. Trying to create the resource group"
        az group create --subscription $subscriptionId -l $location -n $rgName
    }
}

function fail($msg) {
    $msg = "Script execution failed with error: " + $msg
    Write-Host -ForegroundColor Red $msg
    Add-Content -Value "$msg" -Path $logFile
    logText "The script will terminate shortly"
    Start-Sleep -Seconds 5
    exit 1
}

function VMMConnectInstruction() {
	logH4 "`taz scvmm vmmserver connect --tags `"`" --subscription `"$vmmserverSubscriptionId`" --resource-group `"$vmmserverResourceGroupName`" --name `"$vmmserverName`" --location `"$location`" --custom-location `"$customLocationId`""
}

function evaluateForceFlag([bool]$force, [string]$applianceStatus) {
    $resource_config_file_path = Join-Path $PWD "$applianceName-resource.yaml"
    $infra_config_file_path = Join-Path $PWD "$applianceName-infra.yaml"
    $appliance_config_file_path = Join-Path $PWD "$applianceName-appliance.yaml"

    $missingFiles = @()
    if (!(Test-Path $resource_config_file_path)) {
        $missingFiles += $resource_config_file_path
    }
    if (!(Test-Path $infra_config_file_path)) {
        $missingFiles += $infra_config_file_path
    }
    if (!(Test-Path $appliance_config_file_path)) {
        $missingFiles += $appliance_config_file_path
    }

    if ($missingFiles.Count -eq 0) {
        # If all the config files are present and the appliance is not in running state,
        # we always run with --force flag.
        logText "Using --force flag as all the required config files are present."
        return $true
    }

    if ($missingFiles.Count -eq 3) {
        if ($force) {
            if (![string]::IsNullOrEmpty($applianceStatus)){
                # If no config files are found, it might indicate that the script hasn't been
                # executed in the current directory to create the Azure resources before.
                # We let 'az arcappliance run' command handle the force flag.
                logText "Warning: None of the required config files are present."
            } else {
                # If no config files are found and the RB is not found in Azure,
                # we always run without --force flag
                logText "Ignoring --force flag as all the required config files are missing and an existing Arc resource bridge is not found in Azure."
                return $false
            }
        }
        return $force
    }

    if ($force) {
        # Handle missing config files occuring due to createconfig failure.
        $missingMsg = $missingFiles -join "`n"
        logText "Ignoring --force flag as one or more of the required config files are missing."
        $msg = "Missing configuration files:`n$missingMsg`n"
        logText $msg
    }
    return $false
}

$scFqdnKey = "ScvmmFqdn"
$scPortKey = "ScvmmPort"
$scUsernameKey = "ScvmmUsername"
$scPasswordKey = "ScvmmPassword"
$scvmmDetails = @{}
function fetchScvmmDetailsInto($scvmmDetails, $isVmmServerConnect = $false) {
    if (![string]::IsNullOrEmpty($scvmmDetails[$scFqdnKey]) -and
        ![string]::IsNullOrEmpty($scvmmDetails[$scPortKey]) -and
        ![string]::IsNullOrEmpty($scvmmDetails[$scUsernameKey]) -and
        ![string]::IsNullOrEmpty($scvmmDetails[$scPasswordKey])) {
        return
    }
    while ($true) {
        while ($true) {
            if (![string]::IsNullOrEmpty($scvmmDetails[$scFqdnKey])) {
                $fqdn = $scvmmDetails[$scFqdnKey]
                break
            }
            Write-Host ""
            $fqdn = Read-Host "Please enter SCVMM Server FQDN (e.g. vmmuser001.contoso.lab) or IPv4 address. If you have a Highly Available VMM setup, enter the role name"
            if ([string]::IsNullOrEmpty($fqdn)) {
                Write-Host "`nFQDN or IP Address cannot be empty. Please try again."
                continue
            }
            $ipAddress = $null
            if (!$isVmmServerConnect) {
                if (($fqdn -notmatch '^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$') -and
                    ![System.Net.IPAddress]::TryParse($fqdn, [ref]$ipAddress)) {
                    Write-Host "`nKindly re-enter a valid FQDN with the domain(e.g. vmmuser001.contoso.lab) or a valid IPv4 address."
                    continue
                }
            }
            break
        }
        while ($true) {
            if (![string]::IsNullOrEmpty($scvmmDetails[$scPortKey])) {
                $port = $scvmmDetails[$scPortKey]
                break
            }
            $port = Read-Host "Please enter SCVMM port (press enter to use default port 8100)"
            if ([string]::IsNullOrEmpty($port)) {
                $port = "8100"
            }
            if ($port -match '\D') {
                Write-Host "`nPort should be a number. Please try again."
                continue
            }
            if ([int]$port -lt 1 -or [int]$port -gt 65535) {
                Write-Host "`nPort should be a number between 1 and 65535. Please try again."
                continue
            }
            break
        }
        while ($true) {
            if (![string]::IsNullOrEmpty($scvmmDetails[$scUsernameKey])) {
                $username = $scvmmDetails[$scUsernameKey]
                break
            }
            if (!$isVmmServerConnect) {
                $username = Read-Host "Please enter SCVMM Administrator Username in the format domain\username where 'domain' should be the NetBIOS name of the domain (e.g. contoso\administrator)"
            } else {
                $username = Read-Host "Please enter SCVMM Administrator Username"
            }
            if ([string]::IsNullOrEmpty($username)) {
                Write-Host "`nUsername cannot be empty. Please try again."
                continue
            }
            break
        }
        while ($true) {
            if (![string]::IsNullOrEmpty($scvmmDetails[$scPasswordKey])) {
                $password = $scvmmDetails[$scPasswordKey]
                break
            }
            $passwordSec = Read-Host "Please enter SCVMM Administrator Password" -AsSecureString
            $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSec))
            if ($password.Length -eq 0) {
                Write-Host "`nPassword cannot be empty. Please try again."
                continue
            }

            $confirmPasswordSec = Read-Host "Please confirm SCVMM Administrator Password" -AsSecureString
            $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSec))
            $confirmPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPasswordSec))
            if ($password -cne $confirmPassword) {
                Write-Host "`nPasswords do not match. Please try again."
            }
            else {
                break
            }
        }
        Write-Host "`nSCVMM Server Details:`nSCVMM Server FQDN/IP: $fqdn`nSCVMM Port: $port`nSCVMM Administrator Username: $username`n"
        if (ConfirmationPrompt -msg "Confirm SCVMM Server details?") {
            # Enquote username and password with double quotes,
            # so that special characters are not interpreted by PowerShell.
            $username = '"{0}"' -f $username.Replace('"', '""')
            $password = '"{0}"' -f $password.Replace('"', '""')

            $scvmmDetails[$scFqdnKey] = $fqdn
            $scvmmDetails[$scPortKey] = $port
            $scvmmDetails[$scUsernameKey] = $username
            $scvmmDetails[$scPasswordKey] = $password
            break
        }
    }
}

if ((Get-Host).Name -match "ISE") {
    fail "The script is not supported in PowerShell ISE window, please run it in a regular PowerShell window"
}

$supportMsg = "`nPlease refer to the Troubleshooting guide https://aka.ms/arcscvmmtsg for assistance. If the issue persists, kindly create a support ticket for Azure Arc enabled SCVMM from Azure portal or reach out to arc-vmm-feedback@microsoft.com."
$deployKVATimeoutMsg = "`nPlease refer to the Troubleshooting guide https://aka.ms/arcscvmmtsg for assistance. If the issue persists, kindly create a support ticket for Azure Arc enabled SCVMM from Azure portal or reach out to arc-vmm-feedback@microsoft.com.`nIn case of DeployKvaTimeoutError please run the following steps to collect the logs to send it to arc-vmm-feedback@microsoft.com `n`t`"az arcappliance logs scvmm [Appliance_VM_IP]`"`nwhere Appliance_VM_IP is the IP of the Appliance VM Created in SCVMM"

logH1 "Step 1/5: Setting up the current workstation"

$privateLinkMsg = "Resource bridge deployment is currently not supported over a private network by using Azure private link.`nPress Enter to confirm that the resource bridge deployment is not attempted over an Azure private link and proceed"

if (!(enterToContinue -msg $privateLinkMsg)){
    exit 0
}

if (!$UseProxy -and (confirmationPrompt -msg "`nIs the current workstation behind a proxy?")) {
    $UseProxy = $true
}

Write-Host "Setting the TLS Protocol for the current session to TLS 1.3 if supported, else TLS 1.2."
# Ensure TLS 1.2 is accepted. Older PowerShell builds (sometimes) complain about the enum "Tls12" so we use the underlying value
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
# Ensure TLS 1.3 is accepted, if this .NET supports it (older versions don't)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 12288 } catch {}

$proxyCA = ""

if ($UseProxy) {
    logH2 "Provide proxy details"
    $proxyURL = Read-Host "Please Enter Proxy URL, Ex) http://[URL]:[PORT] (press enter to skip if you don't use HTTP proxy)"
    if ($proxyURL.StartsWith("http") -ne $true) {
        $proxyURL = "http://$proxyURL"
    }

    $noProxy = Read-Host "No Proxy (comma separated)"

    $env:http_proxy = $proxyURL
    $env:HTTP_PROXY = $proxyURL
    $env:https_proxy = $proxyURL
    $env:HTTPS_PROXY = $proxyURL
    $env:no_proxy = $noProxy
    $env:NO_PROXY = $noProxy

    $proxyCA = Read-Host "Proxy CA cert path (Press enter to skip)"
    if ($proxyCA -ne "") {
        $proxyCA = Resolve-Path -Path $proxyCA
    }

    $credential = $null
    $proxyAddr = $proxyURL

    if ($proxyURL.Contains("@")) {
        $x = $proxyURL.Split("//")
        $proto = $x[0]
        $x = $x[2].Split("@")
        $userPass = $x[0]
        $proxyAddr = $proto + "//" + $x[1]
        $x = $userPass.Split(":")
        $proxyUsername = $x[0]
        $proxyPassword = $x[1]
        $password = ConvertTo-SecureString -String $proxyPassword -AsPlainText -Force
        $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $proxyUsername, $password
    }

    [system.net.webrequest]::defaultwebproxy = new-object system.net.webproxy($proxyAddr)
    [system.net.webrequest]::defaultwebproxy.credentials = $credential
    [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
}

# Start Region: Install az cli

$ProgressPreference = 'SilentlyContinue'

function getLatestAzVersion() {
    # https://github.com/Azure/azure-cli/blob/4e21baa4ff126ada2bc232dff74d6027fd1323be/src/azure-cli-core/azure/cli/core/util.py#L295
    $gitUrl = "https://raw.githubusercontent.com/Azure/azure-cli/main/src/azure-cli/setup.py"
    try {
        $response = Invoke-WebRequest -Uri $gitUrl -TimeoutSec 30
    }
    catch {
        logWarn "Failed to get the latest version from '$gitUrl': $($_.Exception.Message)"
        return $null
    }
    if ($response.StatusCode -ne 200) {
        logWarn "Failed to fetch the latest version from '$gitUrl' with status code '$($response.StatusCode)' and reason '$($response.StatusDescription)'"
        return $null
    }
    $content = $response.Content
    foreach ($line in $content -split "`n") {
        if ($line.StartsWith('VERSION')) {
            $match = [System.Text.RegularExpressions.Regex]::Match($line, 'VERSION = "(.*)"')
            if ($match.Success) {
                return $match.Groups[1].Value
            }
        }
    }
    logWarn "Failed to extract the latest version from the content of '$gitUrl'"
    return $null
}

function shouldInstallAzCli() {
    # This function returns a boolean value, but any undirected / uncaptured stdout
    # inside the function might be interpreted as true value by the caller.
    # We can redirect using *>> to avoid this.
    logH2 "Validating and installing 64-bit azure-cli"
    $azCmd = (Get-Command az -ErrorAction SilentlyContinue)
    if ($null -eq $azCmd) {
        logText "Azure CLI is not installed. Installing..."
        return $true
    }

    $currentAzVersion = az version --query '\"azure-cli\"' -o tsv 2>> $logFile
    logText "Azure CLI version $currentAzVersion found in PATH at location: '$($azCmd.Source)'"
    $azVersion = az --version *>&1;
    $azVersionLines = $azVersion -split "`n"
    # https://github.com/microsoft/knack/blob/e0c14114aea5e4416c70a77623e403773aba73a8/knack/cli.py#L126
    $pyLoc = $azVersionLines | Where-Object { $_ -match "^Python location" }
    if ($null -eq $pyLoc) {
        logWarn "Warning: Python location could not be found from the output of az --version:`n$($azVersionLines -join "`n"))"
        return $true
    }
    logText $pyLoc
    $pythonExe = $pyLoc -replace "^Python location '(.+?)'$", '$1'
    try {
        logText "Determining the bitness of Python at '$pythonExe'"
        $arch = & $pythonExe -c "import struct; print(struct.calcsize('P') * 8)";
        if ($arch -lt 64) {
            logText "Azure CLI is $arch-bit. Installing 64-bit version..."
            return $true
        }
    }
    catch {
        logText "Warning: Python version could not be determined from the output of az --version:`n$($azVersionLines -join "`n"))"
        return $true
    }

    logH2 "$arch-bit Azure CLI is already installed. Checking for updates..."
    $latestAzVersion = getLatestAzVersion
    if ($latestAzVersion -and ($latestAzVersion -ne $currentAzVersion)) {
        logText "A newer version of Azure CLI ($latestAzVersion) is available, installing it..."
        return $true
    }
    logText "Azure CLI is up to date."
    return $false
}

function installAzCli64Bit() {
    $azCliMsi = "https://aka.ms/installazurecliwindowsx64"
    $azCliMsiPath = Join-Path $PSScriptRoot "AzureCLI.msi"
    $msiInstallLogPath = Join-Path $env:Temp "azInstall.log"
    logText "Downloading Azure CLI 64-bit MSI from $azCliMsi to $azCliMsiPath"
    Invoke-WebRequest -Uri $azCliMsi -OutFile $azCliMsiPath
    logText "Azure CLI MSI installation log will be written to $msiInstallLogPath"
    logH2 "Installing Azure CLI. This might take a while..."
    $p = Start-Process msiexec.exe -Wait -Passthru -ArgumentList "/i `"$azCliMsiPath`" /quiet /qn /norestart /log `"$msiInstallLogPath`""
    $exitCode = $p.ExitCode
    if ($exitCode -ne 0) {
        throw "Azure CLI installation failed with exit code $exitCode. See $msiInstallLogPath for additional details."
    }
    $azCmdDir = Join-Path $env:ProgramFiles "Microsoft SDKs\Azure\CLI2\wbin"
    [System.Environment]::SetEnvironmentVariable('PATH', $azCmdDir + ';' + $Env:PATH)
    logText "Azure CLI has been installed."
}

if (shouldInstallAzCli) {
    installAzCli64Bit
}

$ProgressPreference = 'Continue'

logText "Enabling long path support for python..."
Start-Process powershell.exe -verb runas -ArgumentList "Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -Value 1" -Wait

# End Region: Install az cli

function CheckResourceState($resourceID) {
    for ($i=1; $i -ne 6; $i++) {
        $resourceState = (az resource show --ids "$resourceID" --query 'properties.provisioningState' -o tsv 2>> $logFile)
        if ($resourceState -eq "Succeeded") {
            return $resourceState
        }
        Start-Sleep -Seconds 30
        logText "Resource `"$resourceID`" is not ready yet, retrying... ($i/5)"
    }
    return $resourceState
}

try {
    if ($proxyCA -ne "") {
        $env:REQUESTS_CA_BUNDLE = $proxyCA
    }

    logH2 "Installing az cli extensions for Arc"
    az extension add --upgrade --allow-preview false --name arcappliance
    az extension add --upgrade --allow-preview false --name k8s-extension
    az extension add --upgrade --allow-preview false --name customlocation
    az extension add --upgrade --allow-preview false --name scvmm

    logH2 "az --version"
    az --version
    az --version >> $logFile

    logH2 "Logging into azure"

    $azLoginMsg = "Please login to Azure CLI.`n" +
    "`t* If you're running the script for the first time, select yes.`n" +
    "`t* If you've recently logged in to az while running the script, you can select no.`n" +
    "Confirm login to azure cli?"
    if (confirmationPrompt -msg $azLoginMsg) {
        az login --use-device-code -o none
    }

    az account set -s $applianceSubscriptionId
    if ($LASTEXITCODE) {
        $Error[0] | Out-String >> $logFile
        throw "The default subscription for the az cli context could not be set."
    }

    logH1 "Step 1/5: Workstation was set up successfully"

    createRG "$applianceSubscriptionId" "$applianceResourceGroupName"

    logH1 "Step 2/5: Creating the Arc resource bridge"

    $applianceObj = (az arcappliance show --debug --subscription $applianceSubscriptionId --resource-group $applianceResourceGroupName --name $applianceName 2>> $logFile | ConvertFrom-Json)
    $applianceStatus = ""
    if ($applianceObj) {
        $applianceStatus = $applianceObj.status
    }

    $invokeApplianceRun = $true
    if ($applianceStatus -eq "Running") {
        $invokeApplianceRun = $false
        if ($Force) {
            $invokeApplianceRun = ConfirmationPrompt -msg "The resource bridge is already running. Running with --force flag will delete the existing resource bridge and create a new one. Do you want to continue?"
        }
    } else {
        $Force = evaluateForceFlag $Force $applianceStatus
        if (!$Force) {
            $deleteAppl = $false
            if ($applianceStatus -eq "WaitingForHeartbeat") {
                $deleteAppl = $true
            } elseif (![string]::IsNullOrEmpty($applianceStatus)) {
                $deleteAppl = (confirmationPrompt -msg "An existing Arc resource bridge is already present in Azure (status: $applianceStatus). Do you want to delete it?")
            }
            if ($deleteAppl) {
                logText "Deleting the existing Arc Appliance resource from azure..."
                az resource delete --debug --ids $applianceObj.id 2>> $logFile
            }
        }
    }
    if ($invokeApplianceRun) {
        logH2 "Provide the details of the VMM Server on which the Azure Arc resource bridge VM will be deployed. These credentials will be used by the Azure Arc resource bridge to update and scale itself."
        fetchScvmmDetailsInto $scvmmDetails
        $forceParam = @()
        if ($Force) {
            $forceParam = @("--force")
        }
        az arcappliance run scvmm --tags "" @forceParam --subscription $applianceSubscriptionId --resource-group $applianceResourceGroupName --name $applianceName --location $location --address $scvmmDetails[$scFqdnKey] --port $scvmmDetails[$scPortKey] --username $scvmmDetails[$scUsernameKey] --password $scvmmDetails[$scPasswordKey]
    } else {
        logText "The Arc resource bridge is already running. Skipping the creation of resource bridge."
    }

    $applianceObj = (az arcappliance show --debug --subscription $applianceSubscriptionId --resource-group $applianceResourceGroupName --name $applianceName 2>> $logFile | ConvertFrom-Json)
    $applianceId = ""
    $applianceStatus = ""
    if ($applianceObj) {
        $applianceId = $applianceObj.id
        $applianceStatus = $applianceObj.status
    }
    if (!$applianceId) {
        # Appliance ARM resource is now created before the appliance VM.
        # So, this code path should not be hit.
        throw "Appliance creation has failed. $supportMsg"
    }
    if ($applianceStatus -eq "WaitingForHeartbeat") {
        throw "Appliance VM creation failed. $supportMsg"
    }
    logText "Waiting for the appliance to be ready..."
    for ($i = 1; $i -le 5; $i++) {
        Start-Sleep -Seconds 60
    $applianceStatus = (az resource show --debug --ids "$applianceId" --query 'properties.status' -o tsv 2>> $logFile)
        if ($applianceStatus -eq "Running") {
            break
        }
        logText "Appliance is not ready yet, retrying... ($i/5)"
    }
    if ($applianceStatus -ne "Running") {
        showSupportMsg($deployKVATimeoutMsg)
        throw "Appliance is not in running state. Current state: $applianceStatus. $supportMsg"
    }

    logH1 "Step 2/5: Arc resource bridge is up and running"
    logH1 "Step 3/5: Installing cluster extension"

    az k8s-extension create --debug --subscription $applianceSubscriptionId --resource-group $applianceResourceGroupName --name azure-vmmoperator --extension-type 'Microsoft.scvmm' --scope cluster --cluster-type appliances --cluster-name $applianceName --config Microsoft.CustomLocation.ServiceAccount=azure-vmmoperator 2>> $logFile
    $clusterExtensionId = (az k8s-extension show --subscription $applianceSubscriptionId --resource-group $applianceResourceGroupName --name azure-vmmoperator --cluster-type appliances --cluster-name $applianceName --query id -o tsv 2>> $logFile)

    if (!$clusterExtensionId) {
        logH2 "Cluster Extension Installation failed... Please rerun the script to continue the deployment"
        throw "Cluster extension installation failed."
    }
    $clusterExtensionState = CheckResourceState($clusterExtensionId)
    if ($clusterExtensionState -ne "Succeeded") {
        showSupportMsg($supportMsg)
        throw "Provisioning State of cluster extension is not succeeded. Current state: $clusterExtensionState. $supportMsg"
    }

    logH1 "Step 3/5: Cluster extension installed successfully"
    logH1 "Step 4/5: Creating custom location"

    createRG "$customLocationSubscriptionId" "$customLocationResourceGroupName"

    $customLocationNamespace = ("$customLocationName".ToLower() -replace '[^a-z0-9-]', '')
    az customlocation create --debug --tags "" --subscription $customLocationSubscriptionId --resource-group $customLocationResourceGroupName --name $customLocationName --location $location --namespace $customLocationNamespace --host-resource-id $applianceId --cluster-extension-ids $clusterExtensionId 2>> $logFile
    $customLocationId = (az customlocation show --subscription $customLocationSubscriptionId --resource-group $customLocationResourceGroupName --name $customLocationName --query id -o tsv 2>> $logFile)

    if (!$customLocationId) {
        logH2 "Custom location creation failed... Please rerun the same script to continue the deployment"
        throw "Custom location creation failed."
    }
    $customLocationState = CheckResourceState($customLocationId)
    if ($customLocationState -ne "Succeeded") {
        showSupportMsg($supportMsg)
        throw "Provisioning State of custom location is not succeeded. Current state: $customLocationState. $supportMsg"
    }

    logH1 "Step 4/5: Custom location created successfully"
    logH1 "Step 5/5: Connecting to VMMServer"

    createRG "$vmmserverSubscriptionId" "$vmmserverResourceGroupName"

    logH2 "Provide the details of the VMM server that will be connected to Azure using the deployed Azure Arc resource bridge."
    logText "`t* These credentials will be used when you perform SCVMM operations through Azure."
    logText "`t* You can connect the same VMM server on which the Azure Arc resource bridge VM is deployed by providing the same credentials as in Step 2."

    for($i=1; $i -le 3; $i++) {
        logText "`nAttempt to Connect to VMM Server... ($i/3)"
        if(Test-Path -Path $vmmConnectLogFile) {
            Clear-Content $vmmConnectLogFile
        }
        $scvmmDetails = @{}
        fetchScvmmDetailsInto $scvmmDetails $true
        az scvmm vmmserver connect --debug --tags "" --subscription $vmmserverSubscriptionId --resource-group $vmmserverResourceGroupName --name $vmmserverName --location $location --custom-location $customLocationId --fqdn $scvmmDetails[$scFqdnKey] --port $scvmmDetails[$scPortKey] --username $scvmmDetails[$scUsernameKey] --password $scvmmDetails[$scPasswordKey] 2>> $vmmConnectLogFile
        if($LASTEXITCODE -ne 0) {
			if(Select-String -Path $vmmConnectLogFile -Pattern 'RemoteHostUnreachable') {
				logH3 "`t Not able to connect to FQDN or IP Provided. Please retry with correct VMM FQDN or IP and Port..."
				continue
			}
			if(Select-String -Path $vmmConnectLogFile -Pattern 'AuthorizationFailed') {
				logH3 "`t Either User does not have the access or Credentials provided are incorrect. Please try again....."
				continue
			}
		}
		else {
			break
		}
    }

    $vmmserverId = (az scvmm vmmserver show --subscription $vmmserverSubscriptionId --resource-group $vmmserverResourceGroupName --name $vmmserverName --query id -o tsv 2>> $logFile)
    if (!$vmmserverId) {
        logH2 "VMM Server connect failed... Please run the following commands from any az cli to complete the onboarding or rerun the same script"
		VMMConnectInstruction
        throw "Connect VMMServer failed."
    }
    $vmmserverState = CheckResourceState($vmmserverId)
    if ($vmmserverState -ne "Succeeded") {
        showSupportMsg($supportMsg)
        throw "Provisioning State of VMMServer is not succeeded. Current state: $vmmserverState. $supportMsg"
    }

    logH1 "Step 5/5: VMMServer was connected successfully"
    logH1 "Your SCVMM has been successfully onboarded to Azure Arc!"
    logText "To continue onboarding and to complete Arc enabling your SCVMM resources, view your VMMServer resource in Azure portal.`nhttps://portal.azure.com/#resource${vmmserverId}/overview"
}
catch {
    $err = $_.Exception | Out-String
    fail $err
}
