#Requires -RunAsAdministrator
# -----------------------------------------------------------------------------------------
# Windows Update Deep Disable/Enable Script for Windows 11 Enterprise (Educational Use)
# Version: 3.3
# Author: [Your Name or Company]
#
# DESCRIPTION:
# This script attempts to heavily disable Windows Update by:
# - Disabling update-related services by directly editing their registry Start values.
# - Using SCHTASKS.exe to disable scheduled tasks related to Windows Update.
# - Applying registry policies to block update access and connections.
# - Adding hosts file entries to block known Microsoft Update endpoints.
# - Adding outbound firewall rules to block known Windows Update IP addresses.
#
# When re-enabled (with the correct key), the script attempts to restore:
# - Services to their original startup type (Manual by default).
# - Scheduled tasks to Enabled state.
# - Remove registry policies, hosts entries, and firewall rules.
#
# Nothing is permanently deleted.
#
# USAGE:
#   To Disable (and set key):
#     .\DisableEnableWindowsUpdates.ps1 -Disable -SetKey "YourCustomKeyHere"
#
#   To Enable (and restore):
#     .\DisableEnableWindowsUpdates.ps1 -Enable -Key "YourCustomKeyHere"
#
# WARNING:
# This is for educational demonstration. It may disrupt system functionality. Use at your own risk.
#
# -----------------------------------------------------------------------------------------

Param(
    [Parameter(Mandatory=$false)]
    [switch]$Disable,

    [Parameter(Mandatory=$false)]
    [switch]$Enable,

    [Parameter(Mandatory=$false)]
    [string]$SetKey,

    [Parameter(Mandatory=$false)]
    [string]$Key
)

Set-StrictMode -Version Latest

# -----------------------------------------------------------------------------------------
# GLOBAL VARIABLES & CONFIGURATION
# -----------------------------------------------------------------------------------------
$RegPath = "HKLM:\Software\CustomWUControl"
$KeyValueName = "ProtectedKeyHash"
$Sha512 = [System.Security.Cryptography.SHA512]::Create()

$ServicesToDisable = @(
    "wuauserv",
    "WaaSMedicSvc",
    "bits",
    "dosvc",
    "UsoSvc",
    "TokenBroker"
)

$ServiceRestoreStartType = @{
    "wuauserv" = 3
    "WaaSMedicSvc" = 3
    "bits" = 3
    "dosvc" = 3
    "UsoSvc" = 3
    "TokenBroker" = 3
}

$ScheduledTasksToDisable = @(
    "\Microsoft\Windows\WindowsUpdate\Automatic App Update",
    "\Microsoft\Windows\WindowsUpdate\Scheduled Start",
    "\Microsoft\Windows\WindowsUpdate\AUScheduledInstall",
    "\Microsoft\Windows\UpdateOrchestrator\Backup Scan",
    "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
    "\Microsoft\Windows\UpdateOrchestrator\Policy Install",
    "\Microsoft\Windows\UpdateOrchestrator\USO_Broker_Display"
)

$RegistrySettings = @(
    @{ Key="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoUpdate"; Value=1; Type="DWord" },
    @{ Key="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="AUOptions"; Value=1; Type="DWord" },
    @{ Key="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="DisableOSUpgrade"; Value=1; Type="DWord" },
    @{ Key="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="DoNotConnectToWindowsUpdateInternetLocations"; Value=1; Type="DWord" },
    @{ Key="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="DisableWindowsUpdateAccess"; Value=1; Type="DWord" }
)

$RegistryKeysToRemove = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DisableOSUpgrade",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DoNotConnectToWindowsUpdateInternetLocations",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DisableWindowsUpdateAccess"
)

$HostsFile = "$env:windir\system32\drivers\etc\hosts"
$UpdateHosts = @(
    "windowsupdate.microsoft.com",
    "update.microsoft.com",
    "download.windowsupdate.com",
    "update.windows.com"
)
$HostsBeginMarker = "# BEGIN_CUSTOM_WU_BLOCK"
$HostsEndMarker = "# END_CUSTOM_WU_BLOCK"

$FirewallIPsToBlock = "13.107.4.50"
$FirewallRulePrefix = "BlockWindowsUpdate_"

# -----------------------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------------------

function Write-Info($Message) {
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-WarningMessage($Message) {
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-ErrorMessage($Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Check-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not ($principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) {
        Write-ErrorMessage "This script must be run as Administrator!"
        exit 1
    }
}

function Hash-Key($InputKey) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($InputKey)
    $hash  = $Sha512.ComputeHash($bytes)
    return ($hash | ForEach-Object ToString x2) -join ""
}

function Store-KeyHash($HashedKey) {
    if (-not (Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $RegPath -Name $KeyValueName -Type String -Value $HashedKey
}

function Retrieve-StoredKeyHash {
    if (Test-Path $RegPath) {
        try {
            return (Get-ItemProperty -Path $RegPath -Name $KeyValueName -ErrorAction Stop).$KeyValueName
        } catch {
            return $null
        }
    } else {
        return $null
    }
}

function Verify-Key($ProvidedKey) {
    $storedHash = Retrieve-StoredKeyHash
    if ([string]::IsNullOrEmpty($storedHash)) {
        Write-ErrorMessage "No stored key found. Cannot verify provided key."
        return $false
    }

    $providedHash = Hash-Key($ProvidedKey)
    if ($providedHash -eq $storedHash) {
        return $true
    } else {
        Write-ErrorMessage "Provided key does not match the stored key."
        return $false
    }
}

function Disable-ServiceRegistry($ServiceName) {
    Write-Info "Attempting to stop and disable service via registry: $($ServiceName)"
    Try {
        Stop-Service $ServiceName -ErrorAction SilentlyContinue
    } catch {
        Write-WarningMessage "Could not stop service $($ServiceName): $($_.Exception.Message)"
    }

    $serviceKey = "HKLM:\System\CurrentControlSet\Services\$ServiceName"
    if (Test-Path $serviceKey) {
        try {
            Set-ItemProperty -Path $serviceKey -Name Start -Type DWord -Value 4
            Write-Info "Set $($ServiceName) to disabled via registry."
        } catch {
            Write-WarningMessage "Failed to set $($ServiceName) start type: $($_.Exception.Message)"
        }
    } else {
        Write-WarningMessage "Service registry key not found for $($ServiceName)"
    }
}

function Enable-ServiceRegistry($ServiceName, $StartType) {
    Write-Info "Restoring service $($ServiceName) to start type $($StartType)"
    $serviceKey = "HKLM:\System\CurrentControlSet\Services\$ServiceName"
    if (Test-Path $serviceKey) {
        try {
            Set-ItemProperty -Path $serviceKey -Name Start -Type DWord -Value $StartType
            Write-Info "Set $($ServiceName) start type to $($StartType)."
        } catch {
            Write-WarningMessage "Failed to restore $($ServiceName) start type: $($_.Exception.Message)"
        }
    }

    if ($StartType -eq 3) {
        Try {
            Start-Service $ServiceName -ErrorAction SilentlyContinue
        } catch {
            Write-WarningMessage "Failed to start $($ServiceName) after restoring: $($_.Exception.Message)"
        }
    }
}

function Disable-ScheduledTask-CLI($TaskPath) {
    Write-Info "Disabling scheduled task: $($TaskPath)"
    $cmd = "SCHTASKS /CHANGE /TN `"$TaskPath`" /DISABLE"
    cmd.exe /c $cmd | Out-Null
}

function Enable-ScheduledTask-CLI($TaskPath) {
    Write-Info "Enabling scheduled task: $($TaskPath)"
    $cmd = "SCHTASKS /CHANGE /TN `"$TaskPath`" /ENABLE"
    cmd.exe /c $cmd | Out-Null
}

function Apply-RegistrySettings {
    Write-Info "Applying registry settings to block Windows Updates"
    foreach ($reg in $RegistrySettings) {
        $key = $reg.Key
        $name = $reg.Name
        $value = $reg.Value
        $type = $reg.Type
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
        }
        Set-ItemProperty -Path $key -Name $name -Type $type -Value $value
        Write-Info "Set $($name) to $($value) at $($key)"
    }
}

function Remove-RegistrySettings {
    Write-Info "Removing registry settings"
    foreach ($fullKeyName in $RegistryKeysToRemove) {
        $splitPath = $fullKeyName.Split("\")
        $valueName = $splitPath[-1]
        $keyPath = ($splitPath[0..($splitPath.Count - 2)]) -join "\"
        
        if (Test-Path $keyPath) {
            try {
                Remove-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue
                Write-Info "Removed $($valueName) from $($keyPath)"
            } catch {
                Write-WarningMessage "Failed to remove $($valueName) from $($keyPath): $($_.Exception.Message)"
            }
        }
    }
}

function Add-HostsEntries {
    Write-Info "Adding hosts file entries to block Windows Update endpoints"
    if (Test-Path $HostsFile) {
        Remove-HostsEntries
        $lines = Get-Content $HostsFile
        $blockLines = @($HostsBeginMarker)
        foreach ($updHost in $UpdateHosts) {
            $blockLines += "127.0.0.1 $updHost"
        }
        $blockLines += $HostsEndMarker

        $lines += $blockLines
        $lines | Out-File $HostsFile -Encoding ASCII
        Write-Info "Hosts file updated."
    } else {
        Write-WarningMessage "Hosts file not found at $HostsFile"
    }
}

function Remove-HostsEntries {
    Write-Info "Removing hosts file entries added by this script"
    if (Test-Path $HostsFile) {
        $lines = Get-Content $HostsFile
        $startIndex = $lines.IndexOf($HostsBeginMarker)
        $endIndex = $lines.IndexOf($HostsEndMarker)

        if ($startIndex -ge 0 -and $endIndex -ge 0 -and $endIndex -ge $startIndex) {
            # Safely determine before and after
            $before = if ($startIndex -gt 0) {
                $lines[0..($startIndex - 1)]
            } else {
                @()
            }

            $after = if ($endIndex -lt ($lines.Count - 1)) {
                $lines[($endIndex + 1)..($lines.Count - 1)]
            } else {
                @()
            }

            $newContent = $before + $after
            $newContent | Out-File $HostsFile -Encoding ASCII
            Write-Info "Hosts file entries removed."
        } else {
            Write-Info "No custom host entries found."
        }
    }
}


function Add-FirewallRules {
    Write-Info "Adding firewall rules to block Windows Update endpoints"
    foreach ($ip in $FirewallIPsToBlock) {
        $ruleName = "$FirewallRulePrefix$ip"
        Write-Info "Blocking outbound traffic to $ip"
        netsh advfirewall firewall add rule name=$ruleName dir=out action=block remoteip=$ip enable=yes | Out-Null
    }
}

function Remove-FirewallRules {
    Write-Info "Removing firewall rules added by this script"
    $allRules = (netsh advfirewall firewall show rule name=all) -split "`r?`n"
    foreach ($line in $allRules) {
        if ($line -like "Rule Name:*") {
            $ruleName = $line -replace "Rule Name:\s*", ""
            if ($ruleName -like "$FirewallRulePrefix*") {
                netsh advfirewall firewall delete rule name="$ruleName" | Out-Null
                Write-Info "Removed firewall rule: $($ruleName)"
            }
        }
    }
}

function Disable-WindowsUpdates {
    Write-Info "Disabling Windows Updates more thoroughly (using registry and SCHTASKS)..."

    # Disable services via registry
    foreach ($svc in $ServicesToDisable) {
        Disable-ServiceRegistry $svc
    }

    # Disable scheduled tasks
    foreach ($task in $ScheduledTasksToDisable) {
        Disable-ScheduledTask-CLI $task
    }

    # Apply registry settings
    Apply-RegistrySettings

    # Add hosts entries
    Add-HostsEntries

    # Add firewall rules
    Add-FirewallRules

    Write-Info "Windows Updates should now be heavily disabled but reversible."
}

function Enable-WindowsUpdates {
    Write-Info "Restoring Windows Update..."

    # Restore services to their original start type
    foreach ($svc in $ServicesToDisable) {
        $startType = if ($ServiceRestoreStartType.ContainsKey($svc)) {
            $ServiceRestoreStartType[$svc]
        } else {
            3
        }
        Enable-ServiceRegistry $svc $startType
    }

    # Enable scheduled tasks
    foreach ($task in $ScheduledTasksToDisable) {
        Enable-ScheduledTask-CLI $task
    }

    # Remove registry settings
    Remove-RegistrySettings

    # Remove hosts entries
    Remove-HostsEntries

    # Remove firewall rules
    Remove-FirewallRules

    Write-Info "Windows Updates have been restored to normal functionality."
}

function Show-CurrentStatus {
    Write-Info "Current Windows Update Components Status:"
    # Services
    Write-Host "Services Status:" -ForegroundColor Cyan
    foreach ($svc in $ServicesToDisable) {
        try {
            $serviceObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($serviceObj) {
                $state = $serviceObj.Status
                $startupType = (Get-CimInstance Win32_Service -Filter "Name='$svc'").StartMode
                Write-Host "  - $($svc): State=$($state), StartupType=$($startupType)"
            } else {
                Write-Host "  - $($svc): Not Found"
            }
        } catch {
            Write-Host "  - $($svc): Error checking status"
        }
    }

    # Tasks
    Write-Host "`nScheduled Tasks Status:" -ForegroundColor Cyan
    foreach ($task in $ScheduledTasksToDisable) {
        try {
            $taskName = (Split-Path $task -Leaf)
            $taskFolder = (Split-Path $task)
            $tObj = Get-ScheduledTask -TaskPath $taskFolder -TaskName $taskName -ErrorAction SilentlyContinue
            if ($tObj) {
                Write-Host "  - $($task): Exists, Enabled=$($tObj.Enabled)"
            } else {
                Write-Host "  - $($task): Not Found"
            }
        } catch {
            Write-Host "  - $($task): Error checking status"
        }
    }

    # Registry
    Write-Host "`nRegistry Settings:" -ForegroundColor Cyan
    foreach ($reg in $RegistrySettings) {
        $key = $reg.Key
        $name = $reg.Name
        if (Test-Path $key) {
            try {
                $val = (Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue).$name
                if ($null -ne $val) {
                    Write-Host "  - $($name) at $($key) = $($val)"
                } else {
                    Write-Host "  - $($name) at $($key) is not set"
                }
            } catch {
                Write-Host "  - $($name) at $($key): Error retrieving value"
            }
        } else {
            Write-Host "  - $($name) at $($key): Key not present"
        }
    }

    # Hosts file
    Write-Host "`nHosts File Entries:" -ForegroundColor Cyan
    if (Test-Path $HostsFile) {
        $lines = Get-Content $HostsFile
        $startIndex = $lines.IndexOf($HostsBeginMarker)
        $endIndex = $lines.IndexOf($HostsEndMarker)
        if ($startIndex -ge 0 -and $endIndex -ge 0) {
            Write-Host "  - Custom Windows Update blocking entries are present in hosts file."
        } else {
            Write-Host "  - No custom blocking entries found in hosts file."
        }
    } else {
        Write-Host "  - Hosts file not found."
    }

    # Firewall
    Write-Host "`nFirewall Rules:" -ForegroundColor Cyan
    $rules = netsh advfirewall firewall show rule name=all | Select-String "$FirewallRulePrefix"
    if ($rules) {
        Write-Host "  - One or more custom firewall rules blocking Windows Update endpoints are present."
    } else {
        Write-Host "  - No custom firewall rules found."
    }

    Write-Host "`n"
}

Check-Admin

if ($Disable -and $Enable) {
    Write-ErrorMessage "You cannot specify both -Disable and -Enable at the same time."
    exit 1
}

if (-not $Disable -and -not $Enable) {
    Write-Info "No action specified. Showing current status of Windows Update components."
    Show-CurrentStatus
    exit 0
}

if ($Disable) {
    if ([string]::IsNullOrEmpty($SetKey)) {
        Write-ErrorMessage "You must provide -SetKey when using -Disable to store a custom key."
        exit 1
    }

    Write-Info "Received request to deeply disable Windows Updates (registry & SCHTASKS)."
    $hashed = Hash-Key($SetKey)
    Store-KeyHash $hashed
    Disable-WindowsUpdates
    Write-Info "Windows Updates are now heavily disabled. Use -Enable -Key \"YourKey\" to restore."
    Show-CurrentStatus
    exit 0
}

if ($Enable) {
    if ([string]::IsNullOrEmpty($Key)) {
        Write-ErrorMessage "You must provide the -Key parameter when using -Enable."
        exit 1
    }

    Write-Info "Received request to restore Windows Updates."
    if (Verify-Key($Key)) {
        Enable-WindowsUpdates
        Write-Info "Windows Updates have been restored."
        Show-CurrentStatus
    } else {
        Write-ErrorMessage "Key verification failed. Cannot enable Windows Updates."
        exit 1
    }
    exit 0
}
