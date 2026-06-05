# uninstall-windows.ps1
# Uninstaller for Windows (PowerShell):
#   1. Disables the system-wide proxy settings in Internet Settings.
#   2. Removes the mitmproxy CA certificate from the Current User's root store.
#   3. Shuts down the docker stack (docker compose down).

$ErrorActionPreference = "Continue"

# Set output encoding to UTF-8 to support Unicode output on Windows PowerShell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# --- Step Helper ---
function Write-Step ($message) {
    Write-Host "▶ $message" -ForegroundColor Magenta
}
function Write-Success ($message) {
    Write-Host "  ✔ $message" -ForegroundColor Green
}
function Write-WarningMsg ($message) {
    Write-Host "  ! $message" -ForegroundColor Yellow
}

# --- 1. Disable System Proxy ---
Write-Step "Disabling Windows system-wide proxy..."
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
try {
    Set-ItemProperty -Path $RegistryPath -Name ProxyEnable -Value 0 -ErrorAction Stop
    Write-Success "Windows System Proxy disabled."
} catch {
    Write-WarningMsg "Failed to disable Windows System Proxy in registry."
}

# --- 2. Remove CA Certificate ---
Write-Step "Removing trusted mitmproxy CA certificate..."
try {
    $Certs = Get-ChildItem Cert:\CurrentUser\Root -ErrorAction Stop | Where-Object { $_.Subject -like "*mitmproxy*" }
    if ($Certs) {
        foreach ($Cert in $Certs) {
            Remove-Item -Path $Cert.PSPath -ErrorAction Stop
            Write-Success "Removed certificate: $($Cert.Subject)"
        }
    } else {
        Write-Success "No mitmproxy certificates found in root store."
    }
} catch {
    Write-WarningMsg "Failed to clean up certificate from store automatically. You can manually remove it via 'certmgr.msc'."
}

# --- 3. Shut down Docker Stack ---
Write-Step "Stopping docker services (docker compose down)..."
$ComposeCmd = "docker compose"
if (-not (docker compose version 2>$null)) {
    $ComposeCmd = "docker-compose"
}

Invoke-Expression "$ComposeCmd down"
if ($LASTEXITCODE -eq 0) {
    Write-Success "Docker containers stopped."
} else {
    Write-WarningMsg "Failed to stop Docker containers automatically. You may need to run '$ComposeCmd down' manually."
}

Write-Host "====================================================================" -ForegroundColor Yellow
Write-Host "  Uninstallation complete. System proxy disabled and CA cert removed." -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Yellow
