# install-windows.ps1
# One-click installer for Windows (PowerShell):
#   1. Verifies Docker and Docker Compose are available.
#   2. Starts the warden-proxy and warden-api containers (docker compose up -d --build).
#   3. Waits for the proxy CA to be generated and extracts it from the container.
#   4. Installs the mitmproxy CA to the User's Root Certificate Store.
#   5. Configures system-wide HTTP/HTTPS proxy in Internet Settings.
#   6. Displays proxy environment variables for PowerShell and Command Prompt.
#
# To revert everything, run: scripts/uninstall-windows.ps1

$ErrorActionPreference = "Continue"

# Set output encoding to UTF-8 to support Unicode output on Windows PowerShell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# --- Brand Logo ---
function Show-Logo {
    Write-Host "" -ForegroundColor Magenta
    Write-Host "  ▄▀█ █ █ ▀█▀ █▀█    █   █   █▀▄▀█" -ForegroundColor Magenta
    Write-Host "  █▀█ █▄█  █  █▄█    █▄▄ █▄▄ █ ▀ █" -ForegroundColor Magenta
    Write-Host "            ◆ W A R D E N ◆" -ForegroundColor Blue
    Write-Host "        prompt-flow firewall for LLMs" -ForegroundColor DarkGray
    Write-Host ""
}
Show-Logo

# --- Step Helper ---
function Write-Step ($message) {
    Write-Host ">> $message" -ForegroundColor Magenta
}
function Write-Success ($message) {
    Write-Host "  [OK] $message" -ForegroundColor Green
}
function Write-WarningMsg ($message) {
    Write-Host "  [WARNING] $message" -ForegroundColor Yellow
}
function Write-Fail ($message) {
    Write-Host "  [FAIL] $message" -ForegroundColor Red
    Exit 1
}

# --- 1. Pre-requisite Checks ---
Write-Step "Checking Docker availability..."
if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
    Write-Fail "Docker is not installed or not in your PATH. Please install Docker Desktop for Windows and try again."
}
if (-not (Get-Command "docker-compose" -ErrorAction SilentlyContinue) -and -not (docker compose version -ErrorAction SilentlyContinue)) {
    Write-Fail "Docker Compose is not available. Please ensure docker-compose or the 'docker compose' plugin is installed."
}
Write-Success "Docker and Docker Compose are available."

# --- 2. Start Docker Containers ---
Write-Step "Starting LLM Warden services (docker compose up -d --build)..."
$ComposeCmd = "docker compose"
if (-not (docker compose version 2>$null)) {
    $ComposeCmd = "docker-compose"
}

Invoke-Expression "$ComposeCmd up -d --build"
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Failed to bring up services via Docker Compose."
}
Write-Success "Containers launched successfully."

# --- 3. Wait for CA Certificate ---
Write-Step "Waiting for proxy CA certificate to be generated (first startup trains the model and can take ~2-4 minutes)..."
$Tries = 0
$MaxTries = 120
$CaGenerated = $false

while ($Tries -lt $MaxTries) {
    $CheckFile = docker exec warden-proxy test -f /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem 2>$null
    if ($LASTEXITCODE -eq 0) {
        $CaGenerated = $true
        break
    }
    $Tries++
    if ($Tries % 5 -eq 0) {
        Write-Host "  still waiting... ($($Tries * 2)s)" -ForegroundColor Gray
    }
    Start-Sleep -Seconds 2
}

if (-not $CaGenerated) {
    Write-Fail "Timed out waiting for the proxy CA certificate to be generated. Check 'docker compose logs warden-proxy'."
}
Write-Success "Proxy CA certificate generated inside the container."

# --- 4. Copy CA Certificate to Host ---
Write-Step "Copying CA certificate to host..."
$CaDest = ".\mitmproxy-ca.pem"
docker cp warden-proxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem $CaDest 2>$null
if (-not (Test-Path $CaDest)) {
    Write-Fail "Failed to copy CA certificate from container."
}
Write-Success "CA certificate copied to $CaDest"

# --- 5. Trust the CA Certificate in Windows ---
Write-Step "Installing and trusting the CA certificate..."
try {
    Import-Certificate -FilePath $CaDest -CertStoreLocation Cert:\CurrentUser\Root -ErrorAction Stop
    Write-Success "CA Certificate trusted for Current User."
} catch {
    Write-WarningMsg "Failed to import certificate automatically. You can install it manually by double-clicking '$CaDest' and placing it in 'Trusted Root Certification Authorities'."
}

# --- 6. Configure Windows system-wide HTTP/HTTPS proxy ---
Write-Step "Configuring Windows system-wide proxy settings..."
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
try {
    Set-ItemProperty -Path $RegistryPath -Name ProxyServer -Value "127.0.0.1:8080" -ErrorAction Stop
    Set-ItemProperty -Path $RegistryPath -Name ProxyEnable -Value 1 -ErrorAction Stop
    Set-ItemProperty -Path $RegistryPath -Name ProxyOverride -Value "localhost;127.0.0.1;<local>" -ErrorAction Stop
    Write-Success "Windows System Proxy configured to 127.0.0.1:8080."
} catch {
    Write-WarningMsg "Failed to configure Windows System Proxy settings in registry."
}

# --- 7. Summary ---
$DashboardUrl = "http://localhost:8090"
Write-Host ""
Write-Host "====================================================================" -ForegroundColor Yellow
Write-Host "  All set! Sensitivity events will appear on the dashboard:" -ForegroundColor Green
Write-Host "      $DashboardUrl" -ForegroundColor Cyan
Write-Host ""
Write-Host "  To route CLIs/scripts in current terminals, export environment variables:"
Write-Host "  PowerShell:" -ForegroundColor White
Write-Host "      `$env:HTTP_PROXY=`"http://localhost:8080`"" -ForegroundColor Cyan
Write-Host "      `$env:HTTPS_PROXY=`"http://localhost:8080`"" -ForegroundColor Cyan
Write-Host "      `$env:ALL_PROXY=`"http://localhost:8080`"" -ForegroundColor Cyan
Write-Host "      `$env:NO_PROXY=`"localhost,127.0.0.1`"" -ForegroundColor Cyan
Write-Host "  Command Prompt (CMD):" -ForegroundColor White
Write-Host "      set HTTP_PROXY=http://localhost:8080" -ForegroundColor Cyan
Write-Host "      set HTTPS_PROXY=http://localhost:8080" -ForegroundColor Cyan
Write-Host "      set ALL_PROXY=http://localhost:8080" -ForegroundColor Cyan
Write-Host "      set NO_PROXY=localhost,127.0.0.1" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Note: Restart any running browsers (Chrome, Edge, Firefox) so they"
Write-Host "  pick up the newly installed root certificate trust store."
Write-Host ""
Write-Host "  To revert (turn off proxy and remove CA):"
Write-Host "      powershell -File scripts\uninstall-windows.ps1" -ForegroundColor Yellow
Write-Host "====================================================================" -ForegroundColor Yellow
Write-Host ""
