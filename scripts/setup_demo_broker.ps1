# Windows PowerShell Helper to Run Mosquitto Demo Broker
# Usage:
#   .\scripts\setup_demo_broker.ps1 -Mode vulnerable
#   .\scripts\setup_demo_broker.ps1 -Mode hardened

param (
    [ValidateSet("vulnerable", "hardened")]
    [string]$Mode = "vulnerable"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Mosquitto Broker Runner for IoT Security Assessment     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Locate mosquitto
$mosquittoPath = Get-Command mosquitto -ErrorAction SilentlyContinue

if (-not $mosquittoPath) {
    # Check default install directories
    $commonPaths = @(
        "C:\Program Files\mosquitto\mosquitto.exe",
        "C:\Program Files (x86)\mosquitto\mosquitto.exe"
    )
    foreach ($p in $commonPaths) {
        if (Test-Path $p) {
            $mosquittoPath = $p
            break
        }
    }
}

if (-not $mosquittoPath) {
    Write-Host "[!] Mosquitto not found on your system." -ForegroundColor Yellow
    Write-Host "    Install via winget:" -ForegroundColor Yellow
    Write-Host "    winget install EclipseFoundation.Mosquitto" -ForegroundColor Green
    Write-Host "    Or in WSL: sudo apt-get install mosquitto" -ForegroundColor Green
    exit 1
}

$confFile = if ($Mode -eq "vulnerable") { "demo_configs\mosquitto_vulnerable.conf" } else { "demo_configs\mosquitto_hardened.conf" }

Write-Host "[*] Launching Mosquitto in $Mode mode using: $confFile" -ForegroundColor Green
Write-Host "    Press Ctrl+C to stop broker." -ForegroundColor Gray

& $mosquittoPath -c $confFile -v
