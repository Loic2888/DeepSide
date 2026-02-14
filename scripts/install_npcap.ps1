# install_npcap.ps1 - Auto-installer for Npcap (required for packet capture)
# Run as Administrator

$npcapVersion = "1.79"
$npcapUrl = "https://npcap.com/dist/npcap-$npcapVersion.exe"
$installerPath = "$env:TEMP\npcap_installer.exe"

Write-Host "╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Npcap Auto-Installer v1.0        ║" -ForegroundColor Cyan  
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Cyan

# Check if already installed
$npcapService = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if ($npcapService) {
    Write-Host "✅ Npcap is already installed!" -ForegroundColor Green
    Write-Host "   Service Status: $($npcapService.Status)" -ForegroundColor Gray
    exit 0
}

# Check admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "❌ This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "   Right-click PowerShell → Run as Administrator" -ForegroundColor Yellow
    exit 1
}

# Download
Write-Host "📥 Downloading Npcap $npcapVersion..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $npcapUrl -OutFile $installerPath -UseBasicParsing
    Write-Host "   Downloaded to: $installerPath" -ForegroundColor Gray
} catch {
    Write-Host "❌ Download failed: $_" -ForegroundColor Red
    exit 1
}

# Install silently with WinPcap compatibility mode
Write-Host "🔧 Installing Npcap (silent mode)..." -ForegroundColor Cyan
try {
    Start-Process -FilePath $installerPath -ArgumentList "/S /winpcap_mode=yes" -Wait -Verb RunAs
    Write-Host "✅ Npcap installed successfully!" -ForegroundColor Green
} catch {
    Write-Host "❌ Installation failed: $_" -ForegroundColor Red
    exit 1
}

# Cleanup
Remove-Item $installerPath -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "🎉 Installation complete! DeepSide can now capture network traffic." -ForegroundColor Green
Write-Host "   Restart DeepSide to apply changes." -ForegroundColor Yellow
