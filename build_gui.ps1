# UniCompute Desktop Studio Build & Packaging Script
# Target: Windows 10/11 Standalone Application (unicompute-studio.exe)

$ErrorActionPreference = "Stop"

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  UniCompute Desktop Studio: Build & Packaging Pipeline" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# 1. Environment Verification
Write-Host "[1/4] Verifying Go compiler toolchain..." -ForegroundColor Yellow
$goVer = go version
Write-Host "      Detected: $goVer" -ForegroundColor Green

# 2. Static Code Analysis (go vet)
Write-Host "[2/4] Running static analysis (go vet ./...)..." -ForegroundColor Yellow
go vet ./...
if ($LASTEXITCODE -ne 0) {
    Write-Error "Static analysis failed. Aborting build."
    exit 1
}
Write-Host "      Static analysis PASSED cleanly." -ForegroundColor Green

# 3. Test Suite Verification
Write-Host "[3/4] Running automated test suite (go test ./...)..." -ForegroundColor Yellow
go test ./...
if ($LASTEXITCODE -ne 0) {
    Write-Error "Test suite failed. Aborting build."
    exit 1
}
Write-Host "      All unit and integration test suites PASSED." -ForegroundColor Green

# 4. Compilation into unicompute-studio.exe
Write-Host "[4/4] Compiling standalone Windows executable: unicompute-studio.exe..." -ForegroundColor Yellow
$targetExe = "unicompute-studio.exe"

# Build with Windows optimizations
go build -ldflags="-s -w" -o $targetExe ./cmd/studio
if ($LASTEXITCODE -ne 0) {
    Write-Error "Compilation of $targetExe failed."
    exit 1
}

if (Test-Path $targetExe) {
    $item = Get-Item $targetExe
    $sizeMB = [math]::Round($item.Length / 1MB, 2)
    Write-Host "==================================================================" -ForegroundColor Green
    Write-Host "  SUCCESS: $targetExe built successfully!" -ForegroundColor Green
    Write-Host "  File: $($item.FullName)" -ForegroundColor Green
    Write-Host "  Size: $sizeMB MB" -ForegroundColor Green
    Write-Host "  Features: Native WebView2 framing, System Tray, JobObject, RS(32, 80)" -ForegroundColor Green
    Write-Host "==================================================================" -ForegroundColor Green
} else {
    Write-Error "Target executable not found after build."
    exit 1
}
