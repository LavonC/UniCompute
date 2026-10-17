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

# 4. Compilation of Executables
Write-Host "[4/6] Compiling Tier 3 Institutional workload: test_data/tier3_task.exe..." -ForegroundColor Yellow
go build -ldflags="-s -w" -o ./test_data/tier3_task.exe ./test_data/src/tier3
if ($LASTEXITCODE -ne 0) {
    Write-Error "Compilation of tier3_task.exe failed."
    exit 1
}
Write-Host "      SUCCESS: test_data/tier3_task.exe built" -ForegroundColor Green

Write-Host "[5/6] Compiling UniCompute cluster executables (coordinator, worker, cli)..." -ForegroundColor Yellow
go build -ldflags="-s -w" -o unicompute-coordinator.exe ./cmd/coordinator
go build -ldflags="-s -w" -o unicompute-worker.exe ./cmd/worker
go build -ldflags="-s -w" -o unicompute-cli.exe ./cmd/cli
Write-Host "      SUCCESS: coordinator, worker, and cli executables compiled" -ForegroundColor Green

Write-Host "[6/6] Compiling UniCompute Desktop Studio dual-binaries (console & windowed)..." -ForegroundColor Yellow
$targetExe = "unicompute-studio.exe"
go build -ldflags="-s -w" -o $targetExe ./cmd/studio
if ($LASTEXITCODE -ne 0) {
    Write-Error "Compilation of $targetExe failed."
    exit 1
}

$targetAppExe = "unicompute-studio-app.exe"
go build -ldflags="-s -w -H=windowsgui" -o $targetAppExe ./cmd/studio
if ($LASTEXITCODE -ne 0) {
    Write-Error "Compilation of $targetAppExe failed."
    exit 1
}

if ((Test-Path $targetExe) -and (Test-Path $targetAppExe)) {
    $item1 = Get-Item $targetExe
    $item2 = Get-Item $targetAppExe
    $size1 = [math]::Round($item1.Length / 1MB, 2)
    $size2 = [math]::Round($item2.Length / 1MB, 2)
    Write-Host "==================================================================" -ForegroundColor Green
    Write-Host "  BUILD COMPLETE: All UniCompute Binaries Ready" -ForegroundColor Green
    Write-Host "  1. Studio Windowed App: $targetAppExe ($size2 MB, -H=windowsgui)" -ForegroundColor Green
    Write-Host "  2. Studio Console App:  $targetExe ($size1 MB)" -ForegroundColor Green
    Write-Host "  3. Central Coordinator: unicompute-coordinator.exe" -ForegroundColor Green
    Write-Host "  4. Donor Node Worker:   unicompute-worker.exe" -ForegroundColor Green
    Write-Host "  5. Researcher CLI Tool: unicompute-cli.exe" -ForegroundColor Green
    Write-Host "  6. Tier 3 GPU Workload: test_data/tier3_task.exe" -ForegroundColor Green
    Write-Host "==================================================================" -ForegroundColor Green
} else {
    Write-Error "Target studio executables not found after build."
    exit 1
}

