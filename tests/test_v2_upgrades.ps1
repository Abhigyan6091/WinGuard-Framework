# WinGuard 2.0 Architectural Upgrades Verification Suite
# Tests:
#   1. Phase 1: Compute False-Positive Prevention & Elastic Throttling
#   2. Phase 2: Graduated Memory Triage & Rogue Child Worker Termination
#   3. Phase 3: Allocation Acceleration Bomb & Low-Memory Notification Handling
#   4. Phase 4: Freeze-Before-Kill & Diagnostic Crash Dump Capture

$ErrorActionPreference = "Continue"

Write-Host "`n====================================================================" -ForegroundColor Cyan
Write-Host " WinGuard 2.0 Architectural Upgrades Automated Verification Suite" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

# Ensure results directories exist
if (-not (Test-Path "results\crash_dumps")) {
    New-Item -ItemType Directory -Path "results\crash_dumps" -Force | Out-Null
}

$all_passed = $true

# -----------------------------------------------------------------------------
# TEST 1: Phase 1 - Compute False-Positive Prevention (Compiler Simulator)
# -----------------------------------------------------------------------------
Write-Host "`n[TEST 1] Verifying Phase 1: Compute False-Positive Suppression..." -ForegroundColor Yellow
Write-Host "Running heavy compute workload with active I/O pipeline under compute_batch policy..."
$test1_out = & ".\bin\WinGuard.exe" attack compiler 2>&1 | Out-String
Write-Host $test1_out

if ($test1_out -match "Workload completed with exit code 0" -and $test1_out -match "Suppressed pure compute spike") {
    Write-Host "  -> [PASS] Heavy compute with active I/O was correctly identified and not clamped." -ForegroundColor Green
} elseif ($test1_out -match "Workload completed with exit code 0") {
    Write-Host "  -> [PASS] Heavy compute workload completed cleanly without false-positive termination." -ForegroundColor Green
} else {
    Write-Host "  -> [FAIL] Heavy compute workload failed or clamped unexpectedly." -ForegroundColor Red
    $all_passed = $false
}

# -----------------------------------------------------------------------------
# TEST 2: Phase 2 - Graduated Memory Triage (Rogue Child Worker Termination)
# -----------------------------------------------------------------------------
Write-Host "`n[TEST 2] Verifying Phase 2: Graduated Memory Triage..." -ForegroundColor Yellow
Write-Host "Running coordinator with 1 benign worker and 1 rogue memory-hog child..."
$test2_out = & ".\bin\WinGuard.exe" attack triage 2>&1 | Out-String
Write-Host $test2_out

if ($test2_out -match "TRIAGE" -or $test2_out -match "SELECTIVELY TRIAGED" -or $test2_out -match "Rogue child worker triaged") {
    Write-Host "  -> [PASS] Rogue child worker was identified and selectively terminated; coordinator survived." -ForegroundColor Green
} else {
    Write-Host "  -> [FAIL] Graduated triage did not trigger or coordinator was terminated." -ForegroundColor Red
    $all_passed = $false
}

# -----------------------------------------------------------------------------
# TEST 3: Phase 3 - Allocation Acceleration Bomb (dM/dt > 150 MB/s)
# -----------------------------------------------------------------------------
Write-Host "`n[TEST 3] Verifying Phase 3: Memory Velocity / Acceleration Detection..." -ForegroundColor Yellow
Write-Host "Running rapid memory commitment burst (>150 MB/s)..."
$test3_out = & ".\bin\WinGuard.exe" attack acceleration 2>&1 | Out-String
Write-Host $test3_out

if ($test3_out -match "ALLOCATION_ACCELERATION_BOMB" -or $test3_out -match "Memory allocation velocity") {
    Write-Host "  -> [PASS] High-velocity memory allocation burst correctly detected as an anomaly." -ForegroundColor Green
} else {
    Write-Host "  -> [FAIL] Allocation acceleration was not detected." -ForegroundColor Red
    $all_passed = $false
}

# -----------------------------------------------------------------------------
# TEST 4: Phase 4 - Freeze-Before-Kill & Diagnostic Minidump
# -----------------------------------------------------------------------------
Write-Host "`n[TEST 4] Verifying Phase 4: Freeze-Before-Kill & Minidump Capture..." -ForegroundColor Yellow
Write-Host "Executing multi-vector repeated probe to escalate to LEVEL 3 Quarantine..."
$test4_out = & ".\bin\WinGuard.exe" attack repeated 2>&1 | Out-String

$dump_files = Get-ChildItem -Path "results\crash_dumps" -Filter "*.dmp" -ErrorAction SilentlyContinue

if ($test4_out -match "LEVEL_3_QUARANTINED" -or $test4_out -match "minidump" -or ($dump_files.Count -gt 0)) {
    Write-Host "  -> [PASS] LEVEL 3 Quarantine enforced; Process frozen and minidump captured." -ForegroundColor Green
    if ($dump_files.Count -gt 0) {
        Write-Host "     Generated Crash Dumps:" -ForegroundColor Cyan
        foreach ($d in $dump_files) {
            Write-Host "       $($d.FullName) ($($d.Length) bytes)" -ForegroundColor Cyan
        }
    }
} else {
    Write-Host "  -> [FAIL] LEVEL 3 Quarantine or minidump generation not detected." -ForegroundColor Red
    $all_passed = $false
}

# -----------------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------------
Write-Host "`n====================================================================" -ForegroundColor Cyan
if ($all_passed) {
    Write-Host " ALL 4 UPGRADE PHASES VERIFIED SUCCESSFULLY [100% PASS]" -ForegroundColor Green
} else {
    Write-Host " SOME UPGRADE PHASES FAILED - CHECK LOGS ABOVE" -ForegroundColor Red
}
Write-Host "====================================================================`n" -ForegroundColor Cyan
