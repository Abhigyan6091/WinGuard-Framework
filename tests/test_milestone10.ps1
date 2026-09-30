# ==============================================================================
# WinGuard Milestone 10 & 11 Automated Test Script
# Comparative Security Experiments, Telemetry Analysis & Benchmark Export
# ==============================================================================

$ErrorActionPreference = "Stop"
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host " WinGuard Test Suite: Milestones 10 & 11 (Comparative Experiments)" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

$Passed = 0
$Failed = 0

function Assert-Condition($condition, $message) {
    if ($condition) {
        Write-Host "  [PASS] $message" -ForegroundColor Green
        $global:Passed++
    } else {
        Write-Host "  [FAIL] $message" -ForegroundColor Red
        $global:Failed++
    }
}

# 1. Clean previous experiment results
if (Test-Path "results\experiment_comparison.csv") {
    Remove-Item "results\experiment_comparison.csv" -Force
}
if (Test-Path "results\benchmark_report.md") {
    Remove-Item "results\benchmark_report.md" -Force
}

# 2. Test Help / CLI options
Write-Host "`n[Test 1] Verifying CLI options for experiment and benchmark..." -ForegroundColor Yellow
$helpOutput = & ".\bin\WinGuard.exe" help 2>&1 | Out-String
Assert-Condition ($helpOutput -match "experiment <subcmd>") "WinGuard help displays 'experiment' command"
Assert-Condition ($helpOutput -match "benchmark") "WinGuard help displays 'benchmark' command"

# 3. Test Automated Benchmark Run
Write-Host "`n[Test 2] Executing 3-Way Empirical Benchmark (bin\WinGuard.exe benchmark)..." -ForegroundColor Yellow
$benchStart = Get-Date
$benchOutput = & ".\bin\WinGuard.exe" benchmark 2>&1 | Out-String
$benchDuration = ((Get-Date) - $benchStart).TotalSeconds
Write-Host "Benchmark completed in $([math]::Round($benchDuration, 2)) seconds." -ForegroundColor Gray

Assert-Condition ($benchOutput -match "WinGuard 3-Way Comparative Experiment") "Experiment header displayed"
Assert-Condition ($benchOutput -match "Permissive Baseline") "Permissive mode executed"
Assert-Condition ($benchOutput -match "Static Strict") "Static Strict mode executed"
Assert-Condition ($benchOutput -match "Adaptive WinGuard") "Adaptive WinGuard mode executed"
Assert-Condition ($benchOutput -match "WinGuard Empirical Benchmarking & Security Comparison Table") "Comparison table rendered"

# 4. Verify CSV Export
Write-Host "`n[Test 3] Verifying results\experiment_comparison.csv integrity..." -ForegroundColor Yellow
Assert-Condition (Test-Path "results\experiment_comparison.csv") "results\experiment_comparison.csv was created"

if (Test-Path "results\experiment_comparison.csv") {
    $csvLines = Get-Content "results\experiment_comparison.csv"
    Assert-Condition ($csvLines.Count -ge 4) "CSV contains header + 3 comparison rows (Count: $($csvLines.Count))"
    Assert-Condition ($csvLines[0] -match "mode,policy,wall_time_sec,cpu_user_ms") "CSV contains expected schema header"
    
    $permissiveRow = $csvLines | Where-Object { $_ -match "Permissive Baseline" }
    $strictRow = $csvLines | Where-Object { $_ -match "Static Strict" }
    $adaptiveRow = $csvLines | Where-Object { $_ -match "Adaptive WinGuard" }
    
    Assert-Condition ($permissiveRow -ne $null) "CSV contains 'Permissive Baseline' data row"
    Assert-Condition ($strictRow -ne $null) "CSV contains 'Static Strict' data row"
    Assert-Condition ($adaptiveRow -ne $null) "CSV contains 'Adaptive WinGuard' data row"
}

# 5. Verify Markdown Report Export
Write-Host "`n[Test 4] Verifying results\benchmark_report.md structure..." -ForegroundColor Yellow
Assert-Condition (Test-Path "results\benchmark_report.md") "results\benchmark_report.md was created"

if (Test-Path "results\benchmark_report.md") {
    $mdContent = Get-Content "results\benchmark_report.md" -Raw
    Assert-Condition ($mdContent -match "# WinGuard Empirical Security & Performance Benchmark Report") "Markdown contains main report title"
    Assert-Condition ($mdContent -match "Comparative Performance & Security Matrix") "Markdown contains matrix section"
    Assert-Condition ($mdContent -match "Key Empirical Findings & Analysis") "Markdown contains findings section"
    Assert-Condition ($mdContent -match "Windows Kernel Primitives Utilized") "Markdown documents kernel primitives"
    Assert-Condition ($mdContent -match "JOBOBJECT_CPU_RATE_CONTROL_INFORMATION") "Markdown lists Job Object rate control primitive"
}

# 6. Test Custom Workload Comparative Experiment
Write-Host "`n[Test 5] Executing custom workload comparative experiment on bin\burst_cpu.exe..." -ForegroundColor Yellow
$burstOutput = & ".\bin\WinGuard.exe" experiment compare "bin\burst_cpu.exe burst 2" 2>&1 | Out-String
Assert-Condition ($burstOutput -match "Target Workload: bin\\burst_cpu.exe burst 2") "Custom workload correctly passed and launched"
Assert-Condition ($burstOutput -match "Permissive Baseline") "Permissive executed on burst workload"
Assert-Condition ($burstOutput -match "Static Strict") "Static Strict executed on burst workload"
Assert-Condition ($burstOutput -match "Adaptive WinGuard") "Adaptive WinGuard executed on burst workload"

$summaryColor = "Green"
if ($Failed -gt 0) { $summaryColor = "Red" }
Write-Host "`n====================================================================" -ForegroundColor Cyan
Write-Host " Milestone 10 & 11 Test Summary: $Passed Passed, $Failed Failed" -ForegroundColor $summaryColor
Write-Host "====================================================================" -ForegroundColor Cyan

if ($Failed -gt 0) {
    exit 1
} else {
    exit 0
}
