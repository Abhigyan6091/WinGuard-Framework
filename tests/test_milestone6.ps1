# Milestone 6 Verification Script: Logging & Behavior Monitoring Subsystem
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TEST 1: Behavior Monitoring on Dummy Workload" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$test1_csv = "results\test_dummy_telemetry.csv"
if (Test-Path $test1_csv) { Remove-Item $test1_csv -Force }

& ".\bin\WinGuard.exe" run bin\dummy_workload.exe --monitor --monitor-interval 20 --csv-out $test1_csv

if (Test-Path $test1_csv) {
    Write-Host "`n[PASS] Telemetry CSV was created: $test1_csv" -ForegroundColor Green
    $lines = Get-Content $test1_csv
    Write-Host "Total Telemetry Data Rows: $($lines.Count - 1)" -ForegroundColor DarkGray
    Write-Host "First 3 Sample Rows:" -ForegroundColor DarkGray
    $lines | Select-Object -First 4 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
} else {
    Write-Host "`n[FAIL] Telemetry CSV was not generated!" -ForegroundColor Red
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 2: Behavior Monitoring under CPU Stress with Rate Limit" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$test2_csv = "results\test_cpu_telemetry.csv"
if (Test-Path $test2_csv) { Remove-Item $test2_csv -Force }

& ".\bin\WinGuard.exe" run bin\cpu_stress.exe 2 1 --cpu-limit 25 --monitor --monitor-interval 25 --csv-out $test2_csv

if (Test-Path $test2_csv) {
    Write-Host "`n[PASS] CPU Telemetry CSV was created: $test2_csv" -ForegroundColor Green
    $lines = Get-Content $test2_csv
    Write-Host "Total Telemetry Data Rows: $($lines.Count - 1)" -ForegroundColor DarkGray
    $lines | Select-Object -First 4 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
} else {
    Write-Host "`n[FAIL] CPU Telemetry CSV was not generated!" -ForegroundColor Red
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 3: Behavior Monitoring under Memory Stress" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$test3_csv = "results\test_memory_telemetry.csv"
if (Test-Path $test3_csv) { Remove-Item $test3_csv -Force }

& ".\bin\WinGuard.exe" run bin\memory_stress.exe 40 10 --memory-limit 64 --monitor --monitor-interval 25 --csv-out $test3_csv

if (Test-Path $test3_csv) {
    Write-Host "`n[PASS] Memory Telemetry CSV was created: $test3_csv" -ForegroundColor Green
    $lines = Get-Content $test3_csv
    Write-Host "Total Telemetry Data Rows: $($lines.Count - 1)" -ForegroundColor DarkGray
    $lines | Select-Object -First 4 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
} else {
    Write-Host "`n[FAIL] Memory Telemetry CSV was not generated!" -ForegroundColor Red
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " MILESTONE 6 TESTS COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
