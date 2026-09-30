# Milestone 7 Verification Script: Policy Parser & Policy Compiler Subsystem
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TEST 1: Compile & Validate Standard Policies" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" policy compile policies\adaptive.policy
& ".\bin\WinGuard.exe" policy compile policies\strict.policy
& ".\bin\WinGuard.exe" policy compile policies\permissive.policy

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 2: Inspect Compiled Policy Configurations" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" policy show strict

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 3: Validate Compiler Rejection of Malformed Policy" -ForegroundColor Cyan
Write-Host " (Expected: Semantic / syntax validation errors detected and rejected)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" policy compile tests\invalid_syntax.policy

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 4: Execute Workload Using Compiled File Policy" -ForegroundColor Cyan
Write-Host " (Expected: Workload runs under compiled strict policy in Low MIC & Job limits)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$test_csv = "results\test_policy_exec_telemetry.csv"
if (Test-Path $test_csv) { Remove-Item $test_csv -Force }

& ".\bin\WinGuard.exe" run bin\dummy_workload.exe --policy policies\strict.policy --monitor --csv-out $test_csv

if (Test-Path $test_csv) {
    Write-Host "`n[PASS] Workload telemetry successfully streamed under compiled policy: $test_csv" -ForegroundColor Green
} else {
    Write-Host "`n[FAIL] Telemetry file not found!" -ForegroundColor Red
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " MILESTONE 7 TESTS COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
