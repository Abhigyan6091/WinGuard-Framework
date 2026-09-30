# Milestone 2 Verification Script: Job Objects and Active Process Limits
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TEST 1: Normal Execution inside Windows Job Object" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" run bin\dummy_workload.exe 1 --policy permissive

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 2: Process Exhaustion Attack with Active Limit = 3" -ForegroundColor Cyan
Write-Host " (Expected: Windows Job Object blocks excess child processes)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" run bin\process_stress.exe 8 --process-limit 3

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 3: WinGuard CLI Attack Command (attack process)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" attack process

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " MILESTONE 2 TESTS COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
