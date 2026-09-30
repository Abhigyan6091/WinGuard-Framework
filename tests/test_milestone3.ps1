# Milestone 3 Verification Script: CPU & Memory Limits Subsystem
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TEST 1: Adversarial Memory Exhaustion under 64 MB Limit" -ForegroundColor Cyan
Write-Host " (Expected: VirtualAlloc blocked when memory quota reached)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" attack memory

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 2: Adversarial CPU Exhaustion under 20% Hard Cap" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" attack cpu

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 3: Custom CPU & Memory Limits via CLI Flags" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" run bin\dummy_workload.exe 1 --cpu-limit 30 --memory-limit 128 --process-limit 5

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " MILESTONE 3 TESTS COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
