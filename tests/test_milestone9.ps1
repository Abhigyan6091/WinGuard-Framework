# Milestone 9 Verification Script: Full Adversarial Workload Suite
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TEST 1: Adversarial Attack 7 - CPU Burst & Creep Pattern" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" attack burst

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 2: Adversarial Attack 8 - Multi-Vector Repeated Violation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" attack repeated

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 3: Adversarial Suite Runner - Complete Test Matrix (8/8)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" attack all

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " MILESTONE 9 TESTS COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
