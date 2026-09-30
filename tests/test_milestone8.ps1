# Milestone 8 Verification Script: Adaptive State Machine Engine
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TEST: Dynamic State Machine Escalation & Decay Probe" -ForegroundColor Cyan
Write-Host " (Expected: LEVEL 0 -> LEVEL 1 -> LEVEL 2 via violations, then demotes back to LEVEL 1 via benign decay)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

& ".\bin\WinGuard.exe" attack adaptive

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " MILESTONE 8 TESTS COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
