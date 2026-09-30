# Milestone 5 Verification Script: Filesystem Policy & Workspace Isolation
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TEST 1: Inspect Filesystem Security Policy" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" fs policy

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 2: Adversarial Filesystem Probe under Strict Sandbox" -ForegroundColor Cyan
Write-Host " (Expected: Read input allowed; Write input denied; Write output allowed; Escape denied)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" attack filesystem

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " MILESTONE 5 TESTS COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
