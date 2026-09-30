# Milestone 4 Verification Script: Windows Access Tokens & Restricted Token Subsystem
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TEST 1: Privilege Probe under Standard/Permissive Token" -ForegroundColor Cyan
Write-Host " (Expected: Medium Integrity, Standard User privileges held)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" run bin\privilege_probe.exe --policy permissive

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 2: Privilege Probe under WinGuard Restricted Token" -ForegroundColor Cyan
Write-Host " (Expected: Low Integrity, All Privileges Stripped, Operations Denied)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" run bin\privilege_probe.exe --policy strict --restricted --low-integrity

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " TEST 3: WinGuard CLI Attack Command (attack privilege)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" attack privilege

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " MILESTONE 4 TESTS COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
