# Milestone 1 Verification Script
Write-Host "=== TEST 1: WinGuard run dummy_workload ===" -ForegroundColor Cyan
& ".\bin\WinGuard.exe" run bin\dummy_workload.exe 2 --policy adaptive

Write-Host "`n=== TEST 2: WinGuard inspect & kill active process ===" -ForegroundColor Cyan
$proc = Start-Process -FilePath ".\bin\dummy_workload.exe" -ArgumentList "20" -PassThru
$pid_to_test = $proc.Id
Write-Host "Started background process PID: $pid_to_test"

Start-Sleep -Milliseconds 400

Write-Host "Inspecting active process PID $pid_to_test..."
& ".\bin\WinGuard.exe" inspect $pid_to_test

Start-Sleep -Milliseconds 200

Write-Host "Killing process PID $pid_to_test..."
& ".\bin\WinGuard.exe" kill $pid_to_test

Start-Sleep -Milliseconds 200

Write-Host "Inspecting terminated process PID $pid_to_test..."
& ".\bin\WinGuard.exe" inspect $pid_to_test

Write-Host "`n=== MILESTONE 1 TESTS COMPLETE ===" -ForegroundColor Green
