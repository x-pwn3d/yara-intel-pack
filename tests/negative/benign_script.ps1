# benign_script.ps1
# This is a benign PowerShell script used for testing purposes
# It performs simple file operations without any malicious intent
# Admin helper - lists services and writes a report

Get-Service | Select-Object Name, Status, StartType | Out-File C:\Windows\Temp\services_report.txt
Write-Host "Services snapshot saved."
