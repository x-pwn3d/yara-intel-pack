# evil_procdump_command.ps1
# simulate usage that would indicate dumping
Start-Process -FilePath "C:\Tools\procdump.exe" -ArgumentList "-ma 1234 C:\Windows\Temp\proc.dmp"
Write-Host "Process dump command executed."
# Note: This is a test file to trigger YARA rules; no actual dumping is performed