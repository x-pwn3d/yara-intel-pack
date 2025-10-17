# Scan files or directories with YARA rules
# Usage: .\scan_with_yara.ps1 -Path "C:\path\to\file" -RulePath "C:\path\to\rule"
# Edit the $YaraExe and $RulesPath variables as needed

param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$RulePath = "",
    [string]$YaraExe = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe"
    
)

if (-not (Test-Path $YaraExe)) { Write-Error "YARA executable not found: $YaraExe"; exit 2 }
if (-not (Test-Path $RulePath)) { Write-Error "Rules path not found: $RulePath"; exit 2 }
if (-not (Test-Path $Path)) { Write-Error "Target path not found: $Path"; exit 2 }

# If Path is folder, run recursive -r
if (Test-Path $Path -PathType Container) {
    & $YaraExe -r (Resolve-Path $RulePath).Path (Resolve-Path $Path).Path
} else {
    & $YaraExe (Resolve-Path $RulePath).Path (Resolve-Path $Path).Path
}
