# scan_with_yara.ps1
# Scan a file or directory with YARA rules
# Usage examples:
#  .\scan_with_yara.ps1 -Path "C:\yara_intel\tests\positive\evil_demo.ps1" -RulePath "..\compiled_rules.yar"
#  .\scan_with_yara.ps1 -Path "C:\LabShare" -RulePath "..\compiled_rules.yar" -YaraExe "C:\tools\yara\yara64.exe"
#
# Note: Edit $DefaultYaraExe below if you want a hard-coded default.


param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$RulePath,
    [string]$YaraExe = $null
)

# Default fallback (adjust if needed)
$DefaultYaraExe = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe"
if (-not $YaraExe) { $YaraExe = $DefaultYaraExe }

if (-not (Test-Path $YaraExe)) { Write-Error "YARA executable not found: $YaraExe"; exit 2 }
if (-not (Test-Path $RulePath)) { Write-Error "Rules path not found: $RulePath"; exit 2 }
if (-not (Test-Path $Path))     { Write-Error "Target path not found: $Path"; exit 2 }

$resolvedRules  = (Resolve-Path $RulePath).Path
$resolvedTarget = (Resolve-Path $Path).Path

# Normalize: remove trailing backslash to avoid escaping issues (keeps drive root OK)
if ($resolvedTarget.Length -gt 3 -and $resolvedTarget.EndsWith('\')) {
    $resolvedTarget = $resolvedTarget.TrimEnd('\')
}

Write-Host "YARA exe: $YaraExe"
Write-Host "Rules:    $resolvedRules"
Write-Host "Target:   $resolvedTarget"
Write-Host ""

# Build argument array (avoid manual quoting)
if (Test-Path $Path -PathType Container) {
    $argList = @('-r', $resolvedRules, $resolvedTarget)
} else {
    $argList = @($resolvedRules, $resolvedTarget)
}

# Temp files for output
$tmpOut = [System.IO.Path]::GetTempFileName()
$tmpErr = [System.IO.Path]::GetTempFileName()

try {
    $proc = Start-Process -FilePath $YaraExe -ArgumentList $argList -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr
    $exitCode = $proc.ExitCode

    $stdout = Get-Content -LiteralPath $tmpOut -ErrorAction SilentlyContinue
    $stderr = Get-Content -LiteralPath $tmpErr -ErrorAction SilentlyContinue

    if ($stderr -and $stderr.Count -gt 0) {
        Write-Host "YARA warnings/errors:" -ForegroundColor Yellow
        $stderr | ForEach-Object { Write-Host " - $_" }
        Write-Host ""
    }

    if ($stdout -and $stdout.Count -gt 0) {
        Write-Host "YARA matches/output:" -ForegroundColor Green
        $stdout | ForEach-Object { Write-Host " - $_" }
    } else {
        Write-Host "No YARA matches." -ForegroundColor Gray
    }

    exit $exitCode
}
finally {
    # cleanup temp files
    Remove-Item -LiteralPath $tmpOut -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpErr -ErrorAction SilentlyContinue
}