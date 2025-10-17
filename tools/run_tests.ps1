# run_tests.ps1
# Script to compile YARA rules and run tests against positive and negative samples
# Usage: .\run_tests.ps1
# Edit the parameters below as needed
# Tested with PowerShell 5.1
param(
    [string]$RulesDir = "..\rules",
    [string]$PosDir   = "..\tests\positive",
    [string]$NegDir   = "..\tests\negative",
    [string]$OutFile  = ".\compiled_rules.yar",
    [string]$YaraExe  = $null # Edit this path to your YARA executable
)

function Fail($msg) {
    Write-Host "ERROR: $msg" -ForegroundColor Red
    exit 2
}

# Validate prerequisites
if (-not (Test-Path $YaraExe)) { Fail "YARA binary not found at: $YaraExe" }
if (-not (Test-Path $RulesDir)) { Fail "Rules directory not found: $RulesDir" }

# Get rules
$rules = Get-ChildItem -Path $RulesDir -Recurse -Filter *.yar | Sort-Object Name
if (-not $rules -or $rules.Count -eq 0) { Fail "No .yar files found under $RulesDir" }

# Remove old compiled file
if (Test-Path $OutFile) { Remove-Item -Path $OutFile -Force }

# Compile rules
"// Compiled rules generated: $(Get-Date -Format o)" | Out-File -FilePath $OutFile -Encoding ascii
foreach ($r in $rules) {
    "" | Out-File -FilePath $OutFile -Append -Encoding ascii
    "// ----- $($r.Name) -----" | Out-File -FilePath $OutFile -Append -Encoding ascii
    Get-Content -Path $r.FullName -Encoding utf8 | Out-File -FilePath $OutFile -Append -Encoding ascii
}
Write-Host "Compiled $($rules.Count) rules into $OutFile" -ForegroundColor Green

# Collect test files
$pos = if (Test-Path $PosDir) { Get-ChildItem -Path $PosDir -File -Recurse } else { @() }
$neg = if (Test-Path $NegDir) { Get-ChildItem -Path $NegDir -File -Recurse } else { @() }

$results = [ordered]@{
    positives_total    = $pos.Count
    positives_detected = 0
    negatives_total    = $neg.Count
    negatives_detected = 0
    false_negatives    = @()
    false_positives    = @()
    yara_warnings      = @()
    per_file_matches   = @{}
}

function Run-Yara($file) {
    $rawOut = & $YaraExe -r $OutFile $file 2>&1
    $lines = ($rawOut -split "`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

    $matchedRules = @()
    $warnings = @()
    foreach ($l in $lines) {
        if ($l -match '^(warning|error):') { 
            $warnings += $l
        }
        elseif ($l -match '^\s*([A-Za-z0-9_\-:]+)\s+\S+') {
            $matchedRules += $matches[1]
        }
    }

    return [PSCustomObject]@{ rules=$matchedRules; warnings=$warnings; raw=$lines }
}

# --- Run positive tests ---
Write-Host "`nRunning positive tests..."
foreach ($f in $pos) {
    $res = Run-Yara $f.FullName
    $results.per_file_matches[$f.FullName] = $res.rules
    if ($res.rules.Count -gt 0) {
        $results.positives_detected++
        Write-Host "[+] $($f.Name) matched rules: $($res.rules -join ', ')" -ForegroundColor Green
    } else {
        $results.false_negatives += $f.FullName
        Write-Host "[-] $($f.Name) not detected" -ForegroundColor Yellow
    }
    if ($res.warnings.Count -gt 0) { $results.yara_warnings += $res.warnings }
}

# --- Run negative tests ---
Write-Host "`nRunning negative tests..."
foreach ($f in $neg) {
    $res = Run-Yara $f.FullName
    $results.per_file_matches[$f.FullName] = $res.rules
    if ($res.rules.Count -gt 0) {
        $results.negatives_detected++
        $results.false_positives += $f.FullName
        Write-Host "[!] FALSE POSITIVE - $($f.Name) matched rules: $($res.rules -join ', ')" -ForegroundColor Red
    } else {
        Write-Host "[OK] $($f.Name) clean" -ForegroundColor Green
    }
    if ($res.warnings.Count -gt 0) { $results.yara_warnings += $res.warnings }
}

# --- Summary ---
Write-Host "`n=== YARA Test Summary ===" -ForegroundColor Cyan
Write-Host "Positives detected : $($results.positives_detected)/$($results.positives_total)"
Write-Host "Negatives matched  : $($results.negatives_detected)/$($results.negatives_total) (should be 0)"

if ($results.false_negatives.Count -gt 0) {
    Write-Host "`nFalse negatives:" -ForegroundColor Yellow
    foreach ($fn in $results.false_negatives) { Write-Host " - $fn" }
}
if ($results.false_positives.Count -gt 0) {
    Write-Host "`nFalse positives:" -ForegroundColor Red
    foreach ($fp in $results.false_positives) { Write-Host " - $fp" }
}
if ($results.yara_warnings.Count -gt 0) {
    Write-Host "`nYARA warnings/errors (unique):" -ForegroundColor Yellow
    $results.yara_warnings | Select-Object -Unique | ForEach-Object { Write-Host " - $_" }
}

# Optional: per-file matches
if ($results.per_file_matches.Keys.Count -gt 0) {
    Write-Host "`nPer-file matched rules:"
    foreach ($k in $results.per_file_matches.Keys) {
        $r = $results.per_file_matches[$k]
        if ($r -and $r.Count -gt 0) {
            Write-Host " - $(Split-Path $k -Leaf) => $($r -join ', ')"
        }
    }
}

# Exit code
if ($results.false_negatives.Count -gt 0 -or $results.false_positives.Count -gt 0) {
    Write-Host "`nTest suite finished with FAIL (FP/FN detected)" -ForegroundColor Red
    exit 3
} else {
    Write-Host "`nAll tests passed (no FP/FN)." -ForegroundColor Green
    exit 0
}
