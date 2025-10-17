# encoded_long_b64.ps1
# Example of a script embedding a long Base64 payload and decoding it (test positive)

# small legit preamble
Write-Host "Starting encoded payload demo..."

# Encoded payload (example): a long Base64 string that decodes to a PowerShell command
# NOTE: this is just a demo payload that writes a string when decoded.
# Generate a real payload using the helper command below; here we put a long B64 to trigger yara.

$payload = 'Write-Host "This is a demo"'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))

# decode and execute (mimic the runtime behaviour of -EncodedCommand)
try {
    $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($enc))
    Write-Host "Decoded payload: $decoded"
    # simulate execution of decoded code (commented for safety)
    # Invoke-Expression $decoded
} catch {
    Write-Host "Decode failed: $_"
}

Write-Host "Done."
