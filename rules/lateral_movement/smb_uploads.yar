rule Suspicious_Share_Transfer_PowerShell
{
    meta:
        description = "PowerShell script on SMB share with suspicious content (PS1 + IEX/Encoded/Download)"
        author = "xpwn3d"

    strings:
        $ps_ext      = /\.ps1\b/i
        $iex         = /\bIEX\b/i
        $enc_flag    = /-EncodedCommand\s+[A-Za-z0-9+\/=]{6,}/i
        $download    = /DownloadString\(|Invoke-WebRequest|Invoke-RestMethod/i

    condition:
        $ps_ext and ( $iex or $enc_flag or $download )
}
