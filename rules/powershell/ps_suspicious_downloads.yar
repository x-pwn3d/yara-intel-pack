rule PS_Suspicious_Downloads
{
    meta:
        description = "Detect common download + execution patterns (IEX + DownloadString or Invoke-WebRequest)"
        author = "xpwn3d"

    strings:
        $iex_ds = /IEX.{0,200}DownloadString/i
        $download_http = /https?:\/\/[^\s]{1,200}\b(download|raw|paste|gist)\b/i
        $iex_simple = /\bIEX\s*\(/i

    condition:
        // match if: explicit download+URL OR IEX plus any download helper OR plain IEX (looser)
        any of ($download_http, $iex_ds, $iex_simple)
}
