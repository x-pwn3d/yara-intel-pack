rule PS_EncodedCommand_Generic
{
    meta:
        author = "xpwn3d"
        description = "PowerShell -EncodedCommand indicator (context-aware: require flag or IEX/Invoke)"
    strings:
        $enc     = /-EncodedCommand\b/i
        $enc2    = /-enc\b/i
        $iex     = /\bIEX\b/i
        $invoke  = /\bInvoke-Expression\b/i
        $b64     = /[A-Za-z0-9+\/]{60,}={0,2}/

        // PEM header to exclude (common FP certificate)
        $pem_hdr = /-----BEGIN (CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY)-----/i

    condition:
        not $pem_hdr and (
            $enc or $enc2 or $iex or $invoke
            or ( $b64 and ( $enc or $enc2 ) )
        )
}


rule PS_Obfuscation_Indicators
{
    meta:
        author = "xpwn3d"
        description = "Concatenation and simple obfuscation patterns (safer + faster)"
    strings:
        $concat_simple  = /\$[A-Za-z_][A-Za-z0-9_]{1,30}\s*\+\s*('|"")/ 
        $concat_simple2 = /('|"")\s*\+\s*\$[A-Za-z_][A-Za-z0-9_]{1,30}/
        $chr            = /(\[char\]\d{1,3})|chr\(\d{1,3}\)/i
    condition:
        any of ($concat_simple, $concat_simple2, $chr)
}


