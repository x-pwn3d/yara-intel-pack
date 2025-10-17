rule LSASS_Tools_Generic
{
    meta:
        author = "xpwn3d"
        description = "Detect common LSASS / memory dump tool names or indicators (text markers)"
        reference = "T1003 - Credential dumping"
        mitre = "T1003"
        severity = "high"
        created = "2025-10-16"

    strings:
        $mimikatz       = /\bmimikatz\b/i
        $procdump       = /\bprocdump(64)?\b/i
        $winpmem        = /\bwinpmem\b/i
        $sekurlsa       = /\bsekurlsa\b/i
        $sekurlsa_cmd   = /sekurlsa::/i
        $sekurlsa_word  = /\blogonpasswords\b/i
        $dumplib        = /mini[_-]?dump/i
    condition:
        any of them
}

import "pe"

rule LSASS_Tools_PE
{
    meta:
        author = "xpwn3d"
        description = "PE heuristics for common dumpers (imports + strings + small PE heuristic)"
        mitre = "T1003"
        severity = "high"
        created = "2025-10-16"

    strings:
        $txt1 = /\bmimikatz\b/i
        $txt2 = /\bprocdump(64)?\b/i
        $txt3 = /\bwinpmem\b/i
        $minidump = "MiniDumpWriteDump" nocase

    condition:
        // textual markers OR PE file with suspicious imports OR PE containing MiniDumpWriteDump string
        any of ($txt1, $txt2, $txt3, $minidump) or
        (
            pe.is_pe and
            (
                pe.imports("DbgHelp.dll") or
                pe.imports("dbghelp.dll")
            ) and
            filesize < 10485760
        )
}

