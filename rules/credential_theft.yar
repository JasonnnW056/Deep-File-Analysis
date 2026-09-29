rule Mimikatz_Strings
{
    meta:
        description = "Strings associated with the Mimikatz credential dumper"
        severity    = "high"
        category    = "credential-theft"
        mitre       = "T1003"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "mimikatz"                 ascii wide nocase
        $s3 = "gentilkiwi"               ascii wide nocase
        $s4 = "lsadump::sam"             ascii wide nocase
    condition:
        2 of them
}

rule LSASS_Memory_Dump
{
    meta:
        description = "References lsass.exe together with a memory-dump method"
        severity    = "high"
        category    = "credential-theft"
        mitre       = "T1003.001"
    strings:
        $l  = "lsass.exe"         ascii wide nocase
        $d1 = "MiniDumpWriteDump" ascii wide
        $d2 = "comsvcs.dll"       ascii wide nocase
    condition:
        $l and any of ($d*)
}

rule Browser_Credential_Theft
{
    meta:
        description = "Access to browser credential stores"
        severity    = "medium"
        category    = "credential-theft"
        mitre       = "T1555.003"
    strings:
        $b1 = "Login Data"   ascii wide
        $b2 = "logins.json"  ascii wide nocase
        $b3 = "key4.db"      ascii wide nocase
        $b4 = "os_crypt"     ascii wide
    condition:
        2 of them
}