rule Process_Injection_APIs
{
    meta:
        description = "Classic remote process injection API combination"
        severity    = "high"
        category    = "injection"
        mitre       = "T1055"
    strings:
        $a1 = "VirtualAllocEx"      ascii
        $a2 = "WriteProcessMemory"  ascii
        $a3 = "CreateRemoteThread"  ascii
    condition:
        all of them
}

rule Persistence_Run_Key
{
    meta:
        description = "References the HKCU/HKLM Run registry key"
        severity    = "medium"
        category    = "persistence"
        mitre       = "T1547.001"
    strings:
        $r = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    condition:
        $r
}

rule Packed_UPX
{
    meta:
        description = "UPX packer section names / signature"
        severity    = "low"
        category    = "packer"
    strings:
        $u0 = "UPX0" ascii
        $u1 = "UPX1" ascii
        $u2 = "UPX!" ascii
    condition:
        2 of them
}

rule Downloader_Strings
{
    meta:
        description = "Downloader-style API/strings (URLDownloadToFile + execution)"
        severity    = "medium"
        category    = "downloader"
        mitre       = "T1105"
    strings:
        $d1 = "URLDownloadToFile" ascii wide
        $d2 = "WinExec"           ascii
        $d3 = "ShellExecute"      ascii wide
    condition:
        $d1 and ($d2 or $d3)
}