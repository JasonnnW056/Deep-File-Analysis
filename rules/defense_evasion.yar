rule Disable_Windows_Defender
{
    meta:
        description = "Commands that disable or exclude paths from Windows Defender"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1562.001"
    strings:
        $a = "DisableRealtimeMonitoring" ascii wide nocase
        $b = "Add-MpPreference"          ascii wide nocase
        $c = "ExclusionPath"             ascii wide nocase
        $d = "sc stop WinDefend"         ascii wide nocase
    condition:
        $a or ($b and $c) or $d
}

rule Event_Log_Clearing
{
    meta:
        description = "Commands that erase Windows event logs"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1070.001"
    strings:
        $a = "wevtutil cl"    ascii wide nocase
        $b = "wevtutil.exe cl" ascii wide nocase
        $c = "Clear-EventLog" ascii wide nocase
    condition:
        any of them
}

rule AMSI_Bypass
{
    meta:
        description = "Patching or disabling the Antimalware Scan Interface"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1562.001"
    strings:
        $a = "AmsiScanBuffer" ascii wide
        $b = "amsiInitFailed" ascii wide nocase
        $c = "VirtualProtect" ascii wide
    condition:
        $b or ($a and $c)
}