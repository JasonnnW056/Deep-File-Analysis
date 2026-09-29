/*
  Anti-VM / anti-sandbox indicators (IDD Innovative Feature #2).
  Files matching these are flagged as evasive: they check whether they
  are being analysed before revealing behaviour.
*/

rule Anti_VM_Artifacts
{
    meta:
        description = "References to virtualisation guest drivers, services or devices"
        severity    = "medium"
        category    = "anti-evasion"
    strings:
        $vbox1 = "VBoxGuest"   ascii wide nocase
        $vbox2 = "VBoxService" ascii wide nocase
        $vbox3 = "VBoxMiniRdrDN" ascii wide nocase
        $vmw1  = "VMwareService" ascii wide nocase
        $vmw2  = "vmtoolsd"    ascii wide nocase
        $vmw3  = "VMware Virtual" ascii wide nocase
        $qemu  = "qemu-ga"     ascii wide nocase
        $wine  = "wine_get_unix_file_name" ascii
    condition:
        2 of them
}

rule Anti_Sandbox_Artifacts
{
    meta:
        description = "References to known sandbox / analysis tooling"
        severity    = "medium"
        category    = "anti-evasion"
    strings:
        $s1 = "SbieDll.dll"   ascii wide nocase
        $s2 = "SandboxieRpcSs" ascii wide nocase
        $s3 = "cuckoomon"     ascii wide nocase
        $s4 = "dbghelp.dll"   ascii wide nocase
        $s5 = "api_log.dll"   ascii wide nocase
        $s6 = "dir_watch.dll" ascii wide nocase
    condition:
        2 of them
}

rule Anti_Debug_APIs
{
    meta:
        description = "Imports commonly used to detect a debugger"
        severity    = "low"
        category    = "anti-evasion"
    strings:
        $a1 = "IsDebuggerPresent"          ascii
        $a2 = "CheckRemoteDebuggerPresent" ascii
        $a3 = "NtQueryInformationProcess"  ascii
    condition:
        2 of them
}