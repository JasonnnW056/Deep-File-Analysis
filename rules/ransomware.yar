rule Ransomware_Backup_Destruction
{
    meta:
        description = "Commands that delete shadow copies or disable recovery"
        severity    = "high"
        category    = "ransomware"
        mitre       = "T1490"
    strings:
        $a1 = "vssadmin delete shadows" ascii wide nocase
        $a2 = "wmic shadowcopy delete"  ascii wide nocase
        $a3 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $a4 = "wbadmin delete catalog"  ascii wide nocase
    condition:
        any of them
}

rule Ransomware_Ransom_Note
{
    meta:
        description = "Ransom-note wording combined with a payment channel"
        severity    = "high"
        category    = "ransomware"
        mitre       = "T1486"
    strings:
        $n1 = "your files have been encrypted" ascii wide nocase
        $n2 = "all your files are encrypted"   ascii wide nocase
        $n3 = "decrypt your files"             ascii wide nocase
        $n4 = "recover your files"             ascii wide nocase
        $p1 = "bitcoin" ascii wide nocase
        $p2 = "monero"  ascii wide nocase
        $p3 = ".onion"  ascii wide nocase
    condition:
        any of ($n*) and any of ($p*)
}