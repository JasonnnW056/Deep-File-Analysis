rule PowerShell_Download_Execute
{
    meta:
        description = "PowerShell that downloads and runs code, or hides an encoded command"
        severity    = "high"
        category    = "script"
        mitre       = "T1059.001"
    strings:
        $dl1  = "DownloadString"     ascii wide nocase
        $dl2  = "DownloadFile"       ascii wide nocase
        $dl3  = "Net.WebClient"      ascii wide nocase
        $dl4  = "Invoke-WebRequest"  ascii wide nocase
        $ex1  = "IEX"                ascii wide
        $ex2  = "Invoke-Expression"  ascii wide nocase
        $enc  = "-EncodedCommand"    ascii wide nocase
        $hid1 = "-WindowStyle Hidden" ascii wide nocase
        $hid2 = "-w hidden"          ascii wide nocase
    condition:
        (any of ($dl*) and any of ($ex*)) or ($enc and any of ($hid*))
}

rule Office_Macro_Container
{
    meta:
        description = "Office document that contains a VBA macro project"
        severity    = "low"
        category    = "macro"
        mitre       = "T1204.002"
    strings:
        $v = "vbaProject.bin" ascii
    condition:
        $v
}

rule Office_Macro_AutoExec_Shell
{
    meta:
        description = "Macro that runs automatically and launches commands"
        severity    = "high"
        category    = "macro"
        mitre       = "T1059.005"
    strings:
        $a1 = "AutoOpen"      ascii wide nocase
        $a2 = "Document_Open" ascii wide nocase
        $a3 = "Workbook_Open" ascii wide nocase
        $a4 = "Auto_Open"     ascii wide nocase
        $e1 = "WScript.Shell" ascii wide nocase
        $e2 = "powershell"    ascii wide nocase
        $e3 = "cmd.exe"       ascii wide nocase
    condition:
        any of ($a*) and any of ($e*)
}

rule Script_HTTP_Downloader
{
    meta:
        description = "VBScript/JScript downloader pattern (HTTP request + file write)"
        severity    = "medium"
        category    = "script"
        mitre       = "T1105"
    strings:
        $h1 = "MSXML2.XMLHTTP"        ascii wide nocase
        $h2 = "MSXML2.ServerXMLHTTP"  ascii wide nocase
        $h3 = "WinHttp.WinHttpRequest" ascii wide nocase
        $w1 = "WScript.Shell"         ascii wide nocase
        $w2 = "ADODB.Stream"          ascii wide nocase
        $w3 = "Scripting.FileSystemObject" ascii wide nocase
    condition:
        any of ($h*) and 2 of ($w*)
}