import "pe"
import "math"

rule PE_High_Entropy_Section
{
    meta:
        description = "PE section with very high entropy (packed or encrypted code)"
        severity    = "medium"
        category    = "packer"
        mitre       = "T1027.002"
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 4096 and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.2
        )
}

rule PE_Almost_No_Imports
{
    meta:
        description = "PE with almost no imported functions (typical of packed loaders)"
        severity    = "low"
        category    = "packer"
    condition:
        uint16(0) == 0x5A4D and pe.is_pe and pe.number_of_imported_functions < 5
}

rule PE_Keylogger_APIs
{
    meta:
        description = "Executable importing keyboard hook and key-state APIs"
        severity    = "medium"
        category    = "spyware"
        mitre       = "T1056.001"
    strings:
        $h = "SetWindowsHookEx" ascii
        $k = "GetAsyncKeyState" ascii
    condition:
        uint16(0) == 0x5A4D and $h and $k
}