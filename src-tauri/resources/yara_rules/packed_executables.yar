/*
    ShieldScan — Packed / Protected Executable Detection Rules
    Detects common packer signatures, runtime protectors, and
    high-entropy sections that indicate compressed or encrypted
    payloads inside PE files.
*/

rule UPX_Packed
{
    meta:
        description = "Detects executables packed with the UPX packer"
        author      = "ShieldScan"
        severity    = "medium"
        created     = "2026-06-28"

    strings:
        $mz         = { 4D 5A }
        $upx0       = "UPX0" ascii
        $upx1       = "UPX1" ascii
        $upx2       = "UPX2" ascii
        $upx_sig    = "UPX!" ascii
        $upx_ver    = /UPX [0-9]\.[0-9]{2}/ ascii

    condition:
        $mz at 0 and
        ($upx0 and $upx1) and
        ($upx_sig or $upx2 or $upx_ver)
}

rule UPX_Modified
{
    meta:
        description = "Detects UPX-packed executables with tampered section names (attempt to evade signature-based UPX detection)"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $mz         = { 4D 5A }
        $upx_sig    = "UPX!" ascii

        $stub1      = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
        $stub2      = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB }

    condition:
        $mz at 0 and
        not $upx_sig and
        ($stub1 or $stub2)
}

rule ASPack_Packed
{
    meta:
        description = "Detects executables packed with ASPack"
        author      = "ShieldScan"
        severity    = "medium"
        created     = "2026-06-28"

    strings:
        $mz             = { 4D 5A }
        $aspack_section = ".aspack" ascii
        $adata_section  = ".adata" ascii

        $aspack_stub1   = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD }
        $aspack_stub2   = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }

    condition:
        $mz at 0 and
        (
            $aspack_section or $adata_section or
            $aspack_stub1 or $aspack_stub2
        )
}

rule Themida_Protected
{
    meta:
        description = "Detects executables protected with Themida / WinLicense"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $mz               = { 4D 5A }
        $themida_section   = ".themida" ascii
        $winlicense_sec    = ".winlice" ascii

        $themida_str       = "THEMIDA" ascii wide
        $winlicense_str    = "WinLicense" ascii wide
        $oreans_str        = "Oreans Technologies" ascii wide

        $vm_stub           = { 83 EC 04 50 53 E8 01 00 00 00 CC }
        $anti_debug        = { 64 A1 30 00 00 00 0F B6 40 02 }

    condition:
        $mz at 0 and
        (
            $themida_section or $winlicense_sec or
            $themida_str or $winlicense_str or $oreans_str or
            ($vm_stub and $anti_debug)
        )
}

rule VMProtect_Protected
{
    meta:
        description = "Detects executables protected with VMProtect"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $mz             = { 4D 5A }
        $vmp0           = ".vmp0" ascii
        $vmp1           = ".vmp1" ascii
        $vmp2           = ".vmp2" ascii

        $vmprotect_str  = "VMProtect" ascii wide
        $vmprot_begin   = "VMProtectBegin" ascii
        $vmprot_end     = "VMProtectEnd" ascii

        $vm_entry       = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? }

    condition:
        $mz at 0 and
        (
            ($vmp0 or $vmp1 or $vmp2) or
            $vmprotect_str or
            ($vmprot_begin and $vmprot_end)
        )
}

rule PECompact_Packed
{
    meta:
        description = "Detects executables packed with PECompact"
        author      = "ShieldScan"
        severity    = "medium"
        created     = "2026-06-28"

    strings:
        $mz             = { 4D 5A }
        $pec_section    = "PEC2" ascii
        $pec_section2   = "pec" ascii

        $pec_stub1      = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 00 00 00 33 C0 8B C4 }
        $pec_stub2      = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 }

    condition:
        $mz at 0 and
        (
            $pec_section or $pec_section2 or
            $pec_stub1 or $pec_stub2
        )
}

rule MPRESS_Packed
{
    meta:
        description = "Detects executables packed with MPRESS"
        author      = "ShieldScan"
        severity    = "medium"
        created     = "2026-06-28"

    strings:
        $mz             = { 4D 5A }
        $mpress1        = ".MPRESS1" ascii
        $mpress2        = ".MPRESS2" ascii

    condition:
        $mz at 0 and $mpress1 and $mpress2
}

rule High_Entropy_PE_Section
{
    meta:
        description = "Detects PE executables with suspiciously high-entropy sections suggesting packing, encryption, or obfuscation"
        author      = "ShieldScan"
        severity    = "medium"
        created     = "2026-06-28"

    strings:
        $mz         = { 4D 5A }
        $pe_sig     = "PE\x00\x00"

        $no_import  = "kernel32.dll" ascii nocase
        $single_imp = "LoadLibraryA" ascii
        $single_gpa = "GetProcAddress" ascii

    condition:
        $mz at 0 and $pe_sig and
        (
            (not $no_import) or
            ($single_imp and $single_gpa and filesize > 50KB)
        )
}

rule Suspicious_PE_Overlay
{
    meta:
        description = "Detects PE files where data beyond the last section may contain a hidden payload (overlay abuse)"
        author      = "ShieldScan"
        severity    = "medium"
        created     = "2026-06-28"

    strings:
        $mz          = { 4D 5A }
        $pe_sig      = "PE\x00\x00"

        $zip_local   = { 50 4B 03 04 }
        $rar_magic   = { 52 61 72 21 1A 07 }
        $cab_magic   = { 4D 53 43 46 }
        $seven_z     = { 37 7A BC AF 27 1C }
        $mz_overlay  = { 4D 5A 90 00 }

    condition:
        $mz at 0 and $pe_sig and
        for any of ($zip_local, $rar_magic, $cab_magic, $seven_z, $mz_overlay) : (
            @ > 1024
        )
}
