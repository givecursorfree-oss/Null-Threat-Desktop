/*
    ShieldScan — Video & Media Threat Detection Rules
    Detects executable payloads, archive overlays, and malicious
    strings hidden inside common media container formats.
*/

rule PE_Inside_MP4
{
    meta:
        description = "Detects a PE (MZ) header embedded inside an MP4 container"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $mp4_ftyp   = "ftyp"
        $mp4_moov   = "moov"
        $mp4_mdat   = "mdat"
        $mz_header  = { 4D 5A 90 00 }
        $pe_sig     = "PE\x00\x00"

    condition:
        ($mp4_ftyp at 4 or $mp4_moov or $mp4_mdat) and
        $mz_header and $pe_sig
}

rule PE_Inside_AVI
{
    meta:
        description = "Detects a PE (MZ) header embedded inside an AVI container"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $riff_magic = "RIFF" ascii
        $avi_marker = "AVI " ascii
        $mz_header  = { 4D 5A 90 00 }
        $pe_sig     = "PE\x00\x00"

    condition:
        $riff_magic at 0 and $avi_marker at 8 and
        $mz_header and $pe_sig
}

rule PE_Inside_MKV
{
    meta:
        description = "Detects a PE (MZ) header embedded inside a Matroska (MKV) container"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $mkv_magic  = { 1A 45 DF A3 }
        $mz_header  = { 4D 5A 90 00 }
        $pe_sig     = "PE\x00\x00"

    condition:
        $mkv_magic at 0 and $mz_header and $pe_sig
}

rule ZIP_Inside_Media
{
    meta:
        description = "Detects ZIP archive magic bytes hidden inside MP4, AVI, or MKV media files"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $mp4_ftyp   = "ftyp"
        $riff_magic = "RIFF" ascii
        $avi_marker = "AVI " ascii
        $mkv_magic  = { 1A 45 DF A3 }

        $zip_local  = { 50 4B 03 04 }
        $zip_eocd   = { 50 4B 05 06 }

    condition:
        (
            $mp4_ftyp at 4 or
            ($riff_magic at 0 and $avi_marker at 8) or
            $mkv_magic at 0
        ) and
        ($zip_local or $zip_eocd)
}

rule PowerShell_In_Media_Metadata
{
    meta:
        description = "Detects PowerShell commands or encoded payloads in media file metadata fields"
        author      = "ShieldScan"
        severity    = "critical"
        created     = "2026-06-28"

    strings:
        $mp4_ftyp       = "ftyp"
        $riff_magic     = "RIFF" ascii
        $mkv_magic      = { 1A 45 DF A3 }

        $ps_invoke      = "Invoke-Expression" ascii nocase
        $ps_iex         = "IEX(" ascii nocase
        $ps_enc_cmd     = "-EncodedCommand" ascii nocase
        $ps_enc_short   = "-enc " ascii nocase
        $ps_download    = "DownloadString(" ascii nocase
        $ps_webclient   = "Net.WebClient" ascii nocase
        $ps_bypass      = "-ExecutionPolicy Bypass" ascii nocase
        $ps_hidden      = "-WindowStyle Hidden" ascii nocase
        $ps_frombase64  = "FromBase64String" ascii nocase
        $ps_start_proc  = "Start-Process" ascii nocase

    condition:
        (
            $mp4_ftyp at 4 or
            $riff_magic at 0 or
            $mkv_magic at 0
        ) and
        2 of ($ps_*)
}
