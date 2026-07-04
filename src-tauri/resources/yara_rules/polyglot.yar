/*
    ShieldScan — Polyglot File Detection Rules
    Detects files that are simultaneously valid in two or more
    formats, a common technique for smuggling payloads past
    content-type filters and antivirus engines.
*/

rule PDF_ZIP_Polyglot
{
    meta:
        description = "Detects a file that is valid as both PDF and ZIP (e.g., PDF with appended ZIP archive)"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $pdf_header = "%PDF-" ascii
        $pdf_eof    = "%%EOF" ascii
        $zip_local  = { 50 4B 03 04 }
        $zip_eocd   = { 50 4B 05 06 }

    condition:
        $pdf_header at 0 and
        $zip_local and $zip_eocd and
        $pdf_eof
}

rule PDF_ZIP_Polyglot_Reversed
{
    meta:
        description = "Detects ZIP-first polyglot with PDF content appended (ZIP header at offset 0)"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $zip_local  = { 50 4B 03 04 }
        $pdf_header = "%PDF-" ascii
        $pdf_xref   = "xref" ascii
        $pdf_eof    = "%%EOF" ascii

    condition:
        $zip_local at 0 and
        $pdf_header and $pdf_xref and $pdf_eof
}

rule PNG_ZIP_Polyglot
{
    meta:
        description = "Detects a file valid as both PNG image and ZIP archive"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $png_magic  = { 89 50 4E 47 0D 0A 1A 0A }
        $png_ihdr   = "IHDR" ascii
        $png_iend   = "IEND" ascii
        $zip_local  = { 50 4B 03 04 }
        $zip_eocd   = { 50 4B 05 06 }

    condition:
        $png_magic at 0 and $png_ihdr and
        $zip_local and
        ($zip_eocd or $png_iend)
}

rule JAR_Disguised_As_Image
{
    meta:
        description = "Detects a Java Archive (JAR) file disguised with an image header (JPEG, PNG, GIF, BMP)"
        author      = "ShieldScan"
        severity    = "critical"
        created     = "2026-06-28"

    strings:
        $jpeg_magic = { FF D8 FF }
        $png_magic  = { 89 50 4E 47 0D 0A 1A 0A }
        $gif_magic  = "GIF8" ascii
        $bmp_magic  = { 42 4D }

        $zip_local  = { 50 4B 03 04 }
        $manifest   = "META-INF/MANIFEST.MF" ascii
        $class_sig  = { CA FE BA BE }
        $jar_entry  = ".class" ascii

    condition:
        ($jpeg_magic at 0 or $png_magic at 0 or $gif_magic at 0 or $bmp_magic at 0) and
        $zip_local and
        ($manifest or $class_sig or $jar_entry)
}

rule GIF_ZIP_Polyglot
{
    meta:
        description = "Detects a file valid as both GIF image and ZIP archive"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $gif87a     = "GIF87a" ascii
        $gif89a     = "GIF89a" ascii
        $zip_local  = { 50 4B 03 04 }
        $zip_eocd   = { 50 4B 05 06 }

    condition:
        ($gif87a at 0 or $gif89a at 0) and
        $zip_local and $zip_eocd
}

rule JPEG_ZIP_Polyglot
{
    meta:
        description = "Detects a file valid as both JPEG image and ZIP archive"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $jpeg_soi   = { FF D8 FF }
        $jpeg_eoi   = { FF D9 }
        $zip_local  = { 50 4B 03 04 }
        $zip_eocd   = { 50 4B 05 06 }

    condition:
        $jpeg_soi at 0 and $jpeg_eoi and
        $zip_local and $zip_eocd
}
