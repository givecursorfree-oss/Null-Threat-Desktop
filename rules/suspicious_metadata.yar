/*
    ShieldScan — Suspicious Metadata Detection Rules
    Detects script injection, malicious URLs, and command-injection
    patterns hidden in file metadata fields (EXIF, ID3, XMP, OLE).
*/

rule Script_Tags_In_Metadata
{
    meta:
        description = "Detects HTML/JavaScript script tags embedded in file metadata (XSS via metadata injection)"
        author      = "ShieldScan"
        severity    = "high"
        created     = "2026-06-28"

    strings:
        $script_open    = "<script" ascii nocase
        $script_close   = "</script>" ascii nocase
        $onerror        = "onerror=" ascii nocase
        $onload         = "onload=" ascii nocase
        $onmouseover    = "onmouseover=" ascii nocase
        $javascript_uri = "javascript:" ascii nocase
        $vbscript_uri   = "vbscript:" ascii nocase
        $svg_onload     = "<svg" ascii nocase
        $img_tag        = "<img" ascii nocase
        $iframe_tag     = "<iframe" ascii nocase
        $eval_func      = "eval(" ascii nocase
        $document_write = "document.write" ascii nocase

        $exif_marker    = { FF E1 }
        $xmp_marker     = "http://ns.adobe.com/xap/" ascii
        $id3_marker     = "ID3" ascii
        $ole_marker     = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        ($exif_marker or $xmp_marker or $id3_marker or $ole_marker) and
        (
            ($script_open and $script_close) or
            $javascript_uri or
            $vbscript_uri or
            ($img_tag and $onerror) or
            ($svg_onload and $onload) or
            $iframe_tag or
            ($eval_func and $document_write)
        )
}

rule Suspicious_URLs_In_Metadata
{
    meta:
        description = "Detects suspicious or obfuscated URLs in file metadata fields that may indicate C2 communication or payload delivery"
        author      = "ShieldScan"
        severity    = "medium"
        created     = "2026-06-28"

    strings:
        $exif_marker    = { FF E1 }
        $xmp_marker     = "http://ns.adobe.com/xap/" ascii
        $id3_marker     = "ID3" ascii
        $ole_marker     = { D0 CF 11 E0 A1 B1 1A E1 }
        $iptc_marker    = { 1C 02 }

        $url_http       = "http://" ascii nocase
        $url_https      = "https://" ascii nocase
        $url_ftp        = "ftp://" ascii nocase

        $susp_pastebin  = "pastebin.com" ascii nocase
        $susp_discord   = "cdn.discordapp.com" ascii nocase
        $susp_ngrok     = ".ngrok.io" ascii nocase
        $susp_telegram  = "api.telegram.org" ascii nocase
        $susp_transfer  = "transfer.sh" ascii nocase
        $susp_onion     = ".onion" ascii nocase
        $susp_raw_ip    = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii

        $susp_b64_aHR   = "aHR0c" ascii
        $susp_hex_url   = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}/ ascii

    condition:
        ($exif_marker or $xmp_marker or $id3_marker or $ole_marker or $iptc_marker) and
        ($url_http or $url_https or $url_ftp) and
        (
            $susp_pastebin or $susp_discord or $susp_ngrok or
            $susp_telegram or $susp_transfer or $susp_onion or
            $susp_raw_ip or $susp_b64_aHR or $susp_hex_url
        )
}

rule Command_Injection_In_Metadata
{
    meta:
        description = "Detects OS command-injection patterns in file metadata (EXIF comments, XMP, ID3 tags, OLE properties)"
        author      = "ShieldScan"
        severity    = "critical"
        created     = "2026-06-28"

    strings:
        $exif_marker    = { FF E1 }
        $xmp_marker     = "http://ns.adobe.com/xap/" ascii
        $id3_marker     = "ID3" ascii
        $ole_marker     = { D0 CF 11 E0 A1 B1 1A E1 }

        $cmd_backtick   = /`[a-zA-Z\/\\]/ ascii
        $cmd_dollar     = "$(" ascii
        $cmd_pipe       = "| " ascii
        $cmd_semicolon  = "; " ascii
        $cmd_and        = "&& " ascii
        $cmd_redirect   = "> " ascii

        $shell_bash     = "/bin/bash" ascii nocase
        $shell_sh       = "/bin/sh" ascii nocase
        $shell_cmd      = "cmd.exe" ascii nocase
        $shell_cmd2     = "cmd /c" ascii nocase
        $shell_pshell   = "powershell" ascii nocase
        $shell_wscript  = "wscript" ascii nocase
        $shell_cscript  = "cscript" ascii nocase

        $payload_curl   = "curl " ascii nocase
        $payload_wget   = "wget " ascii nocase
        $payload_nc     = "nc -e" ascii nocase
        $payload_ncat   = "ncat " ascii nocase
        $payload_chmod  = "chmod +x" ascii nocase
        $payload_mkfifo = "mkfifo" ascii nocase

    condition:
        ($exif_marker or $xmp_marker or $id3_marker or $ole_marker) and
        (
            1 of ($shell_*) or
            (1 of ($cmd_*) and 1 of ($payload_*))
        )
}
