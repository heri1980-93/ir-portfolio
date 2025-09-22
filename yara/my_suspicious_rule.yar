// my_suspicious_rule.yar
// Example YARA rule for portfolio demonstrating detection of obfuscated PowerShell and suspicious payload names

rule Suspicious_PowerShell_And_Payload
{
    meta:
        author = "Heriberto Hernandez"
        description = "Detects likely obfuscated/encoded PowerShell command lines and a sample suspicious payload filename"
        date = "2025-09-22"
        license = "CC0"

    strings:
        // Powershell EncodedCommand or -enc usage
        $ps_enc = /powershell(?:\.exe)?\s+-(?:enc|EncodedCommand)\b/i

        // Long Base64-like strings (heuristic)
        $base64_like = /[A-Za-z0-9+\/=]{50,}/

        // Example suspicious payload filename often used in labs
        $payload_name = "evilpayload.exe"

        // Suspicious downloaders or web-based execution strings
        $iwr = /Invoke-WebRequest|IEX\s+\(/i

    condition:
        any of ($ps_enc, $base64_like, $payload_name, $iwr)
}
