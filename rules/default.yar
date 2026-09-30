rule Suspicious_PowerShell_Encoded_Command
{
    meta:
        description = "Detects PowerShell EncodedCommand/Base64 usage often used to obfuscate malicious scripts"
        severity = "medium"
    strings:
        $a = "-EncodedCommand" nocase
        $b = "-enc " nocase
        $c = "FromBase64String" nocase
    condition:
        any of them
}

rule Suspicious_Disable_Defender
{
    meta:
        description = "Attempts to disable Windows Defender real-time protection"
        severity = "high"
    strings:
        $a = "Disable-RealtimeMonitoring" nocase
        $b = "Set-MpPreference" nocase
    condition:
        all of them
}

rule Suspicious_Reverse_Shell_Indicators
{
    meta:
        description = "Common reverse shell command patterns"
        severity = "high"
    strings:
        $a = "/dev/tcp/" nocase
        $b = "nc -e /bin/sh" nocase
        $c = "bash -i" nocase
        $d = "Invoke-PowerShellTcp" nocase
    condition:
        any of them
}

rule Suspicious_Shadow_Copy_Deletion
{
    meta:
        description = "Ransomware-style shadow copy / backup deletion commands"
        severity = "critical"
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "wbadmin delete catalog" nocase
        $c = "bcdedit /set" nocase
    condition:
        any of them
}

rule Suspicious_Webshell_PHP
{
    meta:
        description = "Common PHP webshell patterns"
        severity = "high"
    strings:
        $a = "eval(base64_decode(" nocase
        $b = "eval($_POST" nocase
        $c = "eval($_GET" nocase
        $d = "system($_REQUEST" nocase
        $e = "passthru($_" nocase
    condition:
        any of them
}

rule EICAR_Test_File
{
    meta:
        description = "Standard antivirus EICAR test file signature"
        severity = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
