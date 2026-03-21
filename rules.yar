rule SuspiciousTextFile
{
    strings:
        $a= "malware" nocase
        $b = "virus" nocase
        $c = "trojan" nocase
        $d = "suspicious" nocase
        $e = "hack" nocase

    condition:
        any of ($a, $b, $c, $d, $e)
}
