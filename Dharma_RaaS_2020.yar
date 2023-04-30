rule Dharma_RaaS_2020 {
    meta:
        description = "Ransomware as a service seen in April 2020"
        date = "2023-04-30"
        author = "malibooyah"
        reference = "https://www.crowdstrike.com/blog/targeted-dharma-ransomware-intrusions-exhibit-consistent-techniques/"
        hash1 = "9b17aee4c8a5c6e069fbb123578410c0a7f44b438a4c988be2b65ab4296cff5e"
        hash2 = "6a4f8b65a568a779801b72bce215036bea298e2c08ec54906bb3ebbe5c16c712"

    strings:
        $r1 = "reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections"
        $r2 = "REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f"

        $f1 = "PCHunter32.exe"
        $f2 = "PCHunter64.exe"
        $f3 = "Processhacker.exe"
    condition:
        uint16be(0) == 0x4D5A or uint16be(0) == 0x5A4D and 1 ($f*) and 1 ($r*)
}