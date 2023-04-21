rule lockbit_mac_os {
    meta:
        description = "Lockbit ransomware goes for MacOS"
        author = "malibooyah"
        date = "2023-04-21"
        sha1 = "2D15286D25F0E0938823DCD742BC928E78199B3D"
        hash1 ="3e4bbd21756ae30c24ff7d6942656be024139f8180b7bddd4e5c62a9dfbd8c79"
    strings:
        $s1 = "lockbit"
        $s2 = "locker"
        $s3 = "bSelfRemove"
        $s4 = "restore-my-files.txt"
    condition:
        2 ($s)
}
