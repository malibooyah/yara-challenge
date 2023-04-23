rule 3CX_Comp_win {
    meta:
        description = "Qbot OneNote March 2023"
        date = "2023-04-22"
        author ="malibooyah"
        reference = "https://www.crowdstrike.com/blog/qakbot-ecrime-campaign-leverages-microsoft-onenote-for-distribution/"
        hash1 = "a28b68f86f05e14d671c1b43bbc662f8d502eb6955091c88af3750cfb4690685"
        hash2 = "701f9ce1be9a1eccda5834f50dec1f441da779ddf7849cc1cc82bb14b6749cba"
        hash3 = "921768f68be2be43a13cf7ea14335ff8e558c080c35993cff86dc512d0e2649f"
        hash4 = "e0190656edb0014add7f2ab99373d2e6495f4e20cd3f51aad5a94ca52cb72b5f"
    strings:
        $s1 = "DocumentsFolder_637695"
        $s2 = "HKCU\SOFTWARE\cqptlz\ug9o\b8kvyy"
    condition:
        any of them
}
