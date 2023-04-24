rule WhisperGate_Jan_2022 {
    meta:
        description = "WhisperGate "
        date = "2023-04-24"
        author = "malibooyah"
        reference = "https://www.crowdstrike.com/blog/technical-analysis-of-whispergate-malware/"
        hash1 = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"
        hash2 = "44ffe353e01d6b894dc7ebe686791aa87fc9c7fd88535acc274f61c2cf74f5b8"
        sha1_1 = "189166d382c73c242ba45889d57980548d4ba37e"
        sha1_2 = "16525cb2fd86dce842107eb1ba6174b23f188537"
        sha1_3 = "b2d863fc444b99c479859ad7f012b840f896172e"
        sha1_4 = "a67205dc84ec29eb71bb259b19c1a1783865c0fc"
    strings:
        $s1 = "Tbopbh.jpg"
        $s2 = "https://cdn.discordapp.com/attachments/928503440139771947"
        $s3 = "Frkmlkdkdubkznbkmcf.dll"
        $s4 = "zx_fee6cce9db1d42510801fc1ed0e09452.dll"
        $s5 = "Waqybg"
    condition:
        filesize < 1000KB any of them
}
