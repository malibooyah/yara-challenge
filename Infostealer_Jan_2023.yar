rule Infostealer_Jan_2023 {
    meta:
        description = "Phsihing invoice attachment malware targetting Italy"
        date = "2023-05-3"
        author = "malibooyah"
        reference = "https://www.uptycs.com/blog/infostealer-malware-attacks-targeting-italian-region/"
        hash1 = "ccfa2a59f817a699433738eb52fef5e6aa236051fa68d6709e7b8a2c576c3de1"
        hash2 = "d3aa8fca03e9eb9911bbb51302d703afa9c04ce94d94ce6c3cd5086999e49471"
        hash3 = "8d4ed7017342c8b737b13f98b95956a5f3d2b2fcfbb921661d93a2c48a916911"

    strings:
        $f3 = "IT_Fattura_n99392.zip"
        $f4 = "Fattura 06-12-2022.lnk"
        $f5 = "Fattura_IT9032003.bat"
        $f6 = "Ejefqnxog.dll"

        $d1 = "116.203.19.97/1/lib32.hta"
        $d2 = "dropboxusercontent.com/s/52eq2p19vc0dcei/IT_Fattura_n99392.zip"

    condition:
        any of them
}