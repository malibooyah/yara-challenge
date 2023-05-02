rule Titan_Stealer_2023 {
    meta:
        description = "Titan Stealer malware marketed on Telegram in January 2023"
        date = "2023-05-1"
        author = "malibooyah"
        reference = "https://www.uptycs.com/blog/titan-stealer-telegram-malware-campaign"
        hash1 = "e252a54e441ea88aafa694259386afd002153481af25a5b7b2df46d17ac53fcc"
        hash2 = "a7dfb6bb7ca1c8271570ddcf81bb921cf4f222e6e190e5f420d4e1eda0a0c1f2"
        hash3 = "152ef5fcd0278e127c3df415018857f3aed0a748160032356786815ccbe870d5"
        hash4 = "af58e830feef2f4086fb52dafda6084b3b85c6200f4cbc35a5460fb703dd39df"

    strings:
        $f1 = "blockchainlzt_crypted.exe"
        $f2 = "nocrypt.exe"
        $f3 = "Kinchin.exe"
        $f4 = "1128.bin"
        $f5 = "Cubase5.exe"

        $d1 = "t.me/titan_stealer"
        $d2 = "77.73.133.88:5000/sendlog"

    condition:
        any of ($f*)) or any of ($d*)
}