rule MacStealer_Feb_22 {
    meta:
        description = "Phishing attack that leads to NimbleMamba malware"
        date = "2023-04-29"
        author = "malibooyah"
        reference = "https://www.uptycs.com/blog/macstealer-command-and-control-c2-malware"
        hash1 = "9b17aee4c8a5c6e069fbb123578410c0a7f44b438a4c988be2b65ab4296cff5e"
        hash2 = "6a4f8b65a568a779801b72bce215036bea298e2c08ec54906bb3ebbe5c16c712"

    strings:
        $f1 = "weed.dmg"

        $ip1 = "89.116.236.26"

        $d1 = "mac.cracked23.site"
        $d2 = "t.me/macos_stealer_2023"
        $d3 = "t.me/macos_logsbot"
    condition:
        any of them
}