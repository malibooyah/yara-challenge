rule DazzleSpy_MacOs_2022 {
    meta:
        description = "DazzleSpy is a full-featured backdoor that was used in MacOS compromisees"
        date = "2023-05-4"
        author = "malibooyah"
        reference = "https://www.welivesecurity.com/2022/01/25/watering-hole-deploys-new-macos-malware-dazzlespy-asia/"
        hash1 = "7965c61a4581f4b2f199595a6b3f0a416fe49bd8eaac0538e37e050d893f9e3c"
        hash2 = "bbbfe62cf15006014e356885fbc7447e3fd37c3743e0522b1f8320ad5c3791c9"
        hash3 = "f9ad42a9bd9ade188e997845cae1b0587bf496a35c3bffacd20fefe07860a348"

    strings:
        $ip1 = "88.218.192.128"

        $s1 = "osxrk"
        $s2 = "wangping"

        $d1 = "https://amnestyhk.org/ss/defaultaa.html"
        $d2 = "https://amnestyhk.org/ss/4ba29d5b72266b28.html"
        $d3 = "https://amnestyhk.org/ss/mac.js"
        $d4 = "https://amnestyhk.org/ss/server.enc"

    condition:
        any of them
}