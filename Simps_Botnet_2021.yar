rule Simps_Botnet_2021 {
    meta:
        description = "DazzleSpy is a full-featured backdoor that was used in MacOS compromisees"
        date = "2023-05-7"
        author = "malibooyah"
        reference = "https://www.uptycs.com/blog/discovery-of-simps-botnet-leads-ties-to-keksec-group"
        hash1 = "c2d5e54544742b7a1b04cf45047859a10bb90c6945d340120872f575aa866e6d"
        hash2 = "e847dfbd831df6015519d03d42ada8241ce1174e9bd96f405452627617229c63"
        hash3 = "f9ad42a9bd9ade188e997845cae1b0587bf496a35c3bffacd20fefe07860a348"

    strings:
        $ip1 = "23.95.80.200"

        $s1 = "ur0a.sh"
        $s2 = "wangping"
        $s3 = "Infected By Simps Botnet" ascii wide nocase
        $s4 = "keksec.infected.you.log"
        $s5 = "b0tz.xyz"
        $s6 = "KEKSEC"

    condition:
        any of them
}