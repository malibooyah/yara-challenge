rule NimbleMamba_Feb_22 {
    meta:
        description = "Phishing attack that leads to NimbleMamba malware"
        date = "2023-04-27"
        author = "malibooyah"
        reference = "https://www.proofpoint.com/us/blog/threat-insight/ugg-boots-4-sale-tale-palestinian-aligned-espionage"
        hash1 = "430c12393a1714e3f5087e1338a3e3846ab62b18d816cc4916749a935f8dab44"
        hash2 = "c61fcd8bed15414529959e8b5484b2c559ac597143c1775b1cec7d493a40369d"
        hash3 = "925aff03ab009c8e7935cfa389fc7a34482184cc310a8d8f88a25d9a89711e86"
        hash4 = "2E4671C517040CBD66A1BE0F04FB8F2AF7064FEF2B5EE5E33D1F9D347E4C419F"
    strings:
        $ip1 = "api.ipify.com"
        $ip2 = "myexternalip.com"
        $ip3 = "ip-api.com"
        $ip4 = "api.ipstack.com"

        $d1 = "uggboots4sale.com"
        $d2 = "dropboxapi.com"
    condition:
        any of (ip*) and any of (d*)
}