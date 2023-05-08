rule Winter_Vivern_2021 {
    meta:
        description = "XLS file with malicious macros used to communicate with C2"
        date = "2023-05-6"
        author = "malibooyah"
        reference = "https://www.domaintools.com/resources/blog/winter-vivern-a-look-at-re-crafted-government-maldocs/"
        hash1 = "94f45ba55420961451afd1b70657375ec64b7697a515a37842478a5009694cfa"
        hash2 = "2a176721b35543d7f4d9e3d24a7c50e0ea57d7eaa251c6b24985d5266a6a977a"
        hash3 = "f84044bddbd3e05fac1319c988919492971553bb65dbf7b7988d66a8cd677eb8"
        hash4 = "bd1efa4cf3f02cd8723c48deb5f69a432c22f359b93cab4f1d2a9f037a236eaa"
        hash5 = "00f6291012646213a5aab81153490bb121bbf9c64bb62eb4ce582c3af88bccfd"
        hash6 = "638bedcc00c1b1b8a25026b34c29cecc76c050aef56fa55f6e8878e6b951e473"
        hash7 = "c34e98a31246f0903d4742dcf0a9890d5328ba8a1897fcf9cd803e104591ed5f"

    strings:
        $ip1 = "37.252.9.123"
        $ip2 = "37.252.5.133"

        $d1 = "centr-security.com"
        $d2 = "secure-daddy.com"
        $d3 = "securemanage.com"

    condition:
        any of them
}