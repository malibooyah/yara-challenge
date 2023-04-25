rule Trader_Traitor {
    meta:
        description = "North Korean Mac OS backdoor Trader Traitor NukeSped"
        date = "2023-04-25"
        author = "malibooyah"
        reference = "https://objective-see.org/blog/blog_0x6E.html"
        hash1 = "60b3cfe2ec3100caf4afde734cfd5147f78acf58ab17d4480196831db4aa5f18"
        hash2 = "5b40b73934c1583144f41d8463e227529fa7157e26e6012babd062e3fd7e0b03"
        hash3 = "f0e8c29e3349d030a97f4a8673387c2e21858cccd1fb9ebbf9009b27743b2e5b"
        hash4 = "9ba02f8a985ec1a99ab7b78fa678f26c0273d91ae7cbe45b814e6775ec477598"
        hash5 = "dced1acbbe11db2b9e7ae44a617f3c12d6613a8188f6a1ece0451e4cd4205156"
        hash6 = "89b5e248c222ebf2cb3b525d3650259e01cf7d8fff5e4aa15ccd7512b1e63957"
    strings:
        $f1 = "DAFOM-1.0.0.dmg" 
        $f2 = "TokenAIS.app.zip"
        $f3 = "CryptAIS.dmg"
        $f4 = "Esilet.dmg"
        $f5 = "Esilet-tmpzpsb3"
        $f6 = "Esilet-tmpg7lpp"
        $f7 = "darwin64.bin"
        $f8 = "Esilet.app"

        $d1 = "esilet.com/update/"

    condition:
        any of them
}
