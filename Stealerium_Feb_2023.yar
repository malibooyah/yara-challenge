rule Stealerium_Feb_2023 {
    meta:
        description = "Stealerium malware through Office files, in this case a powerpoint"
        date = "2023-05-2"
        author = "malibooyah"
        reference = "https://www.uptycs.com/blog/understanding-stealerium-malware-and-its-evasion-techniques"
        hash1 = "9a08bc42590ac64927b41f225a79a84fc58bfcfa215d27bc09cfd19137615847"
        hash2 = "aa6f6cfb3b3c0f0deb2f55c2dc70f0c4f99822e75de3d90162726ee243491f9d"
        hash3 = "9d1df1a2d1b9dcd2de2a8bbbd6cf067f75c7349aa2b2a79a08793b7379e2b85a"
        hash4 = "bd75d5bfd4d0a32ec2dc8aaef90381b29381089676f129b46969b6920818fb19"

    strings:
        $s1 = "Startup\Drivers.js"
        $s2 = "Startup\OneDriveUpdate.js"
        $33 = "Startup\OutlookUpdate.js"

        $f3 = "CypherDeptography"
        $f4 = "Drivers.js"
        $f5 = "OneDriveUpdate.js"
        $f6 = "OutlookUpdate.js"

        $d1 = "blogspot.com/atom.xml"
        $d2 = "mediafire.com/file/1tmrvg4sh6qpfy7/2.txt/file"

    condition:
        any of them
}