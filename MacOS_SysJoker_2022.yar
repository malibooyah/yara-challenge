rule SysJoker_MacOs_2022 {
    meta:
        description = "SysJoker is a malware used for MacOS(and other OS) backdoors"
        date = "2023-05-5"
        author = "malibooyah"
        reference = "https://www.intezer.com/blog/incident-response/new-backdoor-sysjoker/"
        hash1 = "1a9a5c797777f37463b44de2b49a7f95abca786db3977dcdac0f79da739c08ac"
        hash2 = "fe99db3268e058e1204aff679e0726dc77fd45d06757a5fda9eafc6a28cfb8df"
        hash3 = "d0febda3a3d2d68b0374c26784198dc4309dbe4a8978e44bb7584fd832c325f0"

    strings:
        $s1 = "types-config.ts"
        $s2 = "/Library/MacOsServices"
        $s3 = "/Library/MacOsServices/updateMacOs"
        $s4 = "/Library/SystemNetwork"
        $s5 = "/Library/LaunchAgents/com.apple.update.plist"

        $d1 = "https://bookitlab.tech"
        $d2 = "https://winaudio-tools.com"
        $d3 = "https://graphic-updater.com"
        $d4 = "https://github.url-mini.com"
        $d5 = "https://office360-update.com"
        $d6 = "https://drive.google.com/uc?export=download&id=1-NVty4YX0dPHdxkgMrbdCldQCpCaE-Hn"
        $d7 = "https://drive.google.com/uc?export=download&id=1W64PQQxrwY3XjBnv_QAeBQu-ePr537eu"

    condition:
        any 3 of ($s*) or any of ($d*)
}