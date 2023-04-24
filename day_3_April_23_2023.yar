rule part_ticket_feb_2023 {
    meta:
        description = "Go-based ransomware dubbed PartyTicket or HermeticRansom"
        date = "2023-04-23"
        author = "malibooyah"
        reference = "https://www.crowdstrike.com/blog/how-to-decrypt-the-partyticket-ransomware-targeting-ukraine/"
        hash = "4dc13bb83a16d4ff9865a51b3e4d24112327c526c1392e14d56f20d6f4eaf382"

    strings:
        $f1 = "cdir.exe"
        $f2 = "cname.exe"
        $f3 = "intpub.exe"

        $s1 = "primaryElectionProcess"
        $s2 = "403forBiden"
        $s3 = "voteFor403"

    condition:
        any ($f) and 2 of ($s*)
}
