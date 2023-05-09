rule BlueNoroff_MOTW_2023 {
    meta:
        description = "XLS file with malicious macros used to communicate with C2"
        date = "2023-05-8"
        author = "malibooyah"
        reference = "https://securelist.com/bluenoroff-methods-bypass-motw/108383/#_ftn1"
        hash1 = "79de30973b69aa4c44574a512e7820cc0a00f1241930ea361b7b0afcb1cccf2d"
        hash2 = "5f4f006bfb9136c304e0aabf75575360120d022567180ce6b9c1835e209c541e"
        hash3 = "f14c5bad5219b1ed5166eb02f5ff08a890a181cef2af565f3fe7bcea9c870e22"

    strings:
        $s1 = "cr.dat"
        $s2 = "regsile.exe"
        $s3 = "Job_Description.vhd"
        $s4 = "Password.txt.lnk"

        $ip1 = "104.168.249.50"
        $ip2 = "152.89.247.87"
        $ip3 = "104.168.174.80"
        $ip4 = "172.86.121.130"

        $d1 = "bankofamerica.us.org"
        $d2 = "avid.lno-prima.lol"
        $d3 = "azure-protection.cloud"

    condition:
        any of them
}