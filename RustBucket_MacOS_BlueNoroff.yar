rule RustBucket_April_2023 {
    meta:
        description = "North Korean MacOS PDF malware"
        date = "2023-04-26"
        author = "malibooyah"
        reference = "https://www.jamf.com/blog/bluenoroff-apt-targets-macos-rustbucket-malware/"
        hash1 = "0be69bb9836b2a266bfd9a8b93bb412b6e4ce1be"
        hash2 = "ca59874172660e6180af2815c3a42c85169aa0b2"
        hash3 = "7e69cb4f9c37fad13de85e91b5a05a816d14f490"
        hash4 = "182760cbe11fa0316abfb8b7b00b63f83159f5aa"
    strings:
        $s1 = "Internal PDF Viewer.app"
        $s2 = "main.scpt"
        $s3 = "com.apple.pdfViewer"
        $s4 = "InvestmentStrategy(Protected).pdf"  /* VT has the hash with this name */
        $s5 = "DOJ Report on Bizlato Investigation" /* Another PDF name seen */
        $s6 = "Daiwa Ventures.pdf" /* PDF name reported */
        
        $f1 = "_downAndExecute"
        $f2 = "downAndExecute_block_invoke"

        $d1 = cloud.dnx.capital
        $d2 = deck.31ventures.info
    condition:
        any of them
}
