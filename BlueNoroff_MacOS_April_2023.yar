rule BlueNoroff_MacOS_2023_Stage_1 {
    meta:
        description = "Stage 1 of a phishing campaign targeted for MacOS"
        date = "2023-5-3"
        author = "Daniel Blute"
        hash1 = "b3aaa0ac0741f987fd3808e05f5bdc9c3ea955a1efa8e24864af5b2b8634bfb1"
        hash2 = "83bb34af7ac53059f27d613c0c1543b32ef100d9acc79e0428b086459f617e92"
        hash3 = "57a87ec3dec1ec7b1deae0858661691337edf9b4b29054dcacde9da8c0bb2c85"
        hash4 = "c757f2dfa011f68690f6fd50287d9f50a439454e5813c7ecfe07ab777068ce33"
    strings:
        $f1 = "Huge Risk for Stablecoin"

        $d1 = "31ventures.info"
        $d2 = "hedgehogvc.us"
        $d3 = "zvc.capital"
    condition:
        uint32be(0) == 0xFEEDFACE and any of them
}
