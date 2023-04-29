rule RTM_Locker_linux {
    meta:
        description = "RaaS Ransomware being outfitted for Linux - April 2023"
        date = "2023-04-28"
        author = "malibooyah"
        reference = "https://www.uptycs.com/blog/rtm-locker-ransomware-as-a-service-raas-linux"
        hash1 = "55b85e76abb172536c64a8f6cf4101f943ea826042826759ded4ce46adc00638"
        hash2 = "b376d511fb69085b1d28b62be846d049629079f4f4f826fd0f46df26378e398b"
        hash3 = "d68c99d7680bf6a4644770edfe338b8d0591dfe143278412d5ed62848ffc99e0"

    strings:
        $f1 = "name_threads"
        $f2 = "run_esxi_commands"
        $f3 = "pthread_wrapper_main"
        $f4 = "name_thread_routine"
        $f5 = "FUN_00407580"

        $c1 = "esxcli vm process kill -t=force -w"
        
    condition:
       2 ($f*) and ($c1)
}