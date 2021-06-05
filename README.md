```
 __    __       _____  _____  __          _        __ 
/ / /\ \ \/\  /\\_   \/__   \/__\/\/\    /_\    /\ \ \
\ \/  \/ / /_/ / / /\/  / /\/_\ /    \  //_\\  /  \/ /
 \  /\  / __  /\/ /_   / / //__/ /\/\ \/  _  \/ /\  / 
  \/  \/\/ /_/\____/   \/  \__/\/    \/\_/ \_/\_\ \/  
		                                                  
                  _      __    ___                    
                 /_\    /__\  / _ \                   
                //_\\  / \// / /_)/                   
               /  _  \/ _  \/ ___/                    
               \_/ \_/\/ \_/\/                        
		                                                  
      	 __      __ _____  ___  ___  __  __            
      	/ _\  /\ \ \\_   \/ __\/ __\/__\/__\           
      	\ \  /  \/ / / /\/ _\ / _\ /_\ / \//           
      	_\ \/ /\  /\/ /_/ /  / /  //__/ _  \           
      	\__/\_\ \/\____/\/   \/   \__/\/ \_/   
    [---]   Whiteman ARP Spoof Detector.  [---]
    [---]     Created by: Hari Sundar	    [---]
		               Version: 0.1
     Welcome to the Whiteman ARP Sniffer Toolkit.
```
##LAHTP ARP Spoof Detector v0.1 (linux)
This tool will sniff for ARP packets in the interface and can possibly detect if there is an ongoing ARP spoofing attack. This tool is still in a beta stage.
```
		                  Available arguments: 
|------------------------------------------------------------------|
|-h or --help:			Print this help text.                          |
|-l or --lookup:		Print the available interfaces.                |
|-i or --interface:		Provide the interface to sniff on.           |
|-v or --version:		Print the version information.    n            |
|------------------------------------------------------------------|

Usage: ./a.out -i <interface> [You can look for the available interfaces using -l/--lookup]
```
##How to compile?
 1.You should have libpcap installed on your linux system. If you don't have, you can do it with the following command
```
$ sudo apt-get install libpcap-dev
```
 2.You can compile with the following command
```
$ gcc arpsniffer.c -o arpsniffer -lpcap
```
