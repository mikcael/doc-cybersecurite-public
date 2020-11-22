# Tools

Tool|Catégorie|liens
:-|:-|:-
Pentester framework|pentester framework |https://github.com/trustedsec/ptf
Red Baron|Automatisation du plus compliqué| https://github.com/coalfire-Research/Red-Baron
Metasploit|Framework de pentest| https://github.com/rapid7/metasploit-framework/commits/master
Unicorn|payload obfuscator|https://github.com/trustedsec/unicorn
Cobalt Strike|Postexploitation|http://www.cobaltstrike.com
Powershell Empire|Postexploitation|https://github.com/EmpireProject/Empire
dnscat2|Canal C2|https://github.com/iagox86/dnscat2
p0wnedShell|App hôte powershell|https://github.com/Cn33liz/p0wnedShell
Pupy|Postexploitation & remote admin|https://github.com/nunj4sec/pupy
PoshC2|Framwork C2|https://github.com/nettitude/PoshC2
Merlin|Postexploitation HTTP/2|https://github.com/Ne0nd0g/merlin
Nishang|Framework & payloads PowerShell|https://github.com/samratashok/nishang
Masscan|Scanner|https://github.com/robertdavidgraham/masscan
HTTPScreenshot|Capture Web|https://github.com/breenmachine/httpscreenshot
EyeWitness|CaptureWeb|https://github.com/ChrisTruncer/EyeWitness
Shodan|Service scanner host internet|https://www.shodan.io
Censys.io|Service scanner host internet|https://censys.io
Censys| accessible depuis un script|https://github.com/christophetd/censys-subdomain-finder
sslScrape|San hôtes dans certificats SSL|https://girhub.com/cheetz/sslScrape
Discovery Scripts|Reconnaissance|https://github.com/leebaird/discover
Subslist3r|scanner ss domaine vis google dorks|https://github.com/Plazmaz/Sublist3r
SubBrute|scanner sous domaines avec un peu d'anonymat|https://github.com/TheRook/subbrute
Truffle Hog|Scanner de git à la recherche d'info dans les repo
git-all-secrets|Scanner de git à la recherche d'info dans les repo|https://github.com/anshumanbh/git-all-secrets
slurp|Enumeration de compartiment S3
Bucket finder|Enumeration de compartiment S3
SimplyEmail|Liste de mail basé sur des recherches de moteurs de recherche
OSINT|Collections de liens|https://github.com/IVMachiavelli/OSINT_Team_Links
OSINT|Framework OSINT|http://osintframework.com
Wappalyzer|Analyse techno web|https://wappalyzer.com
builtwith|Analyse techno web|https://builtwith.com
Retire.JS|Scan fwk js vulnerable|https://bit.ly/2sQVNpN
BurpSuite|Proxy Pentest|https://portswigger.net/burp
ZAP|Proxy Pentest|https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project
Dirbuster|Site files discovery|
GoBuster|Site files discovery|https://github.com/OJ/gobuster
BeEF|framework exploitation XSS|https://beefproject.com
XSS Hunter|Blind XSS|https://xsshunter.com
Webshell||https://github.com/tennc/webshell /!\ non testé
dencoder|URL encoder/decoder|http://meyerweb.com/eric/tools/dencoder/
PayloadsAllTheThings|Payloads framework|https://github.com/swisskyrepo/PayloadsAllTheThings
SSRFMap|Exploit SSRF|https://github.com/swisskyrepo/SSRFmap
ysoserial|gadget payload for unserialization|https://github.com/frohoff/ysoserial.
TplMap|Injection de template|https://github.com/epinna/tplmap
pwndb|Scan passwd|https://github.com/davidtavarez/pwndb
Kali Anonymous|Kali Anonymous|https://github.com/keeganjk/kali-anonymous

## Wifi Kali 2020
https://github.com/lwfinger/rtlwifi_new/tree/rtw88

    sudo apt-get update
    sudo apt-get install make gcc linux-headers-$(uname -r) build-essentials git
    git clone https://github.com/lwfinger/rtlwifi_new.git -b rtw88
    cd rtlwifi_new
    make
    sudo make install
    sudo modprobe -r rtw_8723de         #This disable the module
    sudo modprobe rtw_8723de            #This enables the module, you can add options like ant_sel=2

## wordlist
sous domaines
* http://bit.ly/2JOkUyj
* http://bit.ly/2qwxrxB
* https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS

## SSH Windows
https://mobaxterm.mobatek.net/download-home-edition.html ou firessh pour firefox

## VM Kali
Kali THP avec tous les outils : thehackerplaybook.com/get.php?type=THP-vm

## Live USB
nom|description|download
:-|:-|:-
kali|Pentest - la plus connu|https://www.kali.org/
backbox|Pentest - une des meilleures. Bésée sur ubuntu|https://backbox.org/
Parrot|Pentest - anonomat et system crypté|https://www.parrotsec.org/
Pentoo|Pentest - Gentoo + persistence|https://www.pentoo.ch/
CAINE|Forensic|http://www.caine-live.net/
DEFT|Forensic|http://www.deftlinux.net/
Hiren|Windows admin tools|https://www.hirensbootcd.org
SystemRescueCD|Gentoo - Admin|http://www.system-rescue-cd.org/
