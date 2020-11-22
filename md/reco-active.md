# Reconnaissance active

La reconnaissance active va permettre d'obtenir des informations en s'attaquant directement à la cible, via des scans de port, de répertoire ...

## Scan réseau
### netdiscover
Permet de scanner un réseau en restant invisible.
En mode actif
<pre><code>netdiscover -r 192.168.0.0/24</pre></code>
En mode passif
<pre><code>netdiscover -r 192.168.0.0/24 -p</pre></code>

### nmap
nmap permet la découverte des hôtes sur le réseau
<pre><code>nmap -sP 192.168.1.0/24</pre></code>
Quelques options possibles:
* sP : scan ping
* sL : utilise la résolution DNS inverse
---
## Scan de port
### nmap
Permet de scanner les ports ouverts et d'obtenir les bannières des services:
<pre><code>nmap -v -sS -A 192.168.1.1</pre></code>

Quelques options possibles:
* v : verbose
* sS : SYN Scan (discret)
* sU : Scan UDP a ne pas oublier -sUV pour résultat avec version. L'option -sV ajoutera de la précsion au scan UDP
* A : récupère les banières
* Pn : ne passe pas par le protocole ICMP, intéressant sur internet, pas forcément sur un réseau local
* -oX <filename>  enregistre le résultat dans un fichier xml

Sur metasploit, utiliser db_nmap pour stocker le résultat dans la base de données.


    msf > db_nmap -v -sS -A <@cible> // résultats stocké en BD
    msf > db_hosts // affiche les OS des hosts scannés
    msf > db_services // affiche les services scannés
    msf > db_import <filename> // importe les résultats contenus dans un fichier xml

Il faut bien garder en tête que sur un réseau d'entreprise, un certain nombre de dispositions anti-nmap sont prises. Tout comme les scanners de vulnérabilités qui s'avèrent très bruyants.

### Metasploit et TCP IDLE SCAN
Scan via nmap de port TCP furtif qui permet d'utiliser l'adresse d'origine d'une autre machine connectée sur le réseau.
ce scan peut être utilisé derrière un NAT pour le contourner et accéer à un réseau privé si on a déjà exploité une des machines de ce réseau.
code

    msf > search ipidseq
    msf > use auxiliary/scanner/ip/ipidseq
    msf > show options
    msf > set RHOSTS 192.168.182.0/24 // adresse du sous réseau et de son masque
    msf > set THREADS 5 // rapidité du scan
    msf > exploit // lance l'exploit
       // @ IPID sequence class : Incremental ==> machine inactive  
       // @ IPID sequence class : All zeros ==> machine active sur le réseau  
    msf > namp -Pn -sI <@machine éteinte> <@cible> // -sI = idle scan zombie
    msf > back // sort du module

### Metasploit et SYN SCAN


    msf > search portscan
    msf > use auxiliary/scanner/portscan/syn
    msf > show options
    msf > set RHOSTS <@cible>
    msf > exploit
        // trouve tous les ports TCP ouverts
    msf > back

### OpenVAS
Scanner gratuit fork de nessus.



    msf > load openvas
    msf > openvas_connect test test 127.0.0.1 ok // ok pour pas d'authentification SSH
    msf > openvas_report_list // pour avoir la liste des rapports déjà traités
    msf > openvas_report_import <id> 11 (pour l'import xml)
    
### Autre scanners
Nessus, Nexposure avec GUI et génération de rapport.

---
## Scan de répertoire
### dirb
dirb est un scanner de répertoire basé sur un serveur web basé sur un dictionnaire paramètrable si nécessaire.
<pre><code>dirb http://adressedelavictime.com</pre></code>

---
## Scan sur protocole SMB
### smbclient
smbclient permet de scanner les répertoires partagés sur le réseau via protocole SMB
<pre><code>smbclient -L //@IP -N</pre></code>
<pre><code>smbclient -L \\\\@IP\\</pre></code>

### nmblookup
Permet de scanner les hostname dispo sur le réseau smb
<pre><code>nmblookup -A @IP</pre></code>

---
## CMS
### wpscan
Permet d'obtenir la liste des users sur une install wordpress
<pre><code>wpscan --url http://nomDeDomaine/ --enumerate p --enumerate t --enumerate u</pre></code>