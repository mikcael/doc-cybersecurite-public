# Reconnaissance passive & OSINT
La reconnaissance passive est la première étape, elle n'est pas en contact direct avec la cible.
La partie OSINT fait partie de la reconnaissance passive, elle correspond à la recherche d'information publique sur le web au sujet de la cible au sens large.

## DNS

### whois
Obtient des infos globales sur le propriétaire d'un nom de domaine.

    $ whois <domain_name>

### netcraft
Permet d'obtenir un peu plus d'informations, notamment l'adresse IP.

Dans le navigateur :

    search.netcraft.com

### nslookup
Recherche également des informations à partir du nom de domaine.

    $ nslookup
    > set type=mx
    > <domain_name>

### dnshistory 
Recense les anciennes entrées des domaines de l'internet.

    https://dnshistory.org

### dnsenum
Permet de récupérer des infos sur un domaine donné (NS, transfert de zone, sous-domaine, serveurs MX, bruteforce DNS, ...)

    $ dnsenum -f subdomains.txt <domain_name> -w

### dnsscan
dispose des mêmes fonctionnalités que dnsenum, mais l'utilisation des deux peut se compléter. Téléchargeable [ici](https://github.com/rbsec/dnscan).

    $ ./dnscan.py -d <domain_name> -w subdomains.txt -r -o dnsscan_result.txt

### Bluto
Récupère les informations DNS et analyse les métadatas des documents disponibles (pour aussi agir en tant que email hunter)

    $ pip install git+git://github.com/darryllane/Bluto

### dig
Permet de travailler sur le nom de domaine:

    $ dig <domain_name>
Permet également de réaliser un transfert de zone:


    $ dig @<dns_server> -p 54011 txt <domain_name>

---
## Systèmes connectés et domaines
### shodan
Moteur de recherche de n'importe quel object connecté sur internet, accède également aux services tournant dessus.
http://shodan.io

### censys
http://censys.io

### creepy
Téléchargeable [ici](https://www.geocreepy.com), outils de géolocalisation.

### Robtek
Donne beaucoup d'info sur un domaine, une IP ....

    https://www.robtex.com

### WayBackMachine 
Permet de remonter le temps et retrouver du contenu web à une certaine periode

    https://archive.org/web/

### host
Permettant d'afficher les redirections DNS et de demander un transfert de zone

    $ host <domain_name>

### locator
Tracker via URL. Téléchargeable [ici](https://github.com/thelinuxchoice/locator).

    $ git clone https://github.com/thelinuxchoice/locator
    $ cd locator
    $ bash locator.sh

### Angry Fuzzer
Récolte d'information. Téléchargeable [ici](https://github.com/ihebski/angryFuzzer).

    $ git clone https://github.com/ihebski/angryFuzzer.git
    $ cd angryFuzzer
    $ python angryFuzzer.py
    $ sudo pip install -r requirements.txt

Exemples:

    $ python angryFuzzer.py -u http://127.0.0.1 
    $ python angryFuzzer.py -u http://127.0.0.1 --cms wp 
    $ python angryFuzzer.py -u http://127.0.0.1 -w fuzzdb/discovery/predictable-filepaths/php/PHP.txt

### r3con1z3r
Téléchargeable [ici](https://github.com/abdulgaphy/r3con1z3r).

    $ pip3 install r3con1z3r
    $ pip3 install win_unicode_console colorama
    $ r3con1z3r -d domain.com

---
## Host Windows
### Responder
Téléchargeable [ici](https://github.com/lgandx/Responder). Responder est un poisoner LLMNR, NBT-NS et MDNS qui va voir passer sur le réseau via un MITM le hash d'une mot de passe Windows.

    ./Responder.py -I eth0 -rPv

---
## Personnes
### webmii
http://webmii.com, méta-moteur de recherche sur une personne.

### Checkusernames 
Lance des recherches sur plusieurs réseaux sociaux

    https://checkusernames.com/

### PeekYou 
Source de renseignements précieux 

    http://www.peekyou.com

### Pipl 
Renseignements précieux et situation géographique

    https://pipl.com/

### skiptracer
Permet de chercher de nombreuses infos. Téléchargeable [ici](https://github.com/xillwillx/skiptracer).

    $ git clone https://github.com/xillwillx/skiptracer.git skiptracer
    $ cd skiptracer
    $ pip install -r requirements.txt
    $ python skiptracer.py

### Have I been pwned
Permet de savoir si user ou un pass ont déjà été hacké.

    https://haveibeenpwned.com

---
## Entreprises
### recon-ng
Recon-ng fonctionne de façon modulaire comme metasploit et permet de récupérer des infos provenant de nombreuses sources du net et des réseaux sociaux.
Permet également de scanner des vulnéravilités sur un site identifié.

    $ recon-ng // lancer recon-ng
    [recon-ng][default] > help // obtenir de l'aide
    [recon-ng][default] > marketplace search // liste des modules dispo
    [recon-ng][default] > marketplace install <modulename> //install un module
    [recon-ng][default] > marketplace load <modulename> // charge un module
    [recon-ng][default][<modulename>] > show options // voir les options dispos pour le module
    [recon-ng][default][<modulename>] > options set SOURCE domain.com
    [recon-ng][default][<modulename>] > info
    [recon-ng][default][<modulename>] > input
    [recon-ng][default][<modulename>] > run
    [recon-ng][default][<modulename>] > show hosts lorsque les hosts sont chargés

    [recon-ng][default] > keys list
    [recon-ng][default] > keys add shodan_api <shodan_api_key> // charger la clé pour shodan
    [recon-ng][default] > marketplace search shodan
    [recon-ng][default] > marketplace install recon/netblocks-hosts/shodan_net
    [recon-ng][default] > modules load recon/netblocks-hosts/shodan_net
    [recon-ng][default][shodan_net] > options set SOURCE 71.6.233.0/24
    [recon-ng][default][shodan_net] > run

### Discover Scripts
Utilise de nombreux outils pour collecter énormement de données. Disponible [ici](https://github.com/leebaird/discover).

### Spiderfoot
http://www.spiderfoot.net
Récupère énormément d'information et se manipule à travers une interface web locale très pratique.

### theHarvester
Cherche les adresses mail d'un nom de domaine à travers les moteurs de recherche.
    
    $ python theHarvester.py -d domain -v -b dnsdumpster
    $ theHarvester -d domain -b google
    $ theHarvester -d domain -b linkedin

### uberharvest
Script analysant un site web pour y retrouver les mails, serveurs et téléphones

    # wget http://ubersec.com/downloads/uberharvest_2_80.tar.bz2
    # bzip2 -cd uberharvest_2_80.tar.bz2 | tar xvf –
    # cd <uberharvest folder>
    # ./setup
    # ./uberharvest -m
Puis rentrer une url.

### CredCatch
Permet d'obtenir beaucoup d'info
https://github.com/pry0cc/CredCatch

### Spraing Toolkit
https://github.com/byt3bl33d3r/SprayingToolkit

### hunter.io
https://hunter.io/ propose la même chose que theHarvester, il faut créer un compte, mais un système d'auto completion permet de préselectionner des entreprises.

### verify-email
http:///www.verify-email.com permet de vérifier si un email existe.

### metagoofil
Outil de collecte d'information conçu pour extraire les métadonnées de documents publics (pdf, doc, xls, ppt, docx, pptx, xlsx) appartenant à une société cible.

### societe.com
Permet d'obtenir des informations sur les sociétés.

    http://www.societe.com

### pagesjaunes
Permet d'obtenir des informations sur les sociétés.

    https://www.pagesjaunes.fr

---
### osintframework.com
Framework complet d'OSINT
http://osintframework.com

### Maltego
Outils permettant de relier des données entre elles issues de différentes plateformes.

### Spiderfoot
SpiderFoot obtient un large éventail d'informations sur une cible, tels que les serveurs Web, netblocks, adresses e-mail et plus encore.

## Téléphone
### phoneInfoga
Téléchargeable [ici](https://github.com/sundowndev/PhoneInfoga), il permet d'obtenir de nombreuses informations sur le numéro de téléphone.

### utils
Création de numéro de redirection temporaire de sms : freesmscode.com
Outils autour des numéros de téléphone : inteltechniques.com

---
### Google dorks
Google index tout ! Il sont donc très importants.
Permettent d'obtenir:
* Des noms d’utilisateurs et les mots de passe
* Des listes d’email
* Des documents sensibles
* Des renseignements personnels, transactionnels ou financiers (PIFI)
* Les vulnérabilités des sites internet, des serveurs ou des plugins

un bon listing [ici](https://www.funinformatique.com/google-dorks-hackez-requete-google/). 

Par exemple:
* + (and) : recherche des pages web regroupant des mots clefs : vuln+exploit
* - (not) : retire une expression de la recherche : vuln - exploit
* | (pipe) considère plusieurs motifs dans la recherche : CVE
* +(exploit | root) la recherche se fera sur les pages contenant CVE et exploit ou root
* "" (guillemet) recherche les expression exacts : "prenom nom"
* .. (double point) permet de rechercher tous les nombres de la plages spécifiée :  bande passante 500..1000 Méga Opérateur avec bande passante entre 500 et 1000

Les opérateurs avancés :

* **site**: recherche les pages du site ou domaine spécifié.
* **Filetype**: recherche par type de fichier. Ex : filetype:.doc
* **Cache**: donne la dernière version de la page web indexée par le robot Google.
* **Related**: renvoie les pages liées à un URL. Ex : related:eni.fr
* **allintext**: restreint la recherche au corps du texte de la page (balise body). Ex. : allintext malware wannacry remonte les pages où on parle du malware wannacry.
* **intext**: fonctionne de la même manière que allintext mais un seul mot peut être recherché. Ex. : intext:wannacry.
* **allintitle**: recherche un ou plusieurs mots dans le titre de la page (balise title).
* **intitle**: même principe mais la recherche n’est possible que sur un seul terme.
* **allinurl**: la recherche s’effectue uniquement sur les URL des pages web pour un ou plusieurs mots.
* **inurl**: même principe pour un seul terme de recherche.
* **stocks**: en indiquant le nom de l’entreprise ou son code action, il permet de suivre le cours de ses actions en bourse. Ex : stocks:nissan
* **info**: donne certaines informations sur le site web passé en argument. Ex : info:eni.fr et donne l’accès à d’autres informations (cache, pages similaires...)

Quelques exemples :

> filetype:txt admin+ (password | passwd) Recherche des fichier text avec les champs

> site: pastebin.com "admin+ (password | passwd)"

Les googles dorks ont eux aussi leur utilités puisqu'ils récupèrent des informations sensibles (il s'agit en fait de requêtes googles avec des opérateurs qui pointent sur de l'information sensibles)
https://www.exploit-db.com/google-hacking-database#