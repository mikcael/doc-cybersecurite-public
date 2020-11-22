# Commandes Unix

## Linux
### Droits 
Trouver les droits de l'utilisateur
<pre><code>$ sudo -l</pre></code>

Trouver la liste des binaires exécutables en root


    $ find / -perm -u=s -type f 2>/dev/null

### vi
i -> mode insertion
esc -> sortir du mode insertin et retour en mode commande
:wq -> quitter et sauvegarder

### Liens symboliques


    $ ln -s <destination> <fichier>

Le fichier va pointer vers la destination

Pour tenir compte d'un lien symbolique dans un zip:


    $ zip --symlinks <fichier.zip> <fichier>

---
## Python
### Install pip


    $ sudo apt install python3-pip

Installer un module pavec pip


    $ pip3 install <module>


### Mini serveur web
Lance un serveur HTTP disponible depuis la commande wget pour le transfert de fichier
<pre><code>$ python -m SimpleHTTPServer </pre></code>

### Endian
Indique 1 si little endian
<pre><code>$ python -c "import sys;print(0 if sys.byteorder=='big' else 1)"</pre></code>

### Bash
Propose un terminal plus sympa
<pre><code>$ python -c’import pty;pty.spawn("/bin/bash")'</pre></code>

---
## SSH
### Problème de connexion à un nouvel host
vider le fichier /root/.ssh/known_hosts ?


    sudo ssh-keygen -f "/home/kali/.ssh/known_hosts" -R "IP_cible"

---
## HTTP
### Redirection observée sur nmap
ajouter le host sur /etc/hosts

### nmap nous retourne la présence de git
dump & extract avec GitTools

### Client distant ne se connecte pas à un serveur local
* Aller sur la box (http://192.168.1.1)
* pass admin = 8 premiers caractères de la clé WPA sur Livebox
* Attribuer une adresse statique à l'hôte du serveur dans les réglages DHCP (Réseau)
* Ajouter une redirection de port dans le menu NAT

### LDAP null bind
Recherche dans LDAP avec ldpsearch. Exemple:


    $ ldapsearch -x -h challenge01.root-me.org -p 54013 -b "ou=anonymous,dc=challenge01,dc=root-me,dc=org" -LLL
