# Le syteme de fichiers Unix

Sous Unix, tout est fichier.

## Arborescence

### `/`

Option | Description 
:-: |:-
/bin | Exécutables systèmes mis à dispo des utilisateurs
/boot | Eléments indispensables au démarrages comme le noyau par exemple
/dev | Points d'accès aux divers périphériques
/etc | Fichiers de configurations du systèmes
/export | Répertoire des partages réseaux
/home | Répertoires des utilisateurs
/lib | Librairies communes utilisées par le système. `/lib/modules/<noyau>` contient les modules du noyau
/lost+found | i-node non recouvrable lors d'un fsck
/mnt | Utilisé pour monter les périohériques comme les disques amovibles
/opt | Répertoire d'installation des produits tiers
/proc | Système de fichier virutel contenant les infos sur le système. Par exemple /proc/pci contient les infos sur les périphériques pci
/root | Répertoires administrateur
/sbin | Exécutables système réservés aux super-utilisateurs
/tmp | Stockage de fichiers temporaires. Répertoire accessible à tous
/usr | Exécutables, librairies et autres non systèmes accessibles aux utilisateurs
/var | Répertoire de fichiers variables en taille notamment, comme les mails, les logs ....

### `/usr`
Option | Description 
:-: |:-
/bin | Exécutables utilisateurs
/include | Contient les headers utilisateurs nécessaires à la recompilation
/lib | Librairies utilisées par les exécutables utilisateurs
/local | Exécutables, fichiers de configurations... installés par les utilisateurs
/man | Pages de manuels 
/sbin | Exécutables non-système réservés aux super-utilisateurs
/share | Contient des éléments partagées par les différents utilisateurs
/src | Fichiers sources à compilés, appartiennent à l'admin

### `/var`
Option | Description 
:-: |:-
/log | Contient tout les logs systèmes
/mail | Contient les emails utilisateurs
/spool | Contient les fichiers en attentes (mail à envoyer, impression ...)
/cron | Automatisation des tâches, cron étant un démon permettant l'exécution de tâches périodiques

---
## Fichiers sensibles

### Authentification
`/etc/passwd` lisible par tous. Chaque ligne correspond à un utilisateur et comprend les champs suivants séparés par `:`:
1. nom
2. mdp hashé ou `x` si dans fichier `shadow`. `*` invalide le compte
3. uid
4. gid
5. gecos, informatif, suivant l'OS
6. home
7. shell de commande

`/etc/group` lisible par tous. Une ligne par groupe et comprend les champs suivants séparés par `:`:
1. nom du groupe
2. mot de pass, `x` si dans gshadow
3. gid
4. liste des users appartenant au groupe par noms

`/etc/shadow` lisible seulement par le système. Chaque ligne correspond à un utilisateur et comprend les champs suivants séparés par `:`:
1. nom
2. mdp hashé. `*` invalide le compte
3. dernier changement
4. autorisation de changement de passe
5. mot de passe doit être changé
6. avertissement user mdp à changer
7. compte invalidé après expiration
8. compte expiré
9. réservé

`/etc/gshadow/` lisible seulement par le système.Une ligne par groupe et comprend les champs suivants séparés par `:`:
1. nom
2. mdp hashé
3. admin du groupe 
4. membres du groupe

Autres fichiers intervenants dans l'authentification:
* `/etc/securetty` : point de connexions autorisé pour root
* `/etc/shells` : shells autorisés
* `/etc/login.defs` : config des exécutables de la suite login
* `/etc/nologin` : si présent, interdit la connexion autre que root

### sudo
`/etc/sudoers` contient la configuration de la commande `sudo`

### cron
`/etc/crontab` contient la configuration globale de `cron`

`/var/spool/cron/<user>` va contenir les éléments et scripts spécifique à un utilisateur.

Afficher crontab:

    $ crontab -l
Effacer crontab:

    $ crontab -r
Lancer l'éditeur crontab:
    
    $ crontab -e

### sysctl
`/etc/sysctl.conf` contient l'initalisatin de la commande `sysctl`permettant la modification de paramètre kernel

Affiche la valeur d'un variable:
    
    $ sysctl <variable>
Voir toutes les variables:
    
    $ sysctl -a 
Modifier une valeur :
    
    $ sysctl -w <variable>=<valeur>


### DNS

`/etc/hosts` permet d'associer des adresses IP et des noms d'hôtes. Dans celui-ci, on peut gérer des redirection.

`/etc/host.conf` défini l'ordre de recherche des noms DNS. `order hosts, bind` : regarde d'abord dans le fichier /etc/hosts puis ensuite on interroge le serveur DNS.

`/etc/nsswitch.conf` peut également définir l'ordre de recherche des noms DNS (`hosts: files dns`). 

`/etc/resolv.conf` pour la résolution du DNS : 
* `nameserver <adresse IP>` : Spécifie l'adresse IP des serveurs DNS
* `search <domaine>` : Spécifie les domaines de recherche de noms DNS 

### syslog
`/etc/syslog.conf` configure la commande syslog permettant de centraliser les logs systèmes et les redirige dans les bons fichiers. 

`logrotate` est lancé par cron et va géré les fichiers de log en fonction de leur taille en créant des sauvegarde. Configurable ici : `/etc/logrotate.conf`.

---
## Les logs
Les logs systèmes se trouvent dans `/var/log`. On peut les exploiter comme suit.

Afficher les logs par ordre chronologique:

    $ ls -lrt /var/log
Voir "en direct" des logs (tail -f):

    $ tail -f /var/log/auth.log
Avoir les 20 dernières lignes d'un fichier log:

    $ tail -n 20 /var/log/messages
Rechercher dans le texte facilement avec less:

    $ tail -n 20 /var/log/messages |less
Rechercher un paquet en particulier:

    $ grep -R <nom_du_paquet> /var/log/*
En incluant les logs compressés sous forme de fichiers .gz:

    $ zgrep <nom_du-paquet> /var/log/*
"grepper" une commande grep:

    $ grep -r <str> /var/log/* | grep erreur
Et avec une commande d'exclusion (grep -v => À l'exclusion de):

    $ grep -r <str> /var/log/* | grep -v <cmd-exclu>
Trouver dans quels fichiers de logs se trouve la chaine "str" (-r recursive, -i insensible à la "casse", -l n'affiche pas tous les résultats, seulement le nom des fichiers):

    $ grep -r -i -l 'str' /var/log/
Pour conserver le résultat des recherches dans un fichier (/tmp/ma_recherche_str.log):

    $ grep -r -i -l 'str' /var/log/ > /tmp/ma_recherche_str.log
Avoir les 20 dernières lignes d'une recherche avec grep:

    $ grep -r "str" /var/log/* | tail -n 20


les logs:

Fichier | Description 
:-: |:-
/var/log/alternatives.log|Les logs d'update-alternatives.
/var/log/apache2/*|Les logs du serveur http apache2.
/var/log/apt/*|Les logs d'apt. Tous les paquets installés avec apt-get install, par exemple.
/var/log/aptitude|Les logs d'aptitude. Contient toutes les actions demandées, même les abandonnées.
/var/log/auth.log|Les informations d'autorisation de système. Y sont consignées toutes les connexions (réussies ou pas) et la méthode d'authentification utilisée.
/var/log/bind.log|Les logs du serveur de nom bind9, s'il sont activés.
/var/log/boot.log|Les informations enregistrées lors du démarrage du système. Ce fichier n'est pas activé par défaut.
/var/log/btmp|Semblable à /var/log/wtmp. Affiche les connexions/déconnexions au système # lastb alors que # last lira le fichier /var/log/wtmp.
/var/log/cups/*|Les logs du système d'impression cups.
/var/log/cron|Les informations sur les tâches cron. Enregistrement à chaque fois que le démon cron (ou anacron) commence une tâche.
/var/log/daemon.log|Les informations enregistrées par les différents daemons (processus) de fond qui fonctionnent sur le système.
/var/log/debug|Les logs de debugging.
/var/log/dmesg|Les messages du noyau Linux depuis le démarrage.
/var/log/dpkg.log|Les informations sur les paquets installés ou retirés en utilisant la commande dpkg.
/var/log/fail2ban.log|Les Ban/Unban et infos sur le programme (Error, Info, etc.) si fail2ban est installé.
/var/log/faillog|Les échecs de connexion. # faillog -u root.
/var/log/kern.log|Les informations enregistrées par le noyau. Utile pour débogguer un noyau personnalisé, par exemple.
/var/log/lastlog|Les informations de connexion récente de tous les utilisateurs. Ce n'est pas un fichier ascii. Vous devez utiliser la commande lastlog pour afficher le contenu de ce fichier.
/var/log/mail.*|Les informations du serveur de messagerie. Par exemple, sendmail enregistre des informations sur tous les éléments envoyés dans ces fichiers.
/var/log/messages|Les messages du système, y compris les messages qui sont enregistrés au démarrage. Beaucoup de choses sont enregistrées dans /var/log/|messages y compris le courrier, cron, daemon, kern, auth, etc.
/var/log/syslog|Tous les messages, hormis les connexions des utilisateurs. Plus complet que /var/log/messages.
/var/log/user.log|Les informations sur tous les journaux de niveau utilisateur.
/var/log/wtmp|Toutes les connexions et déconnexions: last -f /var/log/wtmp.
/var/log/Xorg.x.log|Les messages du serveur X. N'existe pas sur un serveur.Le petit x est le N° d'instance du serveur X.

source [ici](https://wiki.debian-fr.xyz/Consulter_les_logs_:_quoi,_où_et_comment_chercher_%3F).