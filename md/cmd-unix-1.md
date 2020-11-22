# Commandes de bases Unix

---
## Filesystem

### Afficher le chemin courant
Afficher le chemin courant:

    $ pwd

### Se déplacer

Se déplacer dans le répertoire `/home/user`:

    $ cd
Se déplacer dans un répertoire:

    $ cd <folder>
Se déplacer dans un réportoire présent dans `home/user`:

    $ cd ~/<folder>
Se déplacer dans le dossier parent:

    $ cd ..

### Explorer un répertoire

Lister un répertoire:

    $ ls -l <folder>

Les options de la commande `ls`:
Option | Description 
:-: |:-
-a|Liste tous les fichiers, incluant les cachés
-d|Liste les répertoires contenus dans le répertoire ciblé
-t|Trie par date depuis les plus récents
-S|Trie par taille depuis les plus gros

### Copier des fichiers

Copier une fichier: 

    $ cp <src> <dest>
Copier un ficher dans un répertoire:

    $ cp <src> <folder>
Copier un répertoire complet:

    $ cp -r <src> <dest>
    ou
    $ rsync -a <src> <dest> 

### Déplacer/renommer

Déplacer un fichier ou un dossier revient au même que le renommer:

    $ mv <old> <new>
Déplacer un fichier dans un répertoire:

    $ mv <file> <folder>
Déplacer un fichier dans un répertoire en le renommant:

    $ m <old> <folder>/<new>

### Créer / Supprimer

Créer un fichier:

    $ touch <file>

Créer un répertoire:

    $ mkdir <folder>
Créer un lien symbolique (s'apparente à un raccourci):

    $ ln -s <file> <link>
Créer des répertoires impriqués:

    $ mkdir -p <folder1>/<folder2>
Pour supprimer un fichier:

    $ rm <file>
Pour supprimer un répertoire:

    $ rmdir <folder>
Forcer la suppression d'un répertoire non vide:

    $ rmdir -rf <folder>

### Comparer

Comparer des fichiers ou répertoires:

    $ diff <file1> <file2>

### Rechercher

Rechercher un fichier dans un répertoire et son arborescence:

    $ find <folder> -name <file>
La commande `locate` permet également de trouver un fichier si le sytème a été indexé.

### Rechercher un contenu de fichier

Rechercher le contenu dans un fichier: 

    $ grep <str> <file>

Rechercher le contenu dans tous les fichiers d'un répertoire:

    $ grep -r <str> <folder>

### Visualiser un fichier

Afficher le contenu d'un fichier:

    $ cat <file>

Afficher le contenu d'un fichier par page:

    $ cat <file> | more

Afficher les n premières lignes d'un fichier:

    $ head -n <file>

Affichier les n denières lignes d'un fichier:

    $ tail -n <file>

### Changer l'utilisateur d'un fichier
Changer l'utilisateur d'un fichier:

    $ chown <user> <file>
Changer l'utilisateur d'un répertoire et sob arborescence:

    $ chown -R <user> <folder>

### Changer le groupe d'un fichier
Changer le groupe d'un fichier:

    $ chgrp <group> <file>

### Changer les droits d'un fichier
Changer les droits d'un fichier:

    $ chmod <perm> <file>

L'argument `<perm>` peut avoir des possibilités comme suit:
Option | Description 
:-: |:-
-R|S'applique sur un répertoire et son arbo
u+x|Donne au user `u` les droits d'éxecution
u-x|Retire au user `u` les droits d'éxecution
g+w|Donne au group `g` les droits d'écriture
o+rx|Donne aux autres les droits de lecture et d'éxecution
a+r|Donne à tout le monde les droits de lecture
+777|Donne tout les droits à tout le monde


### Rediriger entrée et sortie standard

Rediriger la sortie d'une commande dans un fichier:

    $ <command> > <file>
Rediriger la sortie d'une commande à la fin d'un fichier:

    $ <command> >> <file>
Redéiriger la sortie d'une commande vers l'entrée d'une autre

    $ <command1> | <command2>

### Archiver et compresser
Extraire les fichiers d'une archive:

    $ tar xvf <archive>.tar
Extraire les fichiers d'une archive compressée (gzip):

    $ tar xvfz <archive>.tar.gz
Extraire les fichiers d'une archive compressée (bzip2):

    $ tar jxvf <archive>.tar.bz2
Créer une archive avec les fichiers file1 et file2:

    $ tar cvf <archive>.tar <file1> <file2>
Créer une archive avec le répersoire folder et le compressé avec gzip:

    $ tar cvfz <archive>.tar.gz <folder>
Compresser un fichier:
    
    $ gzip <file>
ou
    
    $ bzip2 <file>
Décompresser un fichier:
    
    $ gunzip <file>.gz
ou
    
    $ bunzip2 <file>.bz2

### Gérer les partitions:
Les infos des partitions montées automatiquements sont dans `/etc/fstab`.

Afficher les partitions actives:

    $ fdisk -l
Créer un point de montage pour une clé usb:

    $ mkdir /media/<usbkey>
Monter la partition de la clé usb:

    $ mouns /media/<usbkey>
Monter ou remonter tous les périphériques présents dans `/etc/fstab`:

    $ mount -a
ou

    $ mount -a -o remount
Lancer l'utilitaire de partitionnement du disque:

    $ fdisk /dev/<disk>
Créer un système de fichier (`ext3` ou `fat32`) sur un disk:

    $ mkfs.ext3 /dev/<disk>
ou

    $ mkfs.vfat /dev/<disk>

---
## Users

### Afficher les informations utilisateurs
Afficher les utilisateurs connectés au système:

    $ who
Afficher le nom de l'utilisateur courant:

    $ whoami
Afficher les informations complètes d'un utilisateur:

    $ finger <user>
Afficher le groupe d'un utilisateur:

    $ groups <user>

### Exécuter des commandes d'un autre utilsateur
Exécuter une commande root:

    $ sudo <command>

Exécuter une commande d'un autre utilisateur:

    $ sudo -u <user> <command>
ou

    $ su <user> -c <command>
Passer en mode root:

    $ su
Changer d'utulisateur et aller dans le home:

    $ su - <user>

`sudo` permet d'éxécuter une commande à partir de son propre mdp.

Quitter le mode root:

    # sudo -k

### Création / suppression / modification d'utilisateur
Créer un utilisateur (la structure du home est définie dans `/etc/skel`):

    # adduser <user>
Créer un group:

    # addgroup <group>
Affecter un utilisateur à un groupe:

    # adduser <user> <group>
Supprimer un utilisateur:

    # userdel <user>
Supprimer un utilisateur et son répertoire home:

    # userdel -r <user>
Supprimer un groupe:

    # groupdel <group>
Modifier l'identifiant d'un compte user:

    # usermod --login <new-user> --home /home/<new-user> --move-home <old-user>
Dans le cas du compte admin, si erreur de vérouillage de `/etc/passwd`:

    # mount -o remount,rw /
Modifier l'identifiant d'un groupe:

    # groupmod -n new-name <new-group> <old-group>

### Vérouiller / déverouiller un compte:
Vérouiller un compte:

    # usermod --expiredate 1 <user> 
Dévérouiller un compte:

    # usermod --expiredate "" <user>

### Modifier du mot de passe
Modifier le mot de passe:

    $ passwd
Modifier le mot de passe d'un utilisateur:

    # passwd <user>

---
## Process

### Afficher les processus
Afficher les processus:

    $ ps -ef
Afficher tous les processus avec détails:

    $ ps -aux
Afficher les processus en rapport avec un sw:

    $ ps -aux | grep <sw>
Afficher l'arbre de process:

    $ pstree

### Arrêter un processus
Envoyer un signal d'arrêt à un processus:

    $ kill <pid>
Envoyer un signal d'arrêt à un processus graphique:

    $ xkill <pid>
Demander au système de tuer un processus:

    $ kill -9 <pid>

---
## System admin
Afficher la version du noyau:

    $ uname -r
Redémarrer le système:

    $ shutdown -h now
Afficher le temps d'exécution d'une commande:

    $ time <command>
Nettoyer la console:

    $ clear
Afficher les périphériques usb:

    $ lsusb
Afficher les périphériques pci:

    $ lspci

---
## Kernel
Si le noyau n'a pas été compilé de façon monolithique, il est possible de charger des modules pour étendre les fonctionnalités du noyau après le démarrage du système. Les modules sont dans `/lib/modules/<version du noyau>`

Afficher la liste des modules chargés:

    # lsmod
Charger un module:

    # insmod <module>
Charger un module avec ses dépendances:

    # modprobe <module>
Supprimer un module (si non utilisé):

    # rmmod <module>

---
## Network admin
Le fichier `/etc/network/interfaces` contient les informations de configuration des interfaces réseaux.

Afficher le nom de la machine sur le réseau:

    $ uname -a
Tester la connexion avec une autre machine:

    $ ping <@ip>
Afficher les intefaces réseaux dispo:

    $ ifconfig -a
Affecter une adresse ip a une interface:

    $ ifconfig <interface> <@ip>
Arrêter une interface:

    $ ifdown <interface>
ou

    $ ifconfig <interface> down
Démarrer une interface:

    $ ifup <interface>
ou

    $ ifconfig <interface> up
Arrêter les connexions réseaux:

    $ poweroff -i
Définir une passerelle par défaut:

    $ route add default <passerelle> <@ip>
Supprimer une passerelle par défaut:

    $ route del default
Configurer une carte wifi:

    $ iwconfig [<interface>]

Afficher plus d'info sur une interface:

    $ iwlist <interface>

---
## Disk

Verifier les disques connectes:

    $ udisksctl

Afficher les partitions du disque /dev/sdb:

    $ mmls /dev/sdb

Se deplacer dans la partition sans monter le disque:

    $ fls /dev/sdb -f ntfs -o 206848  

Se deplacer dans l'arborescence sans monter le disque (emplacement reference 436):

    $ fls /dev/sdb -f ntfs -i 206848 436   

Creer la timeline globale du disque:

    $ fls -z GMT -s 0 -m '/' -f ntfs -r /dev/sdb >> timeline.txt   

#Creer la timeline au format CSV (classé par date):

    $ mactime -b timeline.txt -z GMT    

---
## APT
Le fichier de configuration des dépôts est `/etc/apt/sources.list`.

Mettre à jour la liste des paquets dispo sur les repo du fichier source:

    $ sudo apt update
Mettre à jour les paquets intallés:

    $ sudo apt upgrade
Mettre à jour la distribution:

    $ sudo apt dist-upgrade
Installer un paquet:

    $ sudo apt install <sw>
Supprimer un paquet:

    $ sudo apt remove <sw>
Supprimer un paquet et les fichiers de conf:

    $ sudo apt remove --purge <sw>
Supprimer les copies des paquets désinstallés:

    $ sudo apt autoclean
Recherche d'un mot clé dans les descriptions:

    $ sudo apt-cache search <str>
Affiche la description d'un paquet:

    $ sudo apt-cache show <sw>