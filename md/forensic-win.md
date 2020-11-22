# Forensic Windows

## Liens
https://k-lfa.info/forensic-windows/

## Analyse en environnement Windows

### Fichiers utilisés par NTFS

* $MFT = contient la liste de tous les fichiers stockés sur le disque
* $LogFile = Un fichier qui contient un journal des opérations effectuées et des problèmes rencontrés par un système  d'exploitation.
* $Bitmap = Tableau de bits, Chaque bits indique quel cluster ils utilisent (alloué or libre pour allocation)
* $BOOT = Toujours localisé au premier clusters du volume, il contient le bootstrap code (NTLDR/BOOTMGR) et le paramètres BIOS
* $UpCase = Table de caractères unicode pour assurer la sensibilité à la casse dans win32 et l'espace de nom DOS
* $SECURE = Base de donnée d'ACL qui réduit la surcharge en ayant plusieurs ACL identiques stockées avec chaque fichier (stockant ces ACL uniquement dans cette base de données)
* $EXTEND = Dossier de FS contenant les options d'extensions variés comme $Quota, $ObjId, $Reparse or $UsnJrnl
* $UsnJrnl = fichier contenant les enregistrements lorsque un changement est fait sur un fichier ou dossier

### Ancienne séquence de boot

1. POWER : Alimentation du materiel, (Motherboard, CPU, ...)
2. BIOS: détection d'erreurs, init matériel, choix du média de boot
3. MBR: Premier secteur de disque (Tables de partition, recherche de partition active)
4. BootSector NTFS: 16 premiers secteurs de la partition, Information sur la taille des clusters, record MFT, index, recherche du gestionnaire de boot
5. Bootloader windows: Démarrage via bootmgr, lecture du fichier de configuration \Boot\BCD
6. Chargeur de démarrage windows: winload.exe charge l'OS et des options de configuration (Pagination, Pilotes de boot, ruche de registre en mémoire)
7. win32k.sys: chargement du sous système kernelland pour les appels système
8. crss.exe : Chargement du sous système userland en session 0
9. wininit.exe: Lancé au démarrage de session chargeant le gestionnaire de services service.exe, gestionnaire d'authentification lsass.exe, gestionnaire de sessions TSE lsm.exe

### Séquence de boot (UEFI)

1. POWER :  Alimentation du materiel, (Motherboard, CPU, ...)
2. UEFI BOOT ROM: Firmware ROM fournissant les fonctions du BIOS
3. GPT : Semblable au MBR mais évolué (Moins limité en partition et taille)
4. BootSector NTFS
5. Gestionnaire de démarrage: bootmgfw.efi
6. Suite semblable au LEGACY

### Analyse à chaud

* Accès et analyse manuelle du système
* Analyse automatique de l'OS et base de registre
* analyse manuelle de la base de registre
* Analyse des artefacts/binaire

la suite `sysinternal` téléchargeable [ici](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), on y trouve notamment :
* la suite `pstools`
* `procmon`
* `TCPview`
* `Process Explorer`
* `FTK imager`

### Analyse à froid

Il faut tout d'abords faire une image bit à bit du disque pour préserver l'original. Puis la méthodologie est la suivante:
* Collecte des données
* Examiner
* Analyser
* Documenter

Il faut identifier l'évènement de compromission (le dater) et chercher tout les indices sur des évènements précédents.

Des signes de compromissions sont par exemple:
* Ralentissement général
* Evènements suspects (cmd au boot, processus suspect)
* Alerte Antivirus ou du firewall
* Erreurs systèmes et crash d'application (logs, dump, ...)
* Création de compte user
* Apparition de fichier
* Programmes installés
* Service non légitime
* ...

### Isoler la machine
Il est important d'isoler la machine du réseau, les accès et d'étudier les logs de firewall, ou d'IDS...

#### Acquérir les données 
Donc extraction des disques dur et clonage sur un environnement d'étude dédié. Des outils de clonages par exemple : `Clonezilla`, `dd`. Voici la commande `dd`pour faire un clonage bit à bit:

    $ dd if=/dev/sde of=/root/Case01/forensicdata.dd bs=4096 conv=noerror,sync
Idéalement faire 3 clones et vérifier les checksums.

#### Faire une timeline:
Trouver l'offset du début de la partition:

    $ mmls /root/Case01/forensicData.dd
Création de la timeline globale:

    $ fls -o 206848 -z GMT -s 0 -m '/' -f ntfs -r /root/Case01/forensicData.dd >> /root/Case01/Global_Timeline.txt
`206848` est ici l'offset de la 2ème partition NTFS, c'est généralement celle-ci qui est intéressante.

Création d'une mini timeline:

    $ mactime -b /root/Case01/Global_Timeline.txt -z GMT -d 2019-04-25..2019-04-28 > /root/Case01/Mini_Timeline.csv

Identifier les formats de fichiers sans monter le disque:

    $ fls -r -F -o 206848 /root/Case01/forensicData.dd | grep ".xls"

`-r` recherche recursive et `-F` seulement les fichiers

Ensuite pour extraire un fichier :

    $ icat -o 206848 /root/Case01/forensicData.dd 47658 > Password.xls

`47658` correspond a l'inode du fichier identifié avec fls precedemment

#### Monter les disques

    $ mount -t ntfs -o ro,show_sys_files,streams_interface=windows,offset=$((512*yy)) /root/Case01/forenscData.dd /mnt/Case01

Si chifrée:

    $ dislocker -r -v -o $((2048**512)) -V /root/Case01/forensicData.dd -- /root/Case01
    $ mount -o ro,loop /root/Case01/dislocker-file /mnt/Case01

#### Rechercher des traces (les artefacts)
Tout laisse des traces. Voir les résumés la dessus:
* https://blogs.sans.org/computer-forensics/files/2012/06/SANS-Digital-Forensics-and-Incident-Response-Poster-2012.pdf
* https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download

#### Fichiers sensibles

* Registre HKLM: SYSTEM, SOFTWARE, DEFAULT, SAM, SECURITY (Dans C:\windows\System32\config\)
* Registre utilisateurs  (C:\Users\$user\NTUSER.dat)
* Logs windows (C:\Windows\system32\winevt)
* Profile navigateur: firefox, chrome, ... (C:\Users\$user\AppData\Roaming\Mozilla\Profiles)
* Historique IExplorer

#### Exploiter les artefacts
* `Regripper` sous linux
* `Registry Explorer` sous windows
* `Broiwsinghistoryview` sous windows permet d'analyser les historiques internet
* `python-evtx` sous linux permet de lire les logs windows. Téléchargeable [ici](https://github.com/williballenthin/python-evtx)


Plus d'outils [ici](https://forensicswiki.org/wiki/Tools) 