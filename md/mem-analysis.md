# Analyse de la mémoire

TODO : https://k-lfa.info/forensic-windows/

## Réaliser un dump mémoire

### Windows 10
1. `System configuration`
2. Dans l'onglet `boot`, aller dans `advanced options`
3. S'assurer que la taille max de la mémoire est sélectionné et fermer avec ok
4. Clic droit sur le PC dans l'explorateur, et aller dans `Properties` -> `Advanced system settings`
5. Dans l'onglet `Advanced`, ouvrir les `settings` de la partie `Startup and recovery`
6. Sélectionner `Complete memory dump` dans la partie `Write debugging information`
7. Ok et redémarrer le système


---
## Analyser un dump mémoire Windows

L'analyse se fait ici avec le logiciel [volatility](https://github.com/volatilityfoundation/volatility).

La liste des modules et leur utilisation est [ici](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#envars).

### Rechercher les infos générales

Premire étape, obtenir les informations générales sur le dump qui vont nous renseigner sur le profil:

    $ volatility -f <dumpfile> imageinfo
Un ou plusieurs profils sont suggérés par volatility. Nous en choisirons un par la suite avec l'id suggéré.

Le module `envars` va permettre d'obtenir plus d'informations générales (sur un process ?):

    $ volatility -f <dumpfile> --profile=<WinProfileId> envars

### Obtenir l'emplacement du registre SYSTEM
A l'aide du module `hivelist`, on peut récupérer les adresses virtuelles des clés du registre SYSTEM

    $ volatility -f <dumpfile> --profile=<WinProfileId> hivelist

Le résultat nous renvoie par exemple les adresses virtuelles des clés `\REGISTRY\MACHINE\SYSTEM`, `\SystemRoot\System32\Config\SAM`, `\SystemRoot\System32\Config\SAM`...

### Obtenir le hostname
Il faut trouver la valeur de la clé `\ControlSet001\Control\ComputerName\ComputerName` se situant dans le clé `\REGISTRY\MACHINE\SYSTEM`dont on obtient l'adresse avec le plugin `hivelist`.

Le module `printkey` va permettre l'affichage de la valeur de la clé:

    $ volatility -f <dumpfile> --profile=<WinProfileId> printkey -o <0x@SYSTEM> -K 'ControlSet001\Control\ComputerName\ComputerName'

avec `<0x@SYSTEM>` l'adresse hexa de `\REGISTRY\MACHINE\SYSTEM`

### Obtenir la liste des process 
Le module `pstree` permet l'affichage des process exécutés:

    $ volatility -f <dumpfile> --profile=<WinProfileId> pstree

Le résultat donne notamment par ligne:
* l'adresse virtuelle du process
* le nom du process
* le PID du process
* le PID du process parent (PPID)

### Chercher la persistance d'un malware
La clé `Software\Microsoft\Windows\CurrentVersion\Run` via `NTUSER.dat` est un élément potentiellement utilisé pour stocké les éléments de persistance d'un malware ou d'une backdoor. 
Les modules `hivelist` et `printkey` permettent de l'explorer:

    $ volatility -f <dumpfile> --profile=<WinProfileId> hivelist
    $ volatility -f <dumpfile> --profile=<WinProfileId> printkey -o <0x@NTUSER.dat> -K 'Software\Microsoft\Windows\CurrentVersion\Run'

`<0x@NTUSER.dat>` est l'adresse virtuelle de la clé NTUSER.dat de l'utilisateur en question, les valeures retournées sont les logiciels lancés au démarage.

### Obtenir les arguments et le chemin d'un process
Le module `cmdline` permet d'obtenir les arguments d'un process et donc sa ligne de commande, confirmant le chemin de l'exécutable lancé

    $ volatility -f <dumpfile> --profile=<WinProfileId> cmdline

### Obtenir la liste des connexions au système
Le module `connscann` permet d'afficher la liste des connexions au système

    $ volatility -f <dumpfile> --profile=<WinProfileId> connscan
La commande retourne la liste des connexions avec les pid des process locaux concernés.

### Obtenir les connextion utilisées par un process
Le module `netscan` permet d'étudier les connexions utilisé par un process:

    $ volatility -f <dumpfile> --profile=<WinProfileId> netscan | grep <pid>

### Obtenir les commandes lancés depuis la console
Quelque soit le mode d'ouveture de la console (backdoor, cmd.exe, RDP...) le module `consoles` (tout comme le module `cmdscan`) permet de voir la liste des actions depuis la console

    $ volatility -f <dumpfile> --profile=<WinProfileId> consoles

Le module se base sur l'historique retrouvé en mémoire du process `csrss.exe` pour les Windows avant 7, et `conhost.exe` depuis Windows 7, qui correspondent aux process de la ligne de commande

### Dumper la mémoire d'un process
Le module `memdump` permet de dumper la mémoire d'un seul process:

    $ volatility -f <dumpfile> --profile=<WinProfileId> memdump -p <pid> ./

Le résultat est un fichier `<pid>.dmp` dans le répertoire courant.

### Recherche d'une connextion distante
Un des exécutables permettant de pointer sur une connexion distante est `tcpreplay.exe`, qui transfère les connextions d'un réseau à un autre.

Lorsque l'utilisation de `tcpreplay.exe` a été identifiée dans un process console, on peut à partir du dump du process console, obtenir des informations via:

    $ strings <pidConsole>.dmp | grep tcprelay

Il est possible notamment de trouver un nom de domaine de l'attaquant.

### Obtenir les credentials du SAM
Le module `hashdump` permet d'obenir les creds :

    $ volatility -f <dumpfile> --profile=<WinProfileId> hashdump > hash.txt

Il est ensuite de bruteforcer les creds avec `John the Ripper` ou `hashcat`:

    $ hashcat -m 1000 hash.txt <wordlist>
    $ haschat -m 1000 hash.txt --show 

### Extraction d'un exécutable
Le module `procdump` permet de reconstituer un exécutable à partir de la mémoire:

    $ volatility -f <dumpfile> --profile=<WinProfileId> procdump -p <pid> --dump-dir ./

L'exécutable est ensuite dispo pour être analysé avec strings, wireshark dans une machine virtuelle s'il provoque un trafic réseau et un risque d'infection ... Dans ce cas le trafic réseau vers lequel il pointe peut être intéressant.

### Savoir si le parefeu est activé
La clé `ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile` permet de savoir si le firewall était activé ou non:

    $ volatility -f <dumpfile> --profile=<WinProfileId> printkey -K 'ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'

### Récupérer les mots de passe du navigateur
Il est possible de récupérer des informations sensibles d'un navigateur web et parfois les mots de passe en:
* identifiant le pid du navigateur internet avec `pslist`
* dumpant la mémoire du process avec `memdump`
* affichant les chaînes de caractères avec la commande `strings`

### Récupération des LSA secrets
Le module `lsadump` permet de récupérer les LSA secret (Local Security Authority), dans lesquels on peut retrouver des mdp par défauts par exemple:

    $ volatility -f <dumpfile> --profile=<WinProfileId> lsadump 

