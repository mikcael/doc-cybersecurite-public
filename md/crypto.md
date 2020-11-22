# Cryptographie et cryptanalyse

## Hashage et Chiffrement
**Hashage** : pas de possibilité de revenir au clair avec algo. Ce sont des algos destructif.
**Chiffrement** : on peut retrouver mathématiquement le clair. Il y a chiffrement symétrique et asymétrique.


Algorithmes de hashage:
* MD5
* SHAx
* CRC
* Argon2

Algorithmes de chiffrement par substituion:
* ROT13
* Vigenère
  
Algorithmes de chiffrement:
* par substituion : ROT13, vigenère
* symétrique : DES, AES, 3DES
* asymétrique : RSA

## Un bon algortihme
Un bon algorithme est lent à décrypter pour ralentir le bruteforce. C'est d'ailleurs à partir de ça que sont calculé les durées de renouvellement des mots de passes en entreprise.

Un algo faible peut être choisi pour des problématiques de performance. La question de la sécurité est une balance entre performance et contrainte.

Par exemple par ordre du moins sécure au plus sécure (performance opposée):
* MD4
* MD5
* Bcrypt
* SHA-1
* SHA-256
* SHA-512 // commence à être secure
* Argon

Bcrypt est pas mal, il se base sur blowfish et est l'algo par défaut de la fonction PHP `password_hash`. Fonction qio accepte également Argon si on utilise le paramètre `PASSWORD_ARGON2I`.

## Contremesure sur le bruteforce
Pour ralentir le bruteforce, il existe PBKDF2 qui est la dérivation de clé. Elle va permettre de hasher un hash sur lui même plusieurs milliers de fois. Par exemple, le WPA2 utilise :

    DK = PBKDF2(HMAC−SHA1, passphrase, ssid, 4096, 256)
Avec:
* HMAC−SHA1 : fonction pseudo aléatoire utilisé à chaque itération
* passphrase : la password 
* ssid : le ssid est utilisé comme sel
* 4096 : le nombre d'itération 
* 256 : la longueur de clé désirée

Un autre moyen est le salt qui permet de compliquer un mot de Pass trop simple en générant des caractères aléa mais il faudra connaître le salt. sans le salt on perd le mot de passe puisqu on ne peut pas reconstituer le hash.
le salt sert aussi a contrer les rainbowtable.

## Format du condensat
Le condensat est au format suivant :

    $type$salt$hash
avec type (dans le contexte système):
* `$1$`: MD5-based crypt ('md5crypt')
* `$2$`: Blowfish-based crypt ('bcrypt')
* `$sha1$`: SHA-1-based crypt ('sha1crypt')
* `$5$`: SHA-256-based crypt ('sha256crypt')
* `$6$`: SHA-512-based crypt ('sha512crypt')

OSX Darwin utilisait `des_crypt` et `bsdi_crypt`. Et depuis des méthodes à part.

## Rainbow tables
La rainbowtable a pour but d'optimiser le bruteforce en diminuant le temps via l'utilisation de compromis temps-mémoire. La table arc-en-ciel (en anglais : rainbow table) est une forme sophistiquée de ce type d'attaque.

Les compromis temps-mémoire sont utilisés pour récupérer des clés à partir de leur trace chiffrée, en s'appuyant sur des tables précalculées.

A partir d'un mot de passe on va utiliser la dernière fonction de réduction pour obtenir une empreinte et voir si le mot de passe apparait. Si ce n'est pas le cas on remonte un cran en arrière etc ...

Pour contrer ça, on utilise le sel dans le but de générer de l'aléatoire

## Windows
Windows a une longueur défini de mot de passe. NTLM tronque les mots de passe à 16 caractères puis scindé en 2 mdp de 8 caractères en MD4. Ca va très vite de casser les mdp avec rainbowtable NTLM. Il en existe une de 100 Go marche très bien, en une demi heure elle trouve a peu près tout, il y'en a un peu plus grosse qui vouvre tt le charset européen.

Depuis NTLMv2 est utilisé et est un peu plus sécurisé, il faudra utiliser hashcat et un bon dictionnaire pour le cassé. Un très bon document sur les condensats utilisés avec Windows [ici](https://actes.sstic.org/SSTIC07/Authentification_Windows/SSTIC07-article-Bordes-Secrets_Authentification_Windows.pdf).

## Le password spraying
Un mot sur le password spraying qui n'est surtout pas du bruteforce. Là ou le nombre de tentatives autorisées pour un utilisateur est assez bas, pour un pass donnée, on peut par contre tester énormément d'utilisateurs.

## Commandes
### Contenu hexadécimal
Pour lire un contenu hexa

    $ hexedit <filename>

### Déchiffrer par décalage
Ici décalage de + 10 dans le fichier file.bin

    $ index=0 ; for hex in $(cat file.bin |showhex); do T[$index]=$(echo \\x$(echo "obase=16;ibase=16;$hex-A"|bc)) ; : $((index++)) ; done ; echo -e ${T[*]}

### MD5

    $ echo -n "lachaine" | md5sum
Le -n permet de supprimer le saut de ligne ajouté par echo

### SHA

    $ echo -n "lachaine" | sha1sum
    $ echo -n "lachaine" | sha256sum
    $ echo -n "lachaine" | sha512sum
Le -n permet de supprimer le saut de ligne ajouté par echo

### Argon2
[Argon2](https://github.com/p-h-c/phc-winner-argon2), s'utilise comme ceci:

    $ apt install -y argon2
    $ argon2 salt [OPTIONS]
Le salt doit faire au moins 8 octets. Par défaut utilisation de argon2i (optimisée pour les attaques par canal auxiliaire, accès mémoire indépendant des données secrètes). Quelques options:
* -d     utilise argon2d qui est optimisé contre l'utilisation des GPU
* -id    utilise argon2di
* -t N   nb d'itarations (3 par défaut)
* -m N   utilsation mémoire 2^N KiB (12 par défaut)
* -p N   nombre de thread (1 par défaut)
* -l N   longueur du hash en sortie en octets (32 par défaut)
* -e     seulement le hash encodécen sortie
* -r     seulement les octets brut du hash en sortie

### Base64

    $ base64 fichier.txt
    $ base64 -d fichier.64

### Décoder du ASCII avec python

    >>> str= "4C65......"
    >>> str.decode("hex")

### UU

Installer sharutils si uudecode pas présent

    $ sudo apt install sharutils 
    $ uudecode -o result.txt code.txt

### Cracker un md5
Avec [ipcrack](http://code.google.com/p/lnxg33k/downloads/detail?name=icrack.py)

    $ icrack.py --online [hash]
    $ icrack.py --online [hash][dictionnary]


