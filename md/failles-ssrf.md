# Failles web - SSRF

## Description
La faille SSRF (Server Side Request Forgery) via la modification de requête permet d'accéder au système hôte ou encore à son réseau. Elle permet donc de contourner le pare-feu pour accéder à un système ou à un réseau sans avoir nécessairement une machine compromise.

Plusieurs catégories de SSRF sont définies:
* content-based : extraction de contenu
* boolean-based : la réponse différente en fonction d'une ressource, permet de déduire son existence
* error-based : l'erreur en retour permet de déduire l'existance d'une ressource
* time-based : la variation de temps permet de déduire l'existence d'une ressource 

## Détection
Par exemple sur un site téléchargeant une image (un avatar pour un profil, une gallerie ...), si au lieu de l'URL d'une image nous sélectionnons `https://127.0.0.1:80/favicon.ico` (un fichier connu du site), et que nous avons une réponse HTTP 200 (succès de la requête) alors cela montre que nous accèdons aux ressources locales puisque 127.0.0.1, via l'exécution du serveur à travers la requête. Il y'a donc potentiellement une exploitation possible.

Quelques fonctions PHP peuvent être la source de failles `file_get_contents()`, `fopen()`, `fread()`, `fsockopen()`, `curl_exec()`.

## Intention
La faille SSRF permet de : 
* Accéder aux services de l'hôte
* Accéder aux fichiers de l'hôte avec `FILE://`
* Scanner le réseau
* Accéder aux services du réseau via `HEAD`, `GET` ou `POST`
* Effectuer un mouvement lateral
* Abuser une interface REST

## Exploitation

### Exploitation d'un lien
Partant de l'exemple de la section Détection, au lieu de viser le port 80, il est possible de renseigner d'autres ports qui peuvent être intéressant. Par exemple 8080 qui est non accessible par autre chose que localhost.

Il est aussi possible de jouer sur l'adresse pour atteindre des services du réseau, par exemple :`http://192.168.10.2-254` afin de scanner le réseau local.

### Scan avec BurpSuite
Il est possible de faire un scan avec BurpSuite en interceptant la requête incluant l'adresse et le port ciblé. En envoyant la requête dans le module Intruder, puis en faisant un `clear` des variables, il suffit d'ajouter le port en variable (`Add` -> `§3000§`), puis dans payload parcourir les numéros de port désiré. Une longueur rapportée pour un port est parlante, si elle est plus longue, le port est probablement ouvert.

### Scan de réseau interne et contournement de filtre
Le serveur peut intégrer un filtre (via regex) pour éviter les chaînes de type `url=http://192.168.0.19`. Il est possible de le contourner avec un nom de domaine nous appartenant en enregistrant les 254 valeurs comme `19.domain.com` -> `192.169.0.1` afin de scanner `url=http://19.domain.com`.

L'outil [NIP.IO](https://nip.io) facilite la tâche puisque il suffit de saisir `ip-cible.nip.io` pour que serveur fasse une correspondance dynamiquement en `http://192.168.1.19.nip.io` permettant l'accès à `192.168.0.19`. Si le filtre va plus loin et n'autorise pas de chiffres dans le sous-domaine, il est possible d'ajouter n'importe quelle valeur avant l'adresse IP, par exemple `http://un.sous-domaine.192.168.19.nip.io` pour arriver au même résultat.

### Cibler le serveur vulnérable et contournement de filtre
De même que précédemment si le serveur filtre les chaînes `localhost` ou `127.0.0.1`, il est possible d'utiliser les outils suivants:
* NIP.IO : 127.0.0.1.nip.io
* utiliser les valeurs décimales : `http://2130706433/`

D'autres moyens sont disponibles à travers l'outils [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings).

### SSRFMap
L'outils [SSRFmap](https://github.com/swisskyrepo/SSRFmap) est un outils python très utile dans l'exploitation SSRF. Un certain nombre de module permet de faire de nombreuses actions très facilement. De plus le paramètre `-level` permet de paramétrer le niveau de filtre attendu (et donc de test pour SSRFmap).

Pour découvrir l'outils, dans le répertoire `data` de SSRFmap se trouve un serveur python vulnérable accessible sur le port 5000 pour exemple. Pour le lancer : 

    $ python3 data/example.py
Les modules principaux sont les suivants:
* **portscan** : scan des ports locaux `$ python3 ssrfmap.py -r data/request2.txt -p url -m portscan`
* **networkscan** : scan les autres services web du réseau
* **readfiles** : télécharges les fichiers systèmes sensibles `/etc/passwd`, `/etc/shadow` ... La liste est configurable dans le fichier `modules/readfiles.py` via la variable `files`
* **ProxySocks** : permet d'utiliser le serveur comme un proxy
* **redis**, **github**, **zabbix**, **mysql** … : permet d'obtenir un contrôle en ligne de commande sur des services vulnérables
* **alibaba**, **aws**, **gce** et **digitalocean** : télécharge des fichiers spécifiques en fonction des serveurs

## Prévention
Comme toujours, la première règle est de ne pas faire confiance aux entrées utilisateurs.
Comme bien souvent encore, établir une liste noire et filtrer et une mauvaise idée, ça se contourne. Mieux vaut établir une liste blanche de ce qui sera autorisé.

Il faut alors définir parmi ce qui sera autorisé:
* DNS
* Adresses IP : en l'absence de localhost et `0.0.1` pas d'accès à l'hôte
* Les protocoles autorisés (empêcher `FILE://` et `SFTP://` notamment)

## Liens
https://www.vaadata.com/blog/fr/comprendre-la-vulnerabilite-web-server-side-request-forgery-1/
https://www.vaadata.com/blog/fr/exploiter-la-vulnerabilite-ssrf-2-2/