# Webapp pentest


## Web - notions

La plupart des sites applications webs sont aujourd'hui développés à partir de frameworks ou de CMS. On trouve :

* framework front-end : généralement en Javascript (Angular - React - Vue)
* framework backe-end : généralement NodeJS, PHP (Zend, Symfony, Laravel), .Net, JEE (Spring...)
* CMS : Wordpress, Drupal, TYPO3, Joomla ...

Pour les statistiques de popularité, voir ici : https://www.wappalyzer.com/technologies

PHP est le langage le plus utilisé (77%) devant Java (9%).

Les [CMS](https://www.wappalyzer.com/technologies/cms) les plus utilisés:
* Wordpress 75%
* Drupal 4%
* Joomla 4%
* ...

Les [frameworks](https://www.wappalyzer.com/technologies/web-frameworks) les plus utilisés :
* ASP.net 53%
* Rails 8%
* Laravel 8%
* ... 

Ces solutions ajoutent une couche d'abstraction parfois un peu opaque, riches de composants, et d'appels de fonctions apportant son lot de vulnérabilités.

L'architecture 3-tiers est largement répandue et avec le modèle MVC :
* Modèle : gère les données et les états de la solution
* Vue : offre un style graphique au site basé sur des framework front-end
* Controleur : gère les IO utilisateurs et la logique métier

L'URL mapping (routing) va solliciter le contrôleur qui va manipuler le modèle en fonction des entrées utilisateurs et de la logique métier, avant de mettre à jour la vue qui offrira un retour à l'utilisateur.



---
### Le monde Java
* Les **servlets**, codé en Java avec une API http permettent de gérer les IO
* Les **JSP** (Java Server Page), extension `.jsp`, sont un template HTML compilé dans un servlet
* **Struts** est un framework MVC basé sur les actions. Initialement utilsant des fichiers `.do`, la version 2 a apporté quelques changements majeurs, sur les form notamment et a vu l'apparition des OGNL (Object Graph Notation Language). Cette version utilise des fichiers `.action`.
* Les règles de validations de struts se trouvent dans le répertoire **WEB-INF** : **validator-rules.xml** et **validator.xml** afin d'assuer son rôle de validation des objets.
* Les **JSF** (Java Server Faces), **Spring MVC** ou **GWT** (Goowle Window Toolkit) font parti des framework Java, plutôt back-end

### Le monde Javascript
* **Javascript** est un langage orienté object incorporé au navigateur, donc côté client, supportant le paradigme object, impératif et fonctionnel. Ses bases et ses principales interfaces sont fournies par des objets qui ne sont pas des instances de classes bien que possédant un contructeur pour créer leurs propriétés. Javascript permet l'interaction avec l'utilsateur.
* **AJAX** (Asynchronous Javascript And XML) est une méthode utilisant notamment Javascript, XML, DOM et XMLHttpRequest, apportant un mode de fonctionnement pour les demandes asynchrone, c'est à dire que le navigateur continue à exécuter le code JS au départ de la demande sans attendre la réponse par le serveur. Il ne bloque donc pas l'utilisateur. Il faut par contre prévoir le code pour s'adapter à la réponse du serveur.
* Le format **XML** (accompagné de XSLT) est un langage de balisage standardisant un format de données pour les échanges. 
* **JSON** (Javascript Object Notation) est un format de données basé sur la syntaxe JS qui structure les informations. Il tend à remplacer XML.
* Le **DOM** (Document Object Model) est une interface de programmation utilisée pour l'affichafe dynamique et l'interaction avec les données.
* **XMLHttpRequest** est un objet utilisé par JS dans la communication asynchrone entre navigateur et le serveur pour envoyer les requêtes et déclencher les opérations à la receptions des réponses.
* **Fetch** est une API qui remplace de plus en plus XMLHttpRequest.
* **JQuery** est un framework JS côté client visant à parcourir et modifier le DOM, offrant des possibilités d'animation, la gestion d'évènements ou la manipulation de CSS.
* **React** (Facebook) 24%, **Angular** (Google) 8% et **VueJS** 7% sont les 3 frameworks front-end les plus utilisés.
* **NodeJS** est un framework backend utilisé pour ses performances


### Le monde PHP
* **PHP** est un langage de programmation orienté objet permettant la cration de sites dynamiques. Largement répendu (plus de 80% de part de marché côté serveur) il a permis la cration de Facebook ou Google. Il peut être également interprété en local.
* Il est très souvent couplé avec le serveur web **Apache**, mais fonctionne très bien avec **IIS** ou **Nginx**. La persistence de donnée est derrière assurée avec une base de données SQL comme **MySQL** ou **PostgreSQL** par exemple.
* Il est exécuté côté serveur, pour générer du code HTML interprétable par le navigateur à partir du code PHP.
* La plupart des CMS sont basés sur PHP.
* Beaucoup de framework se sont imposés côté backend, **Symfony**, **Laravel**, **Zend**, **CodeIgniter**, **CakePHP** par exemple.
* Il est faiblement typé et offre beaucoup de vulnérabilités

### Le monde .net
* Le framework **ASP.Net** est branché sur le serveur **IIS**. Il va agir comme un filtre ou une web app qui va récupéré la requête du serveur, accéder à diverses services tiers ou aux bases de données et générer des pages web dynamiques en retour pour l'utilisateur. 
* Ce moteur peut être utiliser avec les langages de la plateforme .Net : **VB**, **C**#, **JScript**
* Contrairement à ASP, les programmes sont compilés en ASP.Net
* Le code source est séparé du HTML (pas le cas non plus en ASP)
* La programmation est évènementiel
* Les formats de fichiers sont :
  * `.aspx` pour les pages web
  * `.asax` pour les récepteurs d'évènements
  * `.ascx` pour les widgets des programmeurs
  * `.asmx` pour les services webs
  * `.cs`, `.vb` et `.js` sont les codes sources en C#, VB et JS
  * `.config` fichiers xml de configuration. Le principal est web.config
* `.NetCore` est un framework basé sur .net, multi plateforme, et avec un compilateur à la volée très performant, qui n'embarque que le strict nécessaire pour construire l'exécutable le rendant plus léger et ouvrant les portes du micro-services.

### Autres frameworks
D'autres langages peuvent faire serveur web avec des frameworks. Par exemple:
* **Python** : Django, Flask, Pyramid, Zope, Pylons, CherryPy
* **Ruby** : Rails, Rack, Synatra, Padrino

---
### HTTP
**HTTP** (Hypertext Transfert Protocol) est un protocol de commuication client-serveur qui permet à un client d'accéder à un serveur conteneant des données.

#### URI, URL, URN
* L'**URI** (Uniform Ressource Identifier) est à la base du web, il identifie via une courte chaîne de caractère, une ressource sur un réseau. il peut être de deux types : **locator** (URL) ou **name** (URN).
* L'**URL** est un URI qui en plus d'identifier, fournit des moyens d'agir sur la ressource ou d'en obtenir une représentation
* L'**URN** est un URI qui identifie une ressource par son nom dans un espace de noms. Il ne se soucie pas de son emplacement.

Pour faire une redirection avec une URL : `?&url=<site>&h=<crypt MD5 de l'http du site>`

#### Paramètres
les paramètres issus d'un formulaire sont passé dans l'url après l'adresse suivie d'un `?` puis chaque nom de paramètre est préfixé par `&` suivi de `=` et sa valeur.

#### Requête
La commuication se fait via des requêtes. Les principales sont:
* **GET** : la plus courante pour récupérer une ressource, elle est sans effet sur la ressource
* **POST** : Comme GET mais destiné à transmettre des données qui seront traitées. A la différence de GET, les paramètres de l'URL se trouve dans le corps de la requête. Parfois à tort utilisée à la place de PUT.
* **HEAD** : Pour obtenir les infos sur la ressource sans la ressource
* **PUT** : Remplaece ou ajoute une ressource sur le serveur. (PATCH permet une modification partielle de la ressource)
* **DELETE** : permet de supprimer une ressource du serveur

On trouve également **CONNECT** pour passer par un proxy, **TRACE** pour teste la connextion et **OPTIONS** pour obtenir ldes options de communication de la ressource au serveur

Les requêtes sont composé d'un HEADER et d'UN BODY. Le Header contient beaucoup d'info, cookie, navigateur ... et d'autres champs qui peuvent être ajoutés. Il est interessant de les inspecter.

---
### Session
HTTP ne prévoit pas de gérer la gestion de la session lors de la navigation d'une page à l'autre d'un même site. Les pages sont indépendantes entre elles. Pour éviter de se logger à chaque demande de ressources, un mécanisme de gestion de session est mis en place soit par Cookies soit par Jetons. Les jetons sont souvent des **JWT** (JSON Web Token). Cookie et Token ont en général une date d'expiration

#### Token
* Les tokens vont être gérés lors de l'authentification. Ils pourront ensuite être soit stockés par le navigateur, soit en local soit dans un cookie. Dans ce dernier cas ça n'en fait pas une gestion de session par cookie. 
* Les tokens sont souvent plus adaptés à un site d'entreprise gérant de nombreuses demandes.
* Ils sont composés de 3 parties :
  * header : contient des informations sur l'algorithme. Ex : `{ "typ": "JWT", "alg": "HS256" }`
  * payload : souvent le nom de l'utilisateur 
  * signature : mdp souvent cryptée en RSA256 (symétrique avec clé privée) ou HS256 (symétrique). 

Le format est `base64urlencode(header).base64urlencode(siganture).base64urlencode(signature)`. 

Quelques sites utiles:
*  https://www.jstoolset.com/jwt
*  https://www.jstoolset.com/base64-encode
*  https://jwt.io/

Le token peut être visible dans la requête HTTP GET ou POST.

#### Cookie
* Les cookies servent à stocker de nombreuses informations et entre autre les informations de sessions. Les informations sont propres à chacun il faut donc les comprendre.
* Ils sont stockés en local par le navigateur et visible depuis le navigateur, très souvent en JSON.
* On peut les observers dans les requêtes HTTP GET et POST. 
* Ce sont des fichiers que l'on peut voler avec l'exploitation d'un faille XSS pour détourner une session admin notamment.
* On peut observer dans la requêtes certains noms de cookies qui nous donne des indications sur la techno du site:
  * PHPSESSID : PHP
  * JSESESSIONID : Java
  * ASP.netsessid : ASP.net
  * ci_session : CodeIgniter

---
### Service Web et Microservices
* Le service web esu un protocole permettant l'échange d'information entre système hétérogènes. Il est l'implémentation logicielle d'une ressource identifiée par un URI accessible via HTTP. Ils sont un moyen de manipuler l'information et pas seulement un accès. Il entre dans le cadre d'un système distribué.
* **SOAP** (Service Oriented Architecture Protocol)est la norme qui défini le protocole de communication et **WSDL** la signature du service.
* **REST** (Representationnal state transfer) est une architecture représentant l'ensemble des fonctionnalités comme des ressources identifiés par leur URI
* Les microservices sont faiblement couplés entre eux et représentent un petit service faisant une tâche très spécifique. Ils sont généralement reliés entre eux par une API REST. Un avantage est que sur la modification d'une ressource seule le microservice concerné est à remplacer, le reste de l'application reste compatible.

