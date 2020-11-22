# La cybersécurité en entreprises

## Chiffres
Selon [NetExplorer](https://www.netexplorer.fr/blog/cyber-securite-2019-en-chiffres):
* 90 % des entreprises ont été attaquées (dont 43% sont des PME) alors que 83% des entreprises ne se sentent pas exposées !
* Seulement 17% des PME se sont doté de moyens pour lutter

Lors d'une attaque il faut en moyenne à une entreprise:
* 7 mois pour détecter l'attaque
* 75 jours pour reprendre une activité normale de son SI
* l'attaque engendre un coût moyen entre 242k euros et  1,3 millions d'euros

En 2019 les types d'attaques sont:
* 24% phishing (73% des entreprises y ont été exposées)
* 20% malware
* 16% ransomware : une attaque toutes les 14 secondes dans le monde en 2019

Pourcentage des entreprises exposées à un risque:
* 64% exposées aux outils shadow IT
* 61% exposées aux failles web
* 52% explosées à une erreur de manip humaine

Dans le monde, les cyberattaques coûtent 400 milliards de dollars aux entreprises par an. Le coût moyen d'une attaque pour une PME est de 242000 euros.

Pour les entreprises qui ne se sentent pas concernées, la question est de savoir, là aujourd'hui, si elles subissaient ce type d'attaque et de dégâts, sont elles prêtes à se défendre ? Peuvent-elles se permettre de subir une exfiltration de données ? Une perte de CA ? Un ralentissement de l'activité ? Comme les autres les ont déjà subies.

Les conséquences sont :
* Financières 
* sur la réputation : l'entreprise perd de sa valeur, et l'image renvoyée est écornée
* juridiques : un français sur deux est prêt à poursuivre une entrerprise pour négligeance quand à leur données

59% des entreprises  affirment que les cyber attaques ont eu un impact sur l’activité de leur entreprise :
* 26% des entreprises ont subi un ralentissement de la production pendant une période significative
* 23% ont vu leur site Internet indisponible pendant une période significative
* 12% ont essuyé des retards de livraison auprès des clients
* 11% ont eu des pertes de chiffre d’affaires
* 9% ont subi un arrêt de la production pendant une période significative
* 22% ont cité d’autres effets négatifs (augmentation de la charge de travail, baisse de productivité des collaborateurs, mauvaise réputation de l’entreprise)

En janvier 2019, 1,76 milliards de dossiers ont déjà été piratés.
En 2017, les cyberattaques ont augmentées de 600%, pourtant les dépenses en cybersécurité ne devraient augmenter que de 9% par an et par entreprise d’ici à 2023.

Les attaques se sont multipliées ces dernières années, favorisées par un monde toujours plus connecté et le fait que certains attaquants opèrent depuis des pays qui ne fera rien contre eux, parce que'ayant d'autres préoccupations (guerre ...).

Il existe pourtant de réélles armées de hacker officiellement "indépendants" mais disponibles pour répondre aux sollicitations de leurs gouvernements dans le cadre de l'intelligence économique, toujours de façon non-officielle.

On peut trouver comme exemple l'attaque des centrifugeuses nucléaires qui paralysent 600 et qui est la réponse d'un pays contre un autre à qui il ne peut offciellement déclaré la guerre. La faille a été des clés USB jetées sur le marking portant le vecteur d'attaque que des utilisateurs ont branchés sur le SI interne.

Deuxième exemple, lockpedia, qui paralysent toute l'infrastructure d'un pays en Ukraine. L'Ukraine est le labo de la Russie en terme de tests de cybersécurité. On sait depuis qu'une puissance peut en paralyser un pays dans le cyberespace.

## Le postionnement des entreprises
Nombreux obstacles encore aujourd'hui:
* Les grandes entreprises sont peu réceptive à la découverte de faille et a rapidement recours au juridique ce qui dissuade les découvertes de failles et ralentit la robuestesse de leur SI.
* Les entreprises, comme les particuliers, se sentent encore peu concernés par la sécurité tant que ça lne es a pas touchés.
* On peut considérer que toute les boîtes connaissent des problèmes de sécurité, mais peu communiquent par peur d'écorner leur image alors qu'une bonne entreprise aujourd'hui est une entreprise qui réagit vite. Une entreprise que ne sera pas attaquée, on peut considérer que ça n'existe pas
* La sécurité est une balance entre ce qu'il faut qui est contraignant et ce que l'utilisateur accepte en ergonomie et rapidité... Les entreprises sont aujourd'hui trop drivées à déliverer rapidement de la valeur, ce n'est pas ce que fait la sécurité
* La plupart des protections sont insuffisantes. Elles ont le mérite d'exister afin de juridiquement pouvoir se retourner contre un attaquant, mais si elles sont exploitées, les dégâts peuvent être très importants.
* De plus en plus d'entreprises stockent leur données sur le cloud qui ont vu leur volume exploser. Hors, le premier problème est que ces hébergeurs sont américains et que quelquesoit la localisation du datacenter dans le monde, et malgré ce que l'ont croit, les données tomberont sous le patriot act, et n'oublions pas que les US sont aujourd'hui dans une logique d'intelligence économique
* Autre problème avec le cloud c'est l'insertion de nouvelles vulnérabilités. Trop peu se sont penchés sur la configuration des espaces de stockages et serveurs pensant que c'était automatiquement blindés. Hors de nombreux cloud sont très mals sécurisés notamment avec les scripts ACL.

## La loi en France
La loi est très restrictive en matière de cybersécurité. Par exemple, publier de quoi expliquer comment pirater, si c utiliser ça engage la responsabilité de l auteur. Donc on dévoile rarement tout. L escalade par exemple sans l exploit précédente.

RGPD ...

## Les campagnes de sécurisation
Les équipes de pentest sont souvent très encadrées, respectent un certain nombre de règles qui parfois ne permettent pas d'aller aussi loin qu'il faudrait dans le cadre de la campagne. Les Red Teams, rééls attaquants ont le mérite de faire ce qu'il faut comme de vrais attaquants non mandatés par l'entreprise le feraient.

## La découverte de failles
Une faille découverte peut donner lieu à un CVE (Common Vulnerability Exposure, identifiées par année et numéro dans l'année) qui va décrire la faille et l'expoitation possible. Ces données sont publics et gérées par un organisme américain : le MITRE.

Pour déclarer la faille découverte il faut contacter une équipe dédiée, qui est une équipe RedHat qui va d'abords un peu vous challenger. Il faudra ensuite réserver le numéro sans donner trop de détails à ce stade, et en montrant les échanges avec la société aurpès de qui on a signalé la faille.

Ensuite on se met d'accord avec l'entreprise sur le jour de publication des données pour le signaler à RedHat. L'entreprise peut avoir des intérêts sensibles aurpès de ses clients, pour attendre de corriger le problème avant la publication.

On ne peut pas demander d'argent, une simple allusion peut être assimiler à de l'extorsion dans le droit français. C'est à l'entreprise de spontanément en proposer. POur gagner de l'argent avec la découverte de failles, il faut s'inscrires aux programmes de Bug Bounty

## Les Bug Bounty
Les Bug Bounty sont gérés par des plateforme qui vont recensées les entreprises se prétant au jeu et proposant ou nom de l'argent pour la découverte des failles, et les hackers venus de tous horizons, en général là pour gagner de l'argent ou progresser.

C'est un moyen encore peu répandu en France et beaucoup plus aux US de faire évoluer la sécurité de son SI. Les récompenses sont beaucoup moins coûteuses que les potentiels dégâts en cas d'exploitation de la faille par quelqu'un de malveillant.

Le montant des récompenses est en général indexé sur la criticité pour l'entreprise et non la difficulté technique.

## L'avenir
C'est d'abords l'industrie et la cybersécurité dans l'industrie. On estime aujourd'hui que seulement 10% des dispositifs qui pourrait être connectés le sont. Ce qui laisse une marge de développement énorme pour l'IoT. Hors la cybersécurité a toujours été laissé de côté pour délivrer de la valeur au plus vite.

C'est également l'évolution de la puissance des machines. Nous sommes proches de produire et de rendre accessible les processeurs quantique qui permettront d'atteindre une puissance calcul peut être 100 milliards de fois plus grande qu'aujourd'hui. Ce qui va balayer d'un coup nos système de cryptage type RSA. En effet il faut savoir que les délai de changement de mot de passe dans les entreprises pour les comptes utilistaeurs sont calculés sur la puissance de calcul actuelle et le temps qu'il faut pour casser un mot de passe par bruteforce.

Dernière grande évolution identifiée, côté sociale et politique, c'est la propagande déjà mise en évidence par une affaire comme Cambridge Analytica ou la campagne présidentielle française de 2017. Les données des utlisateurs massivement collectées sur le net et les réseaux sociaux profilent un utilisateur à travers ses likes et commentaires. Ses données sont exploités par l'IA pour générer du contenu auquel un utilisateur sera sensible. Il est simplement préparé à recevoir uen information. Puis la fausse information arrive via un lien sur facebook ou autre, qui fait réagir l'utilisateur et le conforte dans une opinion politique. Ces faits sont faux, et automatiquement générés depuis des templates reproduit dans différents pays et ont, si on creuse, un point de départ de la page ou de l'info en russie ou en ukraine, pas forcément concernés par la fausse information mise en évidence.