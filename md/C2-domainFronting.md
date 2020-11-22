# Commande et contrôle (C2) et Domain fronting

## Commande et contrôle
Le serveur de commande et contrôle (C2) est utilisé pour récupéré des données sur un réseau. Le serveur potentiellement sur le réseau infecté envoit des commandes à des botnets sur ce réseau et reçoit en retour les infos des ordinateurs contaminés sur le réseau. En général les machines infectées communiques via IRC, des images, des documents ...

L'architetcture peut être en étoile (bots autour du serveur), multiserveur, hieracrchique mais également peer-to-peer. La plupart des campagnes C2 identifiées utilisent des services cloud.

Etablir une communication C2 est une étape nécessaire pour le mouvement lateral sur le réseau. Procéder à ce type d'attaque via le cloud,  consiste à utiliser un serveur externe au réseau, par exemple sur Lightsail, en tant que serveur C2. Les machines compromises sur le réseau ciblé se connecteront sur lui. Bien qu'Amazon (comme les autres) ait bloquer le domain fronting, cela permettait notamment de changer de domaine (entre le C2 et la victime) et donc de donner l'impression à la victime que l'attaque vient d'ailleurs et n'est donc plus la même attaque.

## Mouvement lateral
Essayer de compromette d autres machines sur un réseau quand on est rentré dessus. Très important pour montrer à un client qu une petite brèche peut avoir un impact fort.

## Domain Fronting
Le domain fronting est une technique permettant à un hôte de se connecter à un service non authorisé tout en paraissant communiquer avec un autre service qui lui authorisé. Cette technique utilise le protocole HTTPS et se situe au niveau de la couche applicative.

* Le nom de domaine autorisé est utilisé lors de l'initialisation de la connextion, il est visible dans la requête DNS et dans le TLS
* Une fois la connexion chiffrée HTTPS établie, le vrai nom de domaine est transmis dans la liste des en-têtes de requête HTTP

Cette technique fonctionne si les deux services (le vrai, le leurre) sont sur un même domaine dont l'infra se chargera de faire les redirections, domaine avec un trafic important tel que Amazon ou Google. En effet ces CDN (Content Delivery Networks) masque le traffic d'origine. Ces acteurs ont d'ailleurs pris des dispositions pour emêcher le domain fronting.

Le domain fronting combiné avec le C2 permet de camouflé la connexion entre la victime et le serveur C2.

## Mise en oeuvre

[Cobalt Strike](https://www.cobaltstrike.com) est un outils de post exploitation qui permet d'embarqué un agent sur le réseau ciblé et de créer un canal persistant. Une des technologies de Cobal Strike est Malleable C2 qui est un langage permettant de manipuler les domaines dans le but de donner l'impression d'avoir une attaque différente à chaque fois. Cobalt Strike permet le mouvement lateral, le camouflage ou encore l'extraction de données.

Un exemple de [mise en oeuvre avec Google](https://www.securityartwork.es/2017/01/24/camouflage-at-encryption-layer-domain-fronting/), et [un autre avec Alibaba](https://medium.com/@vysec.private/alibaba-cdn-domain-fronting-1c0754fa0142).

[Meterpreter](https://www.securityartwork.es/2017/01/24/camouflage-at-encryption-layer-domain-fronting/) peut également prendre en charge le Domain Fronting.

Il est également possible d'utiliser PowerShehttps://www.powershellempire.comllEmpire qui offrira des agents PowerShell (même sans powershell.exe installé) tout en gérant une connection C2 sous Linux et OSX.

[dnscat2](https://github.com/iagox86/dnscat2) est un tunnel DNS qui met en place un canal crypté C2 et qui se compose de deux parties, le client sur la machine compromise et le serveur sur la machine attaquante. Un excellent article sur la mise en place est dispo [ici](https://www.hackingarticles.in/dnscat2-command-and-control-over-the-dns/).