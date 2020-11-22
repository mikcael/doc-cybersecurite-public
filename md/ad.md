# Active Directory

**Active Directory** est un annuaire pour le monde Microsoft utilisable de puis Windows 2000. Il permet de remplacer les bases **SAM** (Securtiy Account Manager) et permet de passer des groupes de travail aux **domaines Active Directory**.

Il centralise toute l'administration et la gestion des droits dans un annuaire de type LDAP, et permet de gérer les **utilisateurs**, **ressources** comme les postes de travails (y compris Linux), et les **groupes**. Ces 3 entités forment les **objets AD** qui représentent la façon dont l'information est stockée. 

Il est sécurisé, distribué, partitionné et dupliqué

## Organisation
Les **GPO** (group policy object)permettent de restreindre des actions comme les accès restreints à toutes les ressources ou certains dossiers, la désactivation de certains exécutables ...

L'arborescence : Un arbre AD correspond à un domaine et toutes ces ramifications c’est-à-dire des domaines enfants. Ensuite cet arbre AD fait partie d’un plus grand ensemble qu’on appelle une forêt. Une forêt AD comprend à la foi, le domaine racine ou root domaine mais aussi l’ensemble des domaines enfant.

## Infrastructure
Trois notions:
* **Domaine** (ou sous-domaine) : Le domaine au sens de l'AD est le niveau le plus bas. Il contient au moins un contrôleur de domaine (Ldap + Kerberos). Il représente une organisation ou une partie d'une organisation.
* **Arborescence** : Ensemble d'un domaine et de tous ses sous-domaines.
* **Forêt** : Ensemble d'arborescences qui appartient à la même organisation. Au choix de l'architecte réseau, deux arborescences peuvent appartenir à une même forêt ou pas.

## Commandes
Trouver le contrôleur principal:

    netdom /query FSMO
Installer AD DS en une commande:

    Install-windowsfeature AD-domain-services, RSAT-AD-Tools
Créer la forêt:

    Install-ADDSForest
Pour trouver le serveur sur lequel vous êtes authentifié

    echo %logonserver%
Trouver le controleur de domaine le plus proche: 

    nltest /sc_query:deployadmin.com
Trouver le contrôleur de domaine utilisé:

    nltest /DSGETDC:deployadmin.com
Trouver le contrôleur de domaine global utilisé:

    nltest /DSGETDC:deployadmin.com /GC
Intégrer une machine au domaine en ligne de commande:

    Add-Computer -DomainName deployadmin.com -DomainCredential administrateur@deployadmin.com -OUPath "OU=fixies,OU=Ordinateurs,DC=Deployadminb,DC=com"
Gestion d'object:

    Dsadd : Ajout
    Dsget : Affichage
    Dsmod : Modification
    Dsmove : Déplacements
    Dsquery : Recherche
    Dsrm : Suppression

Ajouter un utilisateur:

    C:\ dsadd user CN=John,CN=Users,DC=it,DC=uk,DC=savilltech,DC=com -samid John -pwd Pa55word
Plus complet:

    C:\ dsadd user CN=John,CN=Users,DC=it,DC=uk,DC=savilltech,DC=com -samid John -pwd Pa55word -fn John -ln Savill -display "John Savill" -email john@savilltech.com -webpg http://www.savilltech.com -pwdneverexpires yes -memberof "CN=Domain Admins,CN=Users,DC=it,DC=uk,DC=savilltech,DC=com" -->
