# Failles web - CSRF (ou XSRF)

## Description
L'attaque CSRF (Cross Site Request Forgery ou XSRF) consiste à faire exécuter par des utilisateurs une ou plusieurs requêtes non désirées sur un site donné, forgées par un utilisateur malintentionné. 
Il est préférable que la victime ait des droits privilégiés comme l'admin.
Forger une requête consiste à modifier ou créer une requête HTTP (via URL ou formulaire) exécutant une action spécifique sur le site. Le script ou la ressource ciblée est accessible sans intermédiaire (pas de nouvelles authentifications, jetons ou autre ...).

## Détection
Il n'y pas vraiment de process automatisable pour cette faille. Les outils types ZAP ou BurpSuite facilitent la détection de dispositif anti-csrf ou la recherche de formulaire vulnérable mais les tests manuels restent les plus opportuns.

## Intention
L'exploitation de la faille CSRF permettent de:
* Opérations non désiré par un utilisateur (opération bancaires ?...)
* Changement de configuration réseau / Wifi, webmail ...
* Usurpation d'identité

## Exploitation
Par exemple sur un site disposant d'un script accessible via une URL supprimant un utilisateur:

    http://domain.com/rmuser.php?user=banni

Et d'un mécanisme de gestion de commentaires vulnérable à la faille XSS, il suffirait d'injecter dans le commentaire une image pointant vers l'URL de la page de suppression que l'administrateur déclencherait involontairement en accédant au commentaire.

## Prévention
Pour se prémunir il est possible d'utiliser des design pattern:
* Synchonizer Token Pattern (Authentification par jeton)
* Double Submit Pattern (si le site est aussi vulnéravle au XSS)

Il faut aussi vérifier les champs dans la requête :
* HTTP Referer
* HTTP Origin

Des mécanismes possibles via l'OWASP:
* OWASP CSRF GUARD
* OWASP ENTERPRISE SECURITY API

## Liens
https://blog.clever-age.com/fr/2014/06/25/owasp-cross-site-request-forgery-csrf-ou-xsrf/
https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet
https://www.cert.ssi.gouv.fr/information/CERTA-2008-INF-003/