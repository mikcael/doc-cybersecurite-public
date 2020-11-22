# Bonnes pratiques

Un service ne doit pas etre configurer en domain admin

Un compte domain admin ne doit etre ouvert que sur une machine sécurisée c'est à dire chiffrée, protection contre le vol, patchée, à jour ...

Chiffrer les machines (bitlocker, truecrypt), et formattage bas niveau

3 comptes différents pour l'admin domain : admin domain, admin local (90% de l'admin), utilsateur (toute action ne nécessitant pas de droits)

Protéger le hash des mdp

Limiter nb login/mdp pour les utilisateurs et mdp forts 

Pas d ouverture de session avec fort privilège sur station standard (Station admin != Station std)

Déployer LAPS

Protéger les wifi (portail captif)

Désactiver les accès bluetooth non utilisé

Retirer les droits debug à l'admin local

Ne pas laisser les algos de dérivation de clé kerberos par défaut