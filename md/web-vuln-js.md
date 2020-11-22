# Vulnérabilités Javascript côté client

La tendance actuelle est de mettre de plus en plus de fonctionnel côté client, ce qui augmente la surface d'attaque de ce côté et donc rend plus intéressant l'analyse statique du code Javascript. On cherche:
* des infos pour augmenter la surface d'attaque
* des infos sensibles (password ...)
* des portions de code dangeureuses (eval, dangerouslySetInnerHTML, etc)
* des vulnérabilités connues

Une fois le scan fait avec Burp, il est possible dans le `proxy` d'aller dans l'onglet `http history` pour ne sélectionner que les fichiers JS, et on a la liste des URL.

Un autre moyen est d'utiliser les [archives web](https://archive.org/web/) à la recherche de code JS qui n'était pas effacé ou avec l'outil [waybackurls](https://github.com/tomnomnom/waybackurls/) écrit en golang:

    go get github.com/tomnomnom/waybackurls
    waybackurls internet.org | grep "\.js" | uniq | sort

Pour trier les faux positifs, utiliser `curl`:

    cat js_files_url_list.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk

Pour gagner du temps on peut utiliser [hackcheckurl](https://github.com/hakluke/hakcheckurl), un outils en golang lui aussi:

    go get github.com/hakluke/hakcheckurl
    cat lyftgalactic-js-urls.txt | hakcheckurl

A ce stade, nous avons les JS intéressants. Mais ils peuvent être minifié ou obfusqué. 
* Pour dé-minifier : [JS-Beautifier](https://github.com/beautify-web/js-beautify). Pour minifier on peut utiliser [UglifyJS.](https://github.com/mishoo/UglifyJS)
* Pour déobfusquer : 
    * [JStillery](https://github.com/mindedsecurity/JStillery)
    * [JSDetox](http://relentless-coding.org/projects/jsdetox)
    * JS-[Beautifier](https://github.com/einars/js-beautify)
    * [IlluminateJs](https://github.com/geeksonsecurity/illuminatejs)
    * [JSNice](http://www.jsnice.org/)

Maintenant le code à analyser est dispo. Nous allons pouvoir rechercher des infos intéressantes.
## Nouveaux sources à analyser pour augmenter la surface d'attaque
* [relative-url-extractor](https://github.com/jobertabma/relative-url-extractor)
* [LinkFinder](https://github.com/GerbenJavado/LinkFinder):

    python linkfinder.py -i https://example.com -d -o cli

## Informations sensibles, clés, token, creds ...
* [DumpsterDiver](https://github.com/securing/DumpsterDiver)
* [Repo-supervisor](https://github.com/auth0/repo-supervisor#repo-supervisor) 
* [truffleHog](https://github.com/dxa4481/truffleHog)
* grep / sed / awk ...

## Failles laissées par les développeurs
* `innerHTML` peut provoquer une faille XSS
* `dangerouslytSetInnerHTML` en React peut conduire aussi a une faille XSS
* `bypassSecurityTrustX` en Angular peut conduire à une faille XSS (avec X qui peut être Html, Script, Style, Url, RessourceUrl)
* `eval` peut s'avérer dangeureux côté client et server
* `window.postMessage` et `window.addEventListener` pour transférer des données peut être contourné en modifiant l'origine
* `window.localStorage` et `window.sessionStorage` qui permettent un stockage local

## Vulnérabilités 
* [JSPrime](https://github.com/dpnishant/jsprime), outils d'analyse statique
* [ESLint](https://github.com/eslint/eslint), un des plus populaires, propose de nombreuses règles de sécurités pour Angular et React

## Identifier d'anciens framework vulnérable
[Retire.js](https://retirejs.github.io/retire.js/) : recherche de framework obsolète

## Links
Quelques [fonctions dangeuseus JS](http://blog.blueclosure.com/2017/09/javascript-dangerous-functions-part-1.html) et le [DOM based XSS](http://blog.blueclosure.com/2017/10/javascript-dangerous-functions-part-2_29.html).
