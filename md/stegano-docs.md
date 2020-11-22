# Steganographie

## Cacher un teste dans une image avec `cat` et `unzip`
Pour cacher un message dans une image avec seulement `cat` et `unzip`:

    $ zip /tmp/file.zip /tmp/message.txt
    $ cat /tmp/image.jpg /tmp/file.zip > /tmp/image+message.jpg

Pour récupérer le message:

    $ unzip /tmp/image+message.jpg -d /tmp/message

## Cacher un fichier dans une image ou un audio avec `steghide`
`steghide` permet de cacher n'importe quel fichier dans un JPEG, un BMP, un WAV ou un AU.

Installer `steghide`:

    $ sudo apt install steghide

Embarquer un fichier:

    $ steghide embed -cf image.jpg -ef <hiddenFile>

Extraire un fichier:

    $ steghide extract -sf image.jpg 

Fonctionnalités supplémentaires:
* Définir le fichier de sortie à la création : ajouter `-sf <hiddenfile.txt>`
* Définir le fichier de sortie à l'extraction : ajouter `-xf <hiddenfile.txt>`
* Obtenir les infos sur une image : `$ steghide info image.jpg`
* Ontenir les algo de cryptage dispo : `$ steghide encinfo`
* Utiliser un algo de cryptage par exemple twofish cbc : 

    $ steghide embed -cf image.jpg -ef <hiddenFile> -e twofish cbc    

## Cacher deux messages avec `outguess`
`outguess` permet d'inclure deux message ce qui autorisera le déni.

Installation:

    $ sudo apt install outguess

Embarquer un message:

    $ outguess -d message.txt image.jpg out.jpg
Extraire un message:

    $ outguess -r out.jpg message.txt
Embarquer un message avec mdp:

    $ outguess -k "password" -d message.txt image.jpg out.jpg
Extraire un message avec mot de passe:

    $ outguess -k "password" -r out.jpg message.txt
Embarquer deux messages (le mot de passe s'applique pour le message important):

    $ outguess  -d message.txt -E -K "password" -D important.txt image.jpg out.jpg
Retrouver le premier message (sans mot de passe):

    $ outguess -r out.jpg message.txt
Retrouver le message important:

    $ outguess -k "password" -e -r out.jpg important.txt


## Cacher un message dans du texte avec `stegsnow`
`stegsnow` ajoute un message dans un texte brut en utilisants espaces et tabulations qui ne sont pas visibles.

Installation:

    $ sudo apt install stegsnow

Embarquer un message dans un fichier texte:

    $ stegsnow -m "le message a cacher" <in>.txt <out>.txt

Embarquer un fichier texte dans un fichier texte:

    $ stegsnow -f <hidden>.txt <in>.txt <out>.txt

Extraire le message:

    $ stegsnow <out>.txt

Extraire le message dans un fichier:

    $ stegsnow <out>.txt > <hidden>.txt

Fonctions supplémentaires:
* Ajouter un mot de passe à la création : `$ stegsnow -f <hidden>.txt -p "password" <in>.txt <out>.txt`
* Extraire un message avec un mot de passe : `$ stegsnow -p "mot de passe" <out>.txt`
* Utiliser la compression à la création : `$ stegsnow -C f <hidden>.txt <in>.txt <out>.txt`
* Utiliser la décompression à l'extraction : `$ stegsnow -C <out>.txt`

## Retrouver un texte dans une image
Parfois la commande `strings` peut suffire à afficher du texte embarqué dans une image.

## Encoder / décoder un message dans une image en jouant sur les bits de couleurs
`LSB-stenography` téléchargeable [ici](https://github.com/RobinDavid/LSB-Steganography) permet de cacher un message dans une image à travers les bits de couleurs.

Encoder:

    $ LSBSteg.py encode -i <input> -o <output> -f <file>
Décoder

    $ LSBSteg.py decode -i <input> -o <output>

## Récupérer les données EXIF d'une photo

    $ exiftool file.jpg

## Obtenir des infos sur l'image et la sténographie utilisée
Sur un png:

    $ pngcheck image.png
Vérifier les métadonnées avec `stegoveritas` téléchargeable [ici](https://github.com/bannsec/stegoVeritas):

    $ python3 stegoveritas.py stego.jpg

Détecter la sténo avec `zteg` téléchargeable [ici](https://github.com/zed-0xff/zsteg):

    $ zsteg -a stego.jpg

Détection de l'utilisation d'un outils stégo via les statistiques:

    $ stegdetect stego.jpg

## Cacher / extraire via le LSB d'un JPG
`jseg` téléchargeable [ici](https://github.com/lukechampine/jsteg).

Cacher:

    $ jsteg hide cover.jpg secret.txt stego.jpg

Extraire:

    $ jsteg reveal cover.jpg output.txt

## Cacher / extraire via le LSB d'un PNG
`openstego` téléchargeable [ici](https://github.com/syvaidya/openstego).

Embarquer:
    
    $ openstego embed -mf secret.txt -cf cover.png -p password -sf stego.png

Extraire:

    $ openstego extract -sf openstego.png -p abcd -xf output.txt


## Bruteforcer un jpeg

Issu de `outguess`:
    
    $ stegbreak -t o -f wordlist.txt stego.jpg

Issu de `jphide`:

    $ stegbreak -t p -f wordlist.txt stego.jpg

Issu de jsteg: 

    $ stegbreak -t j -f wordlist.txt stego.jpg

## Retrouver une image dans une image
`binwalk` permet d'analyser la structure d'un fichier image pour savoir comment il est structuré.

    $ binwalk <imagefile>
Si une image se trouve a une adresse, il est possible de tenter de l'extraire avec la commande `dd`:

    $ dd bs=1 skip=<@image> if=<imagefile> of=<extractfile>

Avec `@image` l'adresse de l'image identifée avec `binwalk`

## Audio
Un fichier audio peut être ouvert avec `audacity` pour être ralenti, accéléré, joué à l'envers ... pour trouver un indice.

L'outils spek, permet d'afficher clairement le spectre qui parfois contient la donnée:

    $ spek <soundfile>

## Vérifier l'intégrité d'un fichier autdio 

    $ ffmpeg -v info -i file.mp3 null -

## Cacher et extraire une donnée dans un fichier WAV / MP3
`AudioStego` téléchargeable [ici](https://github.com/danielcardeenas/AudioStego) permet de cacher et extraire une donnée dans un fichier audio. 

Embarquer un fichier ou message:

    $ hideme son.mp3 <hiddenfile>
    $ hideme son.mp3 "hidden message"
Extraire le message:

    $ hideme son.mp3 -f

## Encoder une image dans un spectre
`spectrology` téléchargeable [ici](https://github.com/solusipse/spectrology) permet de cacher une image dans un spectre audio.

    $ python spectrology.py image.bmp -b 13000 -t 19000

## PDF
Un fichier pdf peut contenir des objets et notamment un autre fichier. 
L'outil `peepdf`, téléchargeable [ici](https://github.com/jesparza/peepdf), permet de l'analyser:

    $ python peepdf -i <pdffile>
En sortie une liste d'objet potentiellement intéressant, que l'on peut suivre comme suit:

    > object <objectId>
    ...
    > object <objectId> > out.txt
Le fichier en sortie peut ou pas devoir être décrypté, ex si base64:

    $ base64 -d out.txt > <outfile>

Un autre outils est très pratique, `pdf-parser`:

    $ sudo apt install pdf-parser
    $ python pdf-parser.py -o <idObject> -f -d <insideFile> <pdfFile>

## Imprimante
Les imprimantes laisse des points jaunes difficlement observable correspondant au numéro de série de l'imprimante et à la date.
Pour l'observer, il faut accéder au claque de l'image avec gimp et supprimer le canale de couleur rouge et vert (l'image doit ête scannée avec une résolution au moins de 600x600 dpi). 

En zommant à 200% sur la page et en cherchant on va trouver les points jaunes (qui apparaissent ici noirs). Se basant sur la méthode de décodage suivant on retrouve toutes les infos. La méthode est décrite [ici](https://fr.wikipedia.org/wiki/Code_d%27identification_de_machine).

## Twitter
Certaines phrases Twitter sont des Steg If The Dump sur Twitter, décryptable [ici](https://twsteg.devsec.fr/).
