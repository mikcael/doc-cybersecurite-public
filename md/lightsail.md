# Lightsail - créer une instance avec un bureau

Rendez-vous sur [lightsail](https://lightsail.aws.amazon.com) pour créer un serveur privé virtuel.

Créer une instance ubuntu en OS seul avec l'option à 5$.

# 1. Configurer SSH
Considérons l'utilisateur ubuntu, on peut également en créer un autre avec la commande `adduser` avant.

  $ sudo passwd ubuntu
  $ sudo nano /etc/ssh/sshd_config -> PasswordAuthentification à Yes
  $ sudo /etc/init.d/ssh restart


# 2a. Installer XFCE

  $ sudo apt update
  $ sudo apt install xrdp xfce4 xfce4-goodies tightvncserver
  $ echo xfce4-session> /home/ubuntu/.xsession
  
# 2b. Installer Mate
  
    $ sudo apt update
    $ sudo apt install xrdp ubuntu-mate-desktop tightvncserver
  
    $ echo "mate-session" > ~/.xsession

# 3 Finir la configuration de xrdp

  $ sudo cp /home/ubuntu/.xsession /etc/skel
  $ sudo sed -i '0,/-1/s//ask-1/' /etc/xrdp/xrdp.ini
  $ sudo service xrdp restart
  $ sudo reboot

Penser à ouvrir le port 3389 dans la config lightsail.

# Accessibilité
L'instance est accessible via:
* ssh : dans une console 

    $ ssh ubuntu@adresse-ip

* Microsoft Remode Desktop

    Add PC : adresse-ip de l'instance
    user : ubuntu/ubuntu