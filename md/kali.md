# Install Kali

## Wifi

    $ sudo apt update
    $ sudo apt install make gcc linux-headers-$(uname -r) build-essentials git
    $ git clone https://github.com/lwfinger/rtlwifi_new.git -b rtw88
    $ cd rtlwifi_new
    $ make
    $ sudo make install
    $ sudo modprobe -r rtw_8723de
    $ sudo modprobe rtw_8723de

## Tools

    $ sudo apt update
    $ sudo apt dist-upgrade

### VS code

    $ sudo apt install ./code_xxx.deb
    $ code

### VMware

    $ sudo bash ./VMware-xxx.bundle
    $ vmplayer

### Brave

    $ sudo apt install apt-transport-https curl
    $ curl -s https://brave-browser-apt-release.s3.brave.com/brave-core.asc | sudo apt-key --keyring /etc/apt/trusted.gpg.d/brave-browser-release.gpg add -
    $ echo "deb [arch=amd64] https://brave-browser-apt-release.s3.brave.com/ stable main" | sudo tee /etc/apt/sources.list.d/brave-browser-release.list
    $ sudo apt update
    $ sudo apt install brave-browser
    $ sudo apt-key add ./brake-key.gpg
    $ brave-browser

### pip

    $ curl -O https://bootstrap.pypa.io/get-pip.py
    $ python3 get-pip.py --user
    $ nano ~/.bashrc
        export PATH=$PATH:/chemin/vers/le/repertoire
    $ source ~/.bashrc

### Accéder à /opt pour l'utilisateur kali

    $ sudo mkdir /opt/ptf
    $ sudo chown -R kali /opt/ptf

### ptf

    $ cd /opt
    $ git clone https://github.com/trustedsec/ptf/
    $ cd ptf
    $ pip install -r requirements.txt
    $ sudo ./ptf
    $ use modules/install_update_all
        yes

### Red Baron
https://github.com/coalfire-Research/Red-Baron

### /opt/anonymity
https://github.com/keeganjk/kali-anonymous

	$ sudo anonymous start
	$ sudo anonymous stop
	$ sudo anonymous status
	$ sudo anonymous update
https://www.torproject.org/fr/thank-you/
https://github.com/GitHackTools/TotghostNGn

### /opt/password
https://github.com/davidtavarez/pwndb

	$ sudo apt install virtualenv	
	$ virtualenv venv
	$ source venv/bin/activate
	(venv) $ pip install -r requirements.txt
	(venv) $ python pwndb.py --target @microsoft.com
	$ deactivate // pour sortir de virutalenv

### /opt/postexploitation
https://github.com/EmpireProject/Empire

	$ sudo ./Empire/setup/install.sh
https://github.com/Ne0nd0g/merlin
https://github.com/samratashok/nishang
https://github.com/Cn33liz/p0wnedShell
https://github.com/n1nj4sec/pupy
https://github.com/thelinuxchoice/eviloffice

### vulnerability
https://github.com/swisskyrepo/SSRFmap
https://github.com/epinna/tplmap
https://github.com/frohoff/ysoserial

### C2
https://github.com/iagox86/dnscat2
https://github.com/nettitude/PoshC2
https://github.com/danilovazb/BabyShark/

### wifi
https://github.com/FluxionNetwork/fluxion

### reco 
https://github.com/m4ll0k/Shodanfy.py - Don't use this tool because your ip will be blocked by Shodan!
https://github.com/samhaxr/recox
https://github.com/dev-2null/ADCollector
https://github.com/luke-goddard/enumy
https://github.com/thelinuxchoice/locator
https://github.com/abdulgaphy/r3con1z3r

### repair
* remmettre @ mac permanent : $ macchanger -p wlan0
* modifier le nom d'hôte : $ nano /etc/hostname

### ssh
activer : # systemctl start/stop ssh.socket
permanent : # systemctl enable/disable ssh.service

### autre
Kali THP avec tous les outils : thehackerplaybook.com/get.php?type=THP-vm

