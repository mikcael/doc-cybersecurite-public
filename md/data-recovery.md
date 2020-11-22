# Forensic - Data recovery

## liens
* https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download
* https://blogs.sans.org/computer-forensics/files/2012/06/SANS-Digital-Forensics-and-Incident-Response-Poster-2012.pdf
* https://k-lfa.info/quelques-tools-forensics/
* https://k-lfa.info/forensic-windows/

## Tools

Plusieurs outils pour cela.

`foremost`

    $ sudo apt intall foremost
    $ foremost image.raw
Voir aussi l'outils `scalpel` basé sur `foremost`. Il faut décommenter les types de fichiers recherchés dans le fichier de conf.

`dd_rescue` téléchargeable [ici](http://www.garloff.de/kurt/linux/ddrescue/)

    $ dd_rescue sda1 file.img

`ntfsundelete` téléchargeable [ici](https://www.ntfsundelete.com/download), pour les système NTFS

    $ umount /mnt/NTFS
    $ ntfsundelete /dev/sdb1

`fatback` téléchargeable [ici](https://github.com/gaul/fatback/blob/master/INSTALL), pour le système FAT.

`sleuthkit` téléchargeable [ici](https://www.sleuthkit.org/sleuthkit/download.php), suite permettant de faciliter le travail sur les partitions.

`testdisk` téléchargeable [ici](https://www.cgsecurity.org/wiki/TestDisk_FR), suite permettant:
* Réparer la table des partitions, récupérer des partitions perdues
* Récupérer le secteur de boot d'une partition FAT32 à partir de sa sauvegarde
* Reconstruire le secteur de boot d'un système de fichier FAT12, FAT16 ou FAT32
* Réparer les tables FAT
* Reconstruire le secteur de boot NTFS
* Restaurer le secteur de boot NTFS à partir de sa sauvegarde
* Réparer la MFT à partir de sa sauvegarde (MFT miroir)
* Localiser un superblock de secours pour une partition ext2/ext3 ou ext4
* Récupérer un fichier effacé d'une partition FAT, NTFS ou ext2
* Copier les fichiers depuis une partition FAT, NTFS, ext2/ext3/ext4 même si elle est effacée.