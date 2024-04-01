# LINFO1341: Projet 1

## Informations Générales

- **Auteurs**:
  - Gloria Akli-Kodjo-Mensah, étudiante à l'UCLouvain, School Of Engineering
  - Mohamed-Anass GALLASS, étudiant à l'UCLouvain, School Of Engineering
- **Date**: Mars 2024

## Objectif

Ce rapport vise à analyser le trafic réseau généré par l'application Dropbox, dans le cadre du cours LINFO1341 - Réseaux informatiques, enseigné par le professeur Olivier Bonaventure à l'Université catholique de Louvain. Les données ont été capturées à la fois en réseaux wifi et 4G.

## Scénarios de Tests

Les captures de trafic ont été effectuées pour les scénarios suivants, en wifi et 4G :

- `0_before.pcapng`: Avant les tests de scénarios
- `1_connexion.pcapng` : Connexion à Dropbox
- `2_folder.pcapng`: Création d'un dossier
- `3a_upload_word.pcapng` : Upload d'un document word
- `3b_upload_video.pcapng` : Upload d'une video
- `4a_visu_word.pcapng` : Visualisation du word
- `4b_visu_video.pcapng` : Visualisation de la vidéo
- `5a_download_word.pcapng` : Téléchargement du word
- `5b_download_video.pcapng`: Téléchargement de la vidéo
- `6_delete_video.pcapng` : Supression de la vidéo
- `7_share_word.pcapng` : Partage du word à un autre utilisateur
- `8_modif_shared_word.pcapng` : modification du word de part et d'autre
- `9_deconnexion.pcapng` : Déconnexion de Dropbox

## Structure du Projet
Des scripts ont été créés pour chaque partie de l'analyse. 
- Pour l'analyse DNS, des notebooks ont été créés : **1_dns_4G.ipynb** & **1_dns_4G.ipynb**
- Pour les analyses couche transport, couche réseaux et chiffrement & sécurité : **2_analyse.py**
- Pour la partie application : **3_application_4G.py** & **3_application_wifi.py**

Un scripit **merge_pcapng.sh** a également été créé pour fusionner les différents frames de scénario en un 1 seul fichier pour les tests en wifi et en 4G.

Dans le dosser capture/, les éléments centrales à considérer sont :

- **caputure/4G**: Contient les captures et analyses en 4G
  - **wireshark**: Captures Wireshark selon les scénarios de tests
  - **Swireshark/SLKEYLOG/sslKEY4G**: Fichiers SSL key log pour le trafic 4G
  - **certificates_4G.csv** : les datas des certificats nécessaires à l'analayse.
- **caputure/wifi**: Contient les captures et analyses en wifi
  - **wireshark**: Captures Wireshark selon les scénarios de tests
  - **wireshark/SSLKEYLOG/sslKEYWIFI**: Fichiers SSL key log pour le trafic wifi
  - **certificates.csv** : les datas des certificats nécessaires à l'analayse.
