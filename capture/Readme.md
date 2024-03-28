# LINFO1341: Projet 1

## Informations Générales

- **Auteurs**:
  - Mohamed-Anass GALLASS, étudiant à l'UCLouvain, School Of Engineering
  - Gloria Akli-Kodjo-Mensah, étudiante à l'UCLouvain, School Of Engineering
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

Le projet est organisé comme suit :

- **4G**: Contient les captures et analyses en 4G
  - `dns_4g_analysis.ipynb`
  - **dns_csv/img**: Images générées pour chaque scénario de tests
  - **wireshark**: Captures Wireshark selon les scénarios de tests
  - **SSLKEYLOG/sslKEY4G**: Fichiers SSL key log pour le trafic 4G
- **video**: Vidéos des tests de scénarios
  - `4G-video.webm`
  - `WIFI_video.webm`
- **wifi**: Contient les captures et analyses en wifi
  - `dns_wifi_analysis.ipynb`
  - **wireshark**: Captures Wireshark selon les scénarios de tests
  - **SSLKEYLOG/sslKEYWIFI**: Fichiers SSL key log pour le trafic wifi

### Arborescence du Projet

.
├── 4G
│   ├── dns_4g_analysis.ipynb
│   ├── dns_csv
│   │   └── img
│   └── wireshark
│       ├── ... (les captures wireshark selon les scéanarions de tests)
│       ├── dns_csv
│       │   ├── ... (fichiers dns en format csv)
│       │   ├── img
│       │   │   ├── ... (png générés pour chaque scnéarios de tests.)
│       └── SSLKEYLOG
│           └── sslKEY4G
├── video
│   ├── 4G-video.webm 
│   └── WIFI_video.webm
└── wifi
    ├── dns_wifi_analysis.ipynb
│   └── wireshark
│       ├── ... (les captures wireshark selon les scéanarions de tests)
│       ├── dns_csv
│       │   ├── ... (fichiers dns en format csv)
│       │   ├── img
│       │   │   ├── ... (png générés pour chaque scnéarios de tests.)
        └── SSLKEYLOG
            └── sslKEYWIFI