#!/bin/bash

# 4G : 

DIRECTORY="capture/4G/wireshark"

# Définir le nom du fichier de sortie
OUTPUT_FILE="merged_4G.pcapng"

# Utiliser mergecap pour fusionner les fichiers
mergecap -w "$DIRECTORY/$OUTPUT_FILE" \
    "$DIRECTORY/1_4G_connexion.pcapng" \
    "$DIRECTORY/2_4G_folder.pcapng" \
    "$DIRECTORY/3a_4G_upload_word.pcapng" \
    "$DIRECTORY/3b_4G_upload_video.pcapng" \
    "$DIRECTORY/4a_4G_visu_word.pcapng" \
    "$DIRECTORY/4b_4G_visu_video.pcapng" \
    "$DIRECTORY/5a_4G_download_word.pcapng" \
    "$DIRECTORY/5b_4G_download_video.pcapng" \
    "$DIRECTORY/6_4G_delete_video.pcapng" \
    "$DIRECTORY/7_4G_share_word.pcapng" \
    "$DIRECTORY/8_4G_modif_shared_word.pcapng" \
    "$DIRECTORY/9_4G_deconnexion.pcapng"

echo "Les fichiers ont été fusionnés dans $DIRECTORY/$OUTPUT_FILE"

# WIFI : 

DIRECTORY="capture/wifi/wireshark"

# Définir le nom du fichier de sortie
OUTPUT_FILE="merged_wifi.pcapng"

# Utiliser mergecap pour fusionner les fichiers
mergecap -w "$DIRECTORY/$OUTPUT_FILE" \
    "$DIRECTORY/1_wifi_connexion.pcapng" \
    "$DIRECTORY/2_wifi_folder.pcapng" \
    "$DIRECTORY/3a_wifi_upload_word.pcapng" \
    "$DIRECTORY/3b_wifi_upload_video.pcapng" \
    "$DIRECTORY/4a_wifi_visu_word.pcapng" \
    "$DIRECTORY/4b_wifi_visu_video.pcapng" \
    "$DIRECTORY/5a_wifi_download_word.pcapng" \
    "$DIRECTORY/5b_wifi_download_video.pcapng" \
    "$DIRECTORY/6_wifi_delete_video.pcapng" \
    "$DIRECTORY/7_wifi_share_word.pcapng" \
    "$DIRECTORY/8_wifi_modif_shared_word.pcapng" \
    "$DIRECTORY/9_wifi_deconnexion.pcapng"

echo "Les fichiers ont été fusionnés dans $DIRECTORY/$OUTPUT_FILE"

