import subprocess
import pyshark
import matplotlib.pyplot as plt

def get_stats_and_ips(file):
    """Fonction combinée pour obtenir les statistiques de tshark et les adresses IP uniques."""
    # Exécution de tshark pour les statistiques
    stats_result = subprocess.run(["tshark", "-r", file, "-q", "-z", "io,stat,0"], capture_output=True, text=True)
    stats = stats_result.stdout
    
    # Utilisation de pyshark pour obtenir les adresses IP uniques
    cap = pyshark.FileCapture(file, only_summaries=True)
    ip_addresses = {packet.source for packet in cap} | {packet.destination for packet in cap}

    # Fermeture de la capture pour libérer les ressources
    cap.close()

    return stats, ip_addresses

def analyze_and_plot(files):
    scenarios = []
    data_volumes = []
    frame_counts = []

    for file in files:
        stats, ips = get_stats_and_ips(file)
        scenario_label = file.split('/')[-1].replace('.pcapng', '')

        # Initialiser les variables pour le comptage et le volume des données pour chaque fichier
        frame_count_for_file = 0
        bytes_count_for_file = 0
        
        # Extraire les données pertinentes des statistiques
        for line in stats.split('\n'):
            if "|<>" in line:  # Vérifie que la ligne contient les marqueurs attendus
                parts = line.split('|')
                if len(parts) > 4:
                    try:
                        frame_count_for_file = int(parts[1].split()[2])  # Troisième élément après split
                        bytes_count_for_file = int(parts[2].split()[0])  # Premier élément
                    except ValueError as e:
                        print(f"Erreur lors de l'extraction des données pour {scenario_label}: {e}")
                    except IndexError as e:
                        print(f"Erreur d'index lors de l'analyse des statistiques pour {scenario_label}: {e}")

        # Ajouter les données à la liste seulement si elles ont été correctement extraites
        if frame_count_for_file and bytes_count_for_file:
            scenarios.append(scenario_label)
            data_volumes.append(bytes_count_for_file)
            frame_counts.append(frame_count_for_file)
        
        print(f"Résultats pour {scenario_label}:\n{stats}")
        print(f"IPs uniques pour {scenario_label}: {ips}\n")

    # Vérification pour s'assurer que les listes ne sont pas vides avant de tracer
    if scenarios and data_volumes and frame_counts:
        # Création des graphiques
        plt.figure(figsize=(12, 6))
        plt.subplot(1, 2, 1)
        plt.bar(scenarios, data_volumes, color='skyblue')
        plt.xticks(rotation=45, ha="right")
        plt.ylabel('Volume de données (bytes)')
        plt.title('Volume de données par scénario')
        
        plt.subplot(1, 2, 2)
        plt.bar(scenarios, frame_counts, color='lightgreen')
        plt.xticks(rotation=45, ha="right")
        plt.ylabel('Nombre de Frames')
        plt.title('Nombre de Frames par scénario')
        
        plt.tight_layout()
        plt.show()
    else:
        print("Aucune donnée à afficher.")




# Liste des fichiers pcapng à analyser
# Liste des fichiers pcapng à analyser
files = [
    "wireshark/0_4G_before.pcapng",
    "wireshark/1_4G_connexion.pcapng",
    "wireshark/2_4G_folder.pcapng",
    "wireshark/3a_4G_upload_word.pcapng",
    "wireshark/3b_4G_upload_video.pcapng",
    "wireshark/4a_4G_visu_word.pcapng",
    "wireshark/4b_4G_visu_video.pcapng",
    "wireshark/5a_4G_download_word.pcapng",
    "wireshark/5b_4G_download_video.pcapng",
    "wireshark/6_4G_delete_video.pcapng",
    "wireshark/7_4G_share_word.pcapng",
    "wireshark/8_4G_modif_shared_word.pcapng",
    "wireshark/9_4G_deconnexion.pcapng"
]


analyze_and_plot(files)
