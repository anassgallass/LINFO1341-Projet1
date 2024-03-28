import csv
import datetime
import ssl
from matplotlib import pyplot as plt
import numpy as np
import pyshark
import os
import dns.resolver
import socket
import pandas as pd
import OpenSSL.crypto





folder_path = 'capture/wifi/wireshark/'
folder_path_4G = 'capture/4G/wireshark/'

"""
for file_path in os.listdir(folder_path):
    file_path = os.path.join(folder_path, file_path)
    if not file_path.endswith('.pcapng') or file_path == '0_wifi_before.pcapng' or file_path == "0_4G_before.pcapng":
        continue
    print('-'*50)
    with pyshark.FileCapture(file_path, display_filter='ip') as cap:

        ip_destinations = set()
        ip_to_domain = {}

        print(file_path)
        print("Number of packets: ", len(list(cap)))
        for pkt in cap:
            if 'IP' in pkt:
                ip_destinations.add(pkt.ip.dst)

                if hasattr(pkt, 'dns') and pkt.dns.qry_name:
                    domain = pkt.dns.qry_name
                    ip_to_domain[pkt.ip.dst] = domain


        for ip in ip_destinations:
            if ip not in ip_to_domain:
                try:
                    domain_name = socket.gethostbyaddr(ip)[0]
                    ip_to_domain[ip] = domain_name
                except socket.herror:
                    pass

        for ip, domain in ip_to_domain.items():
            print(f"{ip} -> {domain}")

        # Check for NAT Traversal Techniques like STUN
        with pyshark.FileCapture(file_path, display_filter='stun') as stun_packets:
                
            if len(list(stun_packets)) > 0:
                print("\nNumber of STUN packets: ", len(list(stun_packets)))
            else:
                print("\nNo STUN packets were found")

        def is_ip_in_range(ip_parts, start, end):
            return all(s <= ip <= e for s, ip, e in zip(start, ip_parts, end))

        private_ips = [
            ((10, 0, 0, 0), (10, 255, 255, 255)),
            ((172, 16, 0, 0), (172, 31, 255, 255)),
            ((192, 168, 0, 0), (192, 168, 255, 255))
        ]
        private_count = 0
        public_count = 0
        for ip in ip_destinations:
            parts = tuple(map(int, ip.split('.')))
            is_private = False
            for range_start, range_end in private_ips:
                if is_ip_in_range(parts, range_start, range_end):
                    is_private = True
                    break
            print("\n")
            if is_private:
                print(f"{ip} is a private IP address")
                private_count += 1
            else:
                print(f"{ip} is a public IP address")
                public_count += 1


        print("\nAnalysis:")
        print("\nPrivate count:", private_count) # number of private IP addresses which are not NATed
        print("\nPublic count:", public_count)

    #---------------------------------------------------------------------------------------end of couche_reseau ---------------------------------------------------------------------------------------#
    
def get_protocol_proportion(file_path, protocol):
    protocol_count = 0
    total_count = 0

    cap = pyshark.FileCapture(file_path)
    for pkt in cap:
        total_count += 1
        if protocol in pkt:
            protocol_count += 1

    cap.close()

    if total_count == 0:
        return 0.0
    
    protocol_proportion = protocol_count / total_count
    return protocol_proportion

def extract_mss(file_path):
    mss_list = []

    cap = pyshark.FileCapture(file_path, display_filter='tcp.flags.syn == 1 && tcp.flags.ack == 0')

    for pkt in cap:
        if 'tcp' in pkt and hasattr(pkt.tcp, 'options_mss_val'):
            if(int(pkt.tcp.options_mss_val) not in mss_list):
                mss_list.append(int(pkt.tcp.options_mss_val))

    cap.close()

    return mss_list

def extract_mss_ack(file_path):
    mss_list = []

    cap = pyshark.FileCapture(file_path, display_filter='tcp.flags.syn == 1 && tcp.flags.ack == 1')

    for pkt in cap:
        if 'tcp' in pkt and hasattr(pkt.tcp, 'options_mss_val'):
            if(int(pkt.tcp.options_mss_val) not in mss_list):
                mss_list.append(int(pkt.tcp.options_mss_val))

    cap.close()

    return mss_list

def process_quic_packet(file_path):
    id_list = []
    cap = pyshark.FileCapture(file_path)
    for packet in cap:
        if 'quic' in packet and hasattr(packet.quic, 'dcil') and hasattr(packet.quic, 'scil')  :
            destination_connection_id_length = packet.quic.dcil
            source_connection_id_length = packet.quic.scil
            if (destination_connection_id_length,source_connection_id_length) not in id_list:
                id_list.append((destination_connection_id_length,source_connection_id_length))
    cap.close()
    return id_list


protocols = ["TCP", "UDP", "QUIC"]
protocol_stats = {protocol: [] for protocol in protocols}
file_names = ["connection", "folder","upload word", "upload video", "visu word", "visu video", "download word", "download video", "delete video", "share word", "modify shared word", "deconnection"]

for file_path in os.listdir(folder_path):
    if not file_path.endswith('.pcapng') or file_path == '0_wifi_before.pcapng' or file_path == "0_4G_before.pcapng":
        continue

    print('-'*50)
    print(file_path+'\n')

    file_path = os.path.join(folder_path, file_path)
    
    with pyshark.FileCapture(file_path) as cap:
        for protocol in protocols:
            protocol_stats[protocol].append(get_protocol_proportion(file_path, protocol))
            print(f"{protocol}: {protocol_stats[protocol][-1]}")
    
    print("MSS Values:", extract_mss(file_path))
    print("MSS Values ACK:", extract_mss_ack(file_path))
    print(process_quic_packet(file_path))

# Création du graphique
bar_width = 0.25
index = np.arange(len(file_names))
colors = ['#406eb8', '#40b880', '#b84840']

for i, protocol in enumerate(protocols):
    plt.bar(index + i * bar_width, protocol_stats[protocol], bar_width, label=protocol, color=colors[i])

plt.xlabel('Fichier')
plt.ylabel('Proportion du protocole')
plt.title('Comparaison des protocoles TCP, UDP et QUIC')
plt.xticks(index + bar_width, file_names, rotation=90)
plt.legend()
plt.tight_layout()
plt.show()
plt.savefig('protocole_proportion_4G.png')


#--------------------------------------------------------------------------------------- chiffrement ---------------------------------------------------------------------------------------#

def check_dns_security(domain):

    try:
        ip_address = socket.gethostbyname(domain)
        print(f"Le DNS pour le domaine {domain} est sécurisé avec technique 1. L'adresse IP est {ip_address}.")
    except socket.gaierror as e:
        print(f"Impossible de résoudre le domaine {domain}. Erreur : {e}")
        return False

check_dns_security('fp.dropbox.com')

for file_path in os.listdir(folder_path_4G):
    if not file_path.endswith('.pcapng') or file_path == '0_wifi_before.pcapng' or file_path == "0_4G_before.pcapng":
        continue

    print('-'*50)
    print(file_path+'\n')

    file_path = os.path.join(folder_path_4G, file_path)

    versions = {'TLS 1.3':0, 'TLS 1.2': 0, 'TLS 1.0': 0}
    contents = {'Application Data':0, 'Change Cipher Spec':0, 'Handshake':0}
    
    with pyshark.FileCapture(file_path) as cap:
        for packet in cap:
            try: 
                tls = packet.tls
                record_versions = [field.showname_value.split('(')[0][0:-1] for field in tls.record_version.all_fields]
                for v in record_versions: versions[v] += 1    #Compte les versions

                content_type = [field.showname_value.split('(')[0][0:-1] for field in tls.record_content_type.all_fields]
                for c in content_type: contents[c] += 1
                hs_types = [field.showname_value.split('(')[0][0:-1] for field in tls.handshake_type.all_fields]

                for hs_idx in range(len(hs_types)):
                    
                    if hs_types[hs_idx] == 'Client Hello': 
                        min_version = tls.record_version.showname_value.split('(')[0][0:-1]
                        max_version = tls.handshake_version.showname_value.split('(')[0][0:-1]
                        try: 
                            supported_versions = [field.showname_value.split('(')[0][0:-1] for field in tls.get("handshake.extensions.supported_version").all_fields]
                        except: 
                            continue

                    elif hs_types[hs_idx] == 'Server Hello':    
                        if tls.get('handshake.extensions.supported_version') != None:
                            versions['TLS 1.3'] += 1
                            versions['TLS 1.2'] -= 1
            except: 
                continue
        print(versions)
        print(contents)
"""

import OpenSSL.crypto

def analyze_tls_certificates(host, port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock) as ssock:
                cert = ssock.getpeercert(True)
    except:
        return None

    # Decode the X.509 certificate
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)

    # Extract certificate information
    return {
    "not_before": x509.get_notBefore().decode(),
    "not_after": x509.get_notAfter().decode(),
    "issuer": x509.get_issuer().CN,
    "subject": x509.get_subject().CN,
    }

def extract_domaine_name(path, column_name, hosts_list):
    df = pd.read_csv(path)
    host_names = df[column_name].dropna().unique()
    for host in host_names:
        if host not in hosts_list:
            hosts_list.append(host)
    return hosts_list

def format_date(date_string):
    date_obj = datetime.datetime.strptime(date_string, '%Y%m%d%H%M%SZ')
    return date_obj.strftime('%d-%m-%Y')

def generate_certificate_csv(hosts, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['Host', 'Issued By', 'Issued To', 'Valid From', 'Valid Until']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        print('-'*50)

        for host in hosts:
            print(f"Analyzing certificates for {host}")
            cert_info = analyze_tls_certificates(host, 443)
            if cert_info is None:
                print(f"Failed to retrieve certificate information for {host}\n")
                continue
            
            writer.writerow({
                'Host': host,
                'Issued By': cert_info['issuer'],
                'Issued To': cert_info['subject'],
                'Valid From': format_date(cert_info['not_before']),
                'Valid Until': format_date(cert_info['not_after'])
            })

            print(f"Certificate Info for {host}:{443}")
            print(f"  Issued By: {cert_info['issuer']}")
            print(f"  Issued To: {cert_info['subject']}")
            print(f"  Valid From: {cert_info['not_before']}")
            print(f"  Valid Until: {cert_info['not_after']}\n")


port = 443
hosts = []
csv_folder_path = 'capture/4G/wireshark/dns_csv/'
for file_path in os.listdir(csv_folder_path):
    if not file_path.endswith('.csv'):
        continue
    file_path = os.path.join(csv_folder_path, file_path)
    hosts = extract_domaine_name(file_path, 'dns.qry.name', hosts)

print(hosts)
generate_certificate_csv(hosts, '4G/certificates_4G.csv')


#--------------------------------------------------------------------------------------- end ---------------------------------------------------------------------------------------#