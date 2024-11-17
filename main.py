import tkinter as tk
from tkinter import messagebox, ttk
import nmap
import socket
import subprocess
import json
import os
from pysnmp.hlapi import *
import networkx as nx
import matplotlib.pyplot as plt

# Définir la version de l'application
APP_VERSION = "1.0.3"

# Scanner Nmap
scanner = nmap.PortScanner()
machines_connectees = []  # Liste pour stocker les machines découvertes

# Fonction pour obtenir l'adresse IP locale et le nom de la machine
def obtenir_infos_locales():
    nom_machine = socket.gethostname()
    adresse_ip = socket.gethostbyname(nom_machine)
    return adresse_ip, nom_machine

# Fonction pour obtenir les adresses MAC
def detecter_adresses_mac():
    try:
        result = os.popen("arp -a").read()  # Utilise la commande 'arp -a' pour obtenir les adresses MAC
        messagebox.showinfo("Adresses MAC", result)
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de détecter les adresses MAC : {str(e)}")

# Fonction pour lancer un scan réseau
def lancer_scan():
    global machines_connectees
    ip_range = "192.168.1.0/24"  # Plage d'adresses IP à scanner
    try:
        scanner.scan(hosts=ip_range, arguments='-p 1-1024')
        machines_connectees = [host for host in scanner.all_hosts()]
        nombre_machines = len(machines_connectees)

        # Mettre à jour la liste déroulante avec les machines découvertes
        liste_machines["values"] = machines_connectees
        if machines_connectees:
            liste_machines.current(0)  # Sélectionne la première machine par défaut

        # Afficher et sauvegarder le rapport de scan
        afficher_resultats_scan(nombre_machines, machines_connectees)
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur lors du scan réseau : {str(e)}")

# Fonction pour afficher et sauvegarder les résultats du scan
def afficher_resultats_scan(nombre_machines, machines_connectees):
    rapport = {
        "nombre_machines": nombre_machines,
        "machines_connectees": machines_connectees
    }
    # Sauvegarde du rapport dans un fichier JSON
    with open("scan_report.json", "w") as f:
        json.dump(rapport, f, indent=4)

    messagebox.showinfo("Résultats du Scan", f"Nombre de machines connectées : {nombre_machines}")
    print(f"Rapport de scan sauvegardé dans scan_report.json")

# Fonction pour lancer un scan avancé sur la machine sélectionnée
def lancer_scan_avance():
    cible = liste_machines.get()  # Récupère l'adresse IP sélectionnée
    if cible:
        try:
            scanner.scan(hosts=cible, arguments='-A')
            details = scanner[cible]
            rapport = json.dumps(details, indent=4, default=str)

            # Afficher les résultats du scan avancé
            messagebox.showinfo("Scan Avancé", f"Résultats du scan avancé pour {cible} :\n{rapport}")
            with open(f"scan_avance_{cible}.json", "w") as f:
                f.write(rapport)
            print(f"Rapport de scan avancé sauvegardé dans scan_avance_{cible}.json")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du scan avancé : {str(e)}")
    else:
        messagebox.showwarning("Avertissement", "Veuillez sélectionner une machine pour le scan avancé.")

# Fonction pour mesurer la latence WAN (ping)
def mesurer_latence(cible):
    try:
        result = subprocess.run(['ping', '-c', '4', cible], capture_output=True, text=True)
        latence = parse_ping_output(result.stdout)
        messagebox.showinfo("Latence WAN", f"Latence moyenne vers {cible}: {latence} ms")
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de mesurer la latence : {str(e)}")

# Fonction pour analyser la sortie de la commande ping
def parse_ping_output(output):
    lignes = output.split('\n')
    for ligne in lignes:
        if "avg" in ligne or "moyenne" in ligne:
            latence = ligne.split('/')[4]
            return latence
    return "Indisponible"

# Fonction pour tester la bande passante
def tester_bande_passante():
    serveur_iperf = entry_iperf.get()
    if not serveur_iperf:
        messagebox.showwarning("Attention", "Veuillez entrer l'adresse IP du serveur iperf.")
        return
    try:
        result = subprocess.run(['iperf3', '-c', serveur_iperf], capture_output=True, text=True)
        rapport = result.stdout
        messagebox.showinfo("Test de Bande Passante", rapport)
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de tester la bande passante : {str(e)}")

# Fonction pour interroger SNMP
def interroger_snmp(ip):
    try:
        for (errorIndication, errorStatus, errorIndex, varBinds) in getCmd(
            SnmpEngine(),
            CommunityData('public', mpModel=0),
            UdpTransportTarget((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),  # Exemple d'OID
        ):
            if errorIndication:
                messagebox.showerror("Erreur SNMP", str(errorIndication))
                return
            elif errorStatus:
                messagebox.showerror("Erreur SNMP", f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')
                return
            else:
                for varBind in varBinds:
                    messagebox.showinfo("SNMP", f'{varBind[0]} = {varBind[1]}')
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible d'interroger SNMP : {str(e)}")

# Fonction pour afficher la topologie réseau
def afficher_topologie():
    G = nx.Graph()
    G.add_node("Routeur")
    G.add_nodes_from(machines_connectees)
    for machine in machines_connectees:
        G.add_edge("Routeur", machine)

    nx.draw(G, with_labels=True, node_color='lightblue', node_size=2000, font_size=10)
    plt.show()

# Interface Tkinter
root = tk.Tk()
root.title("Seahawks Monitoring")

# Obtenir les infos locales et les afficher
adresse_ip, nom_machine = obtenir_infos_locales()
label_infos = tk.Label(root, text=f"Adresse IP Locale : {adresse_ip}\nNom de la Machine : {nom_machine}\nVersion : {APP_VERSION}")
label_infos.pack(pady=10)

# Bouton pour détecter les adresses MAC
btn_adresses_mac = tk.Button(root, text="Détecter les Adresses MAC", command=detecter_adresses_mac)
btn_adresses_mac.pack(pady=10)

# Bouton pour lancer le scan réseau
btn_scan = tk.Button(root, text="Lancer le Scan Réseau", command=lancer_scan)
btn_scan.pack(pady=10)

# Liste déroulante pour sélectionner une machine
label_selection = tk.Label(root, text="Sélectionnez une machine pour le scan avancé :")
label_selection.pack(pady=5)
liste_machines = ttk.Combobox(root)
liste_machines.pack(pady=5)

# Bouton pour lancer le scan avancé
btn_scan_avance = tk.Button(root, text="Lancer le Scan Avancé", command=lancer_scan_avance)
btn_scan_avance.pack(pady=10)

# Bouton pour mesurer la latence WAN
btn_latence = tk.Button(root, text="Mesurer la Latence WAN", command=lambda: mesurer_latence("8.8.8.8"))
btn_latence.pack(pady=10)

# Champ de saisie pour l'adresse IP du serveur iperf
label_iperf = tk.Label(root, text="Adresse IP du serveur iperf :")
label_iperf.pack(pady=5)
entry_iperf = tk.Entry(root)
entry_iperf.pack(pady=5)

# Bouton pour tester la bande passante
btn_bande_passante = tk.Button(root, text="Tester la Bande Passante", command=tester_bande_passante)
btn_bande_passante.pack(pady=10)

# Bouton pour interroger SNMP
btn_snmp = tk.Button(root, text="Interroger SNMP", command=lambda: interroger_snmp("192.168.1.1"))
btn_snmp.pack(pady=10)

# Bouton pour afficher la topologie réseau
btn_topologie = tk.Button(root, text="Afficher la Topologie du Réseau", command=afficher_topologie)
btn_topologie.pack(pady=10)

root.mainloop()
