import tkinter as tk
from tkinter import messagebox, ttk
import nmap
import socket
import subprocess
import json
import os
import datetime
from pysnmp.hlapi import *
import networkx as nx
import matplotlib.pyplot as plt

# Définir la version de l'application
APP_VERSION = "1.0.6"

# Scanner Nmap
scanner = nmap.PortScanner()
machines_connectees = []

# Dossier pour sauvegarder les scans
base_scan_dir = "scanResults"
if not os.path.exists(base_scan_dir):
    os.mkdir(base_scan_dir)

# Créer un dossier pour chaque session
session_dir = os.path.join(
    base_scan_dir, f"scan_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
)
os.mkdir(session_dir)

# Fonction pour obtenir l'adresse IP locale et le nom de la machine
def obtenir_infos_locales():
    nom_machine = socket.gethostname()
    adresse_ip = socket.gethostbyname(nom_machine)
    return adresse_ip, nom_machine


# Fonction pour détecter les adresses MAC
def detecter_adresses_mac():
    try:
        result = os.popen("arp -a").read()
        report_path = os.path.join(session_dir, "adresses_mac_report.json")
        with open(report_path, "w") as f:
            json.dump({"adresses_mac": result}, f, indent=4)
        messagebox.showinfo("Adresses MAC", f"Rapport enregistré : {report_path}")
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de détecter les adresses MAC : {str(e)}")


# Fonction pour lancer un scan réseau
def lancer_scan():
    global machines_connectees
    ip_range = "192.168.1.0/24"
    try:
        scanner.scan(hosts=ip_range, arguments='-p 1-1024')
        machines_connectees = [host for host in scanner.all_hosts()]
        nombre_machines = len(machines_connectees)
        liste_machines["values"] = machines_connectees
        if machines_connectees:
            liste_machines.current(0)
        afficher_resultats_scan(nombre_machines, machines_connectees)
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur lors du scan réseau : {str(e)}")


# Fonction pour afficher et sauvegarder les résultats du scan
def afficher_resultats_scan(nombre_machines, machines_connectees):
    rapport = {"nombre_machines": nombre_machines, "machines_connectees": machines_connectees}
    report_path = os.path.join(session_dir, "scan_reseau_report.json")
    with open(report_path, "w") as f:
        json.dump(rapport, f, indent=4)
    messagebox.showinfo("Résultats du Scan", f"Rapport enregistré : {report_path}")


# Fonction pour lancer un scan avancé sur la machine sélectionnée
def lancer_scan_avance():
    cible = liste_machines.get()
    if cible:
        try:
            scanner.scan(hosts=cible, arguments='-A')
            details = scanner[cible]
            rapport = json.dumps(details, indent=4, default=str)
            report_path = os.path.join(session_dir, f"scan_avance_{cible}.json")
            with open(report_path, "w") as f:
                f.write(rapport)
            messagebox.showinfo("Scan Avancé", f"Rapport enregistré : {report_path}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du scan avancé : {str(e)}")
    else:
        messagebox.showwarning("Avertissement", "Veuillez sélectionner une machine pour le scan avancé.")


# Fonction pour mesurer la latence WAN (ping)
def mesurer_latence(cible):
    try:
        result = subprocess.run(['ping', '-c', '4', cible], capture_output=True, text=True)
        latence = parse_ping_output(result.stdout)
        report_path = os.path.join(session_dir, "latence_wan_report.json")
        with open(report_path, "w") as f:
            json.dump({"cible": cible, "latence": latence}, f, indent=4)
        messagebox.showinfo("Latence WAN", f"Rapport enregistré : {report_path}")
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


# Fonction pour interroger SNMP
def interroger_snmp(ip):
    try:
        resultats_snmp = {}
        iterator = getCmd(
            SnmpEngine(),
            CommunityData('public', mpModel=0),
            UdpTransportTarget((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication:
            messagebox.showerror("Erreur SNMP", f"Indication d'erreur : {errorIndication}")
            return
        elif errorStatus:
            messagebox.showerror("Erreur SNMP", f"Statut d'erreur : {errorStatus.prettyPrint()}")
            return
        else:
            for varBind in varBinds:
                resultats_snmp[str(varBind[0])] = str(varBind[1])
            report_path = os.path.join(session_dir, "snmp_report.json")
            with open(report_path, "w") as f:
                json.dump(resultats_snmp, f, indent=4)
            messagebox.showinfo("SNMP", f"Rapport enregistré : {report_path}")
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible d'interroger SNMP : {str(e)}")


# Interface Tkinter
root = tk.Tk()
root.title("Seahawks Monitoring")

# Obtenir les infos locales et les afficher
adresse_ip, nom_machine = obtenir_infos_locales()
label_infos = tk.Label(root, text=f"Adresse IP Locale : {adresse_ip}\nNom de la Machine : {nom_machine}\nVersion : {APP_VERSION}")
label_infos.pack(pady=10)

# Boutons
btn_adresses_mac = tk.Button(root, text="Détecter les Adresses MAC", command=detecter_adresses_mac)
btn_adresses_mac.pack(pady=10)
btn_scan = tk.Button(root, text="Lancer le Scan Réseau", command=lancer_scan)
btn_scan.pack(pady=10)
label_selection = tk.Label(root, text="Sélectionnez une machine pour le scan avancé :")
label_selection.pack(pady=5)
liste_machines = ttk.Combobox(root)
liste_machines.pack(pady=5)
btn_scan_avance = tk.Button(root, text="Lancer le Scan Avancé", command=lancer_scan_avance)
btn_scan_avance.pack(pady=10)
btn_latence = tk.Button(root, text="Mesurer la Latence WAN", command=lambda: mesurer_latence("8.8.8.8"))
btn_latence.pack(pady=10)
btn_snmp = tk.Button(root, text="Interroger SNMP", command=lambda: interroger_snmp("192.168.1.1"))
btn_snmp.pack(pady=10)

root.mainloop()
