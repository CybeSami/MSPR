import tkinter as tk
from tkinter import messagebox, ttk
import nmap
import socket
import subprocess
import json
import os
import datetime
import requests

# Définir la version de l'application
APP_VERSION = "1.1.0"

# Scanner Nmap
scanner = nmap.PortScanner()
machines_connectees = []
all_reports = []  # Liste pour stocker tous les rapports

# Dossier pour sauvegarder les scans
base_scan_dir = "scanResults"
if not os.path.exists(base_scan_dir):
    os.mkdir(base_scan_dir)

# Créer un dossier pour chaque session
session_dir = os.path.join(
    base_scan_dir, f"scan_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
)
os.mkdir(session_dir)

# Fonction pour envoyer les rapports en batch
def envoyer_rapports():
    if not all_reports:
        messagebox.showwarning("Avertissement", "Aucun rapport à envoyer.")
        return

    url = "http://127.0.0.1:5000/reports"  # Remplacez par l'URL de votre API Flask
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(url, data=json.dumps(all_reports), headers=headers)
        if response.status_code == 200:
            messagebox.showinfo("Succès", "Tous les rapports ont été envoyés avec succès.")
        else:
            messagebox.showerror("Erreur", f"Erreur lors de l'envoi : {response.text}")
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur de connexion : {str(e)}")

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
        all_reports.append({"type": "adresses_mac", "data": result})
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
    rapport = {"type": "scan_reseau", "data": {"nombre_machines": nombre_machines, "machines_connectees": machines_connectees}}
    all_reports.append(rapport)
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
            rapport = {"type": "scan_avance", "cible": cible, "details": details}
            all_reports.append(rapport)
            report_path = os.path.join(session_dir, f"scan_avance_{cible}.json")
            with open(report_path, "w") as f:
                json.dump(details, f, indent=4)
            messagebox.showinfo("Scan Avancé", f"Rapport enregistré : {report_path}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du scan avancé : {str(e)}")
    else:
        messagebox.showwarning("Avertissement", "Veuillez sélectionner une machine pour le scan avancé.")

# Interface Tkinter
root = tk.Tk()
root.title("Seahawks Harverster")

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

# Bouton pour envoyer les rapports
btn_envoyer_rapports = tk.Button(root, text="Envoyer les Rapports", command=envoyer_rapports)
btn_envoyer_rapports.pack(pady=10)

root.mainloop()
