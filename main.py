import tkinter as tk
from tkinter import messagebox, ttk
import nmap
import socket
import subprocess
import json
import os
import datetime
import requests
from urllib.parse import urlparse
import logging

# Charger la configuration depuis config.json
try:
    with open("config.json", "r") as config_file:
        config = json.load(config_file)

    required_keys = ["api_url", "scan_directory", "ip_range", "app_version"]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Clé manquante dans config.json : {key}")

    API_URL = config["api_url"]
    SCAN_DIR = config["scan_directory"]
    IP_RANGE = config["ip_range"]
    APP_VERSION = config["app_version"]

except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
    messagebox.showerror("Erreur", f"Erreur dans config.json : {str(e)}")
    exit()

# Vérifier la validité de l'URL de l'API
if not urlparse(API_URL).scheme:
    raise ValueError("L'URL de l'API est invalide.")

# Initialiser le scanner Nmap
scanner = nmap.PortScanner()
machines_connectees = []

# Créer un répertoire pour les scans si nécessaire
os.makedirs(SCAN_DIR, exist_ok=True)

# Créer un répertoire pour chaque session
session_dir = os.path.join(
    SCAN_DIR, f"scan_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
)
os.mkdir(session_dir)

# Initialiser les logs
logging.basicConfig(
    filename=os.path.join(session_dir, "app.log"), level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logging.info("Application démarrée")

# Chemin du fichier de rapport global
rapport_global_path = os.path.join(session_dir, "rapport_global.json")

# Initialiser le rapport global
rapport_global = {
    "session": session_dir,
    "date": str(datetime.datetime.now()),
    "app_version": APP_VERSION,
    "rapports": {}
}


# Sauvegarder le rapport global dans un fichier
def sauvegarder_rapport_global():
    with open(rapport_global_path, "w") as f:
        json.dump(rapport_global, f, indent=4)


# Fonction pour envoyer le rapport global à l'API
def envoyer_rapport_global():
    if not os.path.exists(rapport_global_path):
        messagebox.showerror("Erreur", "Aucun rapport global trouvé à envoyer.")
        return

    try:
        with open(rapport_global_path, "r") as f:
            rapport = json.load(f)

        headers = {"Content-Type": "application/json"}
        response = requests.post(API_URL, json=rapport, headers=headers)

        if response.status_code == 200:
            messagebox.showinfo("Succès", "Le rapport global a été envoyé avec succès.")
            logging.info("Rapport global envoyé avec succès.")
        else:
            messagebox.showerror("Erreur", f"Échec de l'envoi : {response.status_code}\n{response.text}")
            logging.error(f"Erreur d'envoi : {response.status_code}, {response.text}")
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur lors de l'envoi : {str(e)}")
        logging.error(f"Erreur lors de l'envoi du rapport : {str(e)}")


# Fonction pour obtenir l'adresse IP locale et le nom de la machine
def obtenir_infos_locales():
    try:
        nom_machine = socket.gethostname()
        adresse_ip = socket.gethostbyname(nom_machine)
        adresses_mac = detecter_adresses_mac()
        rapport_global["rapports"]["infos_locales"] = {
            "nom_machine": nom_machine,
            "adresse_ip": adresse_ip,
            "adresses_mac": adresses_mac,
        }
        sauvegarder_rapport_global()
        return adresse_ip, nom_machine, adresses_mac
    except Exception as e:
        logging.error(f"Erreur lors de l'obtention des infos locales : {str(e)}")
        return "Inconnu", "Inconnu", []


# Fonction pour détecter les adresses MAC
def detecter_adresses_mac():
    try:
        if os.name == "posix":  # Linux/MacOS
            result = os.popen("arp -a").read()
        elif os.name == "nt":  # Windows
            result = os.popen("arp -a").read()
        else:
            return ["OS non supporté."]

        # Filtrer et afficher seulement les adresses MAC
        adresses_mac = [line.split()[1] for line in result.splitlines() if len(line.split()) > 1 and ":" in line]
        return adresses_mac if adresses_mac else ["Aucune adresse MAC détectée"]
    except Exception as e:
        logging.error(f"Erreur lors de la détection des adresses MAC : {str(e)}")
        return [f"Erreur : {str(e)}"]


# Fonction pour lancer un scan réseau
def lancer_scan():
    try:
        scanner.scan(hosts=IP_RANGE, arguments='-p 1-1024')
        global machines_connectees
        machines_connectees = [host for host in scanner.all_hosts()]
        rapport_global["rapports"]["scan_reseau"] = {
            "nombre_machines": len(machines_connectees),
            "machines_connectees": machines_connectees,
        }
        sauvegarder_rapport_global()
        liste_machines['values'] = machines_connectees  # Mise à jour de la liste
        messagebox.showinfo("Scan Réseau", f"{len(machines_connectees)} machines détectées.")
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur lors du scan réseau : {str(e)}")
        logging.error(f"Erreur lors du scan réseau : {str(e)}")


# Fonction pour mesurer la latence WAN (ping)
def mesurer_latence():
    cible = "8.8.8.8"
    try:
        if os.name == "posix":
            result = subprocess.run(['ping', '-c', '4', cible], capture_output=True, text=True)
        elif os.name == "nt":
            result = subprocess.run(['ping', '-n', '4', cible], capture_output=True, text=True)
        latence = parse_ping_output(result.stdout)
        rapport_global["rapports"]["latence"] = {
            "cible": cible,
            "latence_moyenne": latence,
        }
        sauvegarder_rapport_global()
        messagebox.showinfo("Latence WAN", f"Latence moyenne : {latence} ms.")
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur lors de la mesure de latence : {str(e)}")
        logging.error(f"Erreur lors de la mesure de latence : {str(e)}")


# Fonction pour analyser la sortie de la commande ping
def parse_ping_output(output):
    lignes = output.split('\n')
    for ligne in lignes:
        if "avg" in ligne or "moyenne" in ligne:
            latence = ligne.split('/')[4]
            return latence
    return "Indisponible"


# Interface Tkinter
root = tk.Tk()
root.title("Seahawks Harvester")

# Obtenir les infos locales et les afficher
adresse_ip, nom_machine, adresses_mac = obtenir_infos_locales()
label_infos = tk.Label(
    root,
    text=f"Adresse IP Locale : {adresse_ip}\nNom de la Machine : {nom_machine}\nAdresse MAC : {', '.join(adresses_mac)}",
)
label_infos.pack(pady=10)

# Boutons pour les fonctionnalités
btn_scan = tk.Button(root, text="Lancer le Scan Réseau", command=lancer_scan)
btn_scan.pack(pady=10)

label_selection = tk.Label(root, text="Sélectionnez une machine pour le scan avancé :")
label_selection.pack(pady=5)

liste_machines = ttk.Combobox(root)
liste_machines.pack(pady=5)

btn_latence_wan = tk.Button(root, text="Mesurer la Latence WAN", command=mesurer_latence)
btn_latence_wan.pack(pady=10)

btn_envoyer_rapport = tk.Button(root, text="Envoyer le Rapport Global", command=envoyer_rapport_global)
btn_envoyer_rapport.pack(pady=10)

root.mainloop()
