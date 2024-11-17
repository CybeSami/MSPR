import tkinter as tk
from tkinter import messagebox
import nmap
import socket
import subprocess
import json

# Définir la version de l'application
APP_VERSION = "1.0.0"

# Scanner Nmap
scanner = nmap.PortScanner()


# Fonction pour obtenir l'adresse IP locale et le nom de la machine
def obtenir_infos_locales():
    nom_machine = socket.gethostname()
    adresse_ip = socket.gethostbyname(nom_machine)
    return adresse_ip, nom_machine


# Fonction pour lancer un scan réseau
def lancer_scan():
    ip_range = "192.168.1.0/24"  # Plage d'adresses IP à scanner
    scanner.scan(hosts=ip_range, arguments='-p 1-1024')

    machines_connectees = []
    for host in scanner.all_hosts():
        ports_ouverts = [port for port in scanner[host].all_tcp() if scanner[host]['tcp'][port]['state'] == 'open']
        machines_connectees.append({
            "ip": host,
            "ports_ouverts": ports_ouverts
        })

    nombre_machines = len(machines_connectees)
    afficher_resultats_scan(machines_connectees, nombre_machines)


# Fonction pour afficher les résultats du scan
def afficher_resultats_scan(machines_connectees, nombre_machines):
    rapport = {
        "nombre_machines": nombre_machines,
        "machines_connectees": machines_connectees
    }
    # Sauvegarde du rapport dans un fichier JSON
    with open("scan_report.json", "w") as f:
        json.dump(rapport, f, indent=4)

    messagebox.showinfo("Résultats du Scan", f"Nombre de machines connectées : {nombre_machines}")
    print(f"Rapport de scan sauvegardé dans scan_report.json")


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


# Interface Tkinter
root = tk.Tk()
root.title("Seahawks Monitoring")

# Obtenir les infos locales et les afficher
adresse_ip, nom_machine = obtenir_infos_locales()
label_infos = tk.Label(root,
                       text=f"Adresse IP Locale : {adresse_ip}\nNom de la Machine : {nom_machine}\nVersion : {APP_VERSION}")
label_infos.pack(pady=10)

# Boutons pour lancer les scans et mesurer la latence
btn_scan = tk.Button(root, text="Lancer le Scan Réseau", command=lancer_scan)
btn_scan.pack(pady=10)

btn_latence = tk.Button(root, text="Mesurer la Latence WAN", command=lambda: mesurer_latence("8.8.8.8"))
btn_latence.pack(pady=10)

root.mainloop()
