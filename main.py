import tkinter as tk
from tkinter import messagebox, ttk  # Importer ttk pour la liste déroulante
import nmap
import socket
import subprocess
import json

# Définir la version de l'application
APP_VERSION = "1.0.0"

# Scanner Nmap
scanner = nmap.PortScanner()
machines_connectees = []  # Liste pour stocker les machines découvertes


# Fonction pour obtenir l'adresse IP locale et le nom de la machine
def obtenir_infos_locales():
    nom_machine = socket.gethostname()
    adresse_ip = socket.gethostbyname(nom_machine)
    return adresse_ip, nom_machine


# Fonction pour lancer un scan réseau
def lancer_scan():
    global machines_connectees
    ip_range = "192.168.1.0/24"  # Plage d'adresses IP à scanner
    scanner.scan(hosts=ip_range, arguments='-p 1-1024')

    machines_connectees = [host for host in scanner.all_hosts()]
    nombre_machines = len(machines_connectees)

    # Mettre à jour la liste déroulante avec les machines découvertes
    liste_machines["values"] = machines_connectees
    liste_machines.current(0)  # Sélectionne la première machine par défaut

    afficher_resultats_scan(nombre_machines)


# Fonction pour afficher les résultats du scan
def afficher_resultats_scan(nombre_machines):
    messagebox.showinfo("Résultats du Scan", f"Nombre de machines connectées : {nombre_machines}")
    print(f"{nombre_machines} machines connectées trouvées.")


# Fonction pour lancer un scan avancé sur la machine sélectionnée
def lancer_scan_avance():
    cible = liste_machines.get()  # Récupère l'adresse IP sélectionnée
    if cible:
        print(f"Lancement du scan avancé sur {cible}...")
        scanner.scan(hosts=cible, arguments='-A')
        details = scanner[cible]
        rapport = json.dumps(details, indent=4, default=str)

        # Afficher les résultats du scan avancé
        messagebox.showinfo("Scan Avancé", f"Résultats du scan avancé pour {cible} :\n{rapport}")
        with open(f"scan_avance_{cible}.json", "w") as f:
            f.write(rapport)
        print(f"Rapport de scan avancé sauvegardé dans scan_avance_{cible}.json")
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


# Interface Tkinter
root = tk.Tk()
root.title("Seahawks Monitoring")

# Obtenir les infos locales et les afficher
adresse_ip, nom_machine = obtenir_infos_locales()
label_infos = tk.Label(root,
                       text=f"Adresse IP Locale : {adresse_ip}\nNom de la Machine : {nom_machine}\nVersion : {APP_VERSION}")
label_infos.pack(pady=10)

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

root.mainloop()
