import tkinter as tk
from tkinter import messagebox
import nmap
import json

# Scanner Nmap
scanner = nmap.PortScanner()


def lancer_scan_basique():
    ip_range = "192.168.1.0/24"  # À personnaliser
    print(f"Lancement du scan basique sur {ip_range}...")
    scanner.scan(hosts=ip_range, arguments='-sn')

    hosts_decouverts = [host for host in scanner.all_hosts() if scanner[host].state() == "up"]
    print("Hôtes découverts :", hosts_decouverts)

    afficher_resultats_scan("Scan Basique", hosts_decouverts)
    return hosts_decouverts


def lancer_scan_avance(hosts_decouverts):
    print("Lancement du scan avancé sur les hôtes découverts...")
    resultats_avances = {}

    for host in hosts_decouverts:
        scanner.scan(hosts=host, arguments='-A')
        resultats_avances[host] = scanner[host]

    afficher_resultats_scan("Scan Avancé", resultats_avances)


def lancer_scan_avance_2(hosts_decouverts):
    print("Lancement du scan avancé 2 (-sC -sV) sur les hôtes découverts...")
    resultats_avances_2 = {}

    for host in hosts_decouverts:
        scanner.scan(hosts=host, arguments='-sC -sV')
        resultats_avances_2[host] = scanner[host]

    afficher_resultats_scan("Scan Avancé 2", resultats_avances_2)


def afficher_resultats_scan(titre, resultats):
    rapport = json.dumps(resultats, indent=4, default=str)
    messagebox.showinfo(titre, rapport)

    # Enregistre le rapport dans un fichier JSON
    with open(f"{titre.replace(' ', '_').lower()}_report.json", "w") as f:
        f.write(rapport)
    print(f"Rapport {titre} enregistré.")


# Interface Tkinter
root = tk.Tk()
root.title("Seahawks Monitoring")

hosts_decouverts = []

btn_scan_basique = tk.Button(root, text="Scan Basique", command=lambda: hosts_decouverts.extend(lancer_scan_basique()))
btn_scan_basique.pack(pady=10)

btn_scan_avance = tk.Button(root, text="Scan Avancé", command=lambda: lancer_scan_avance(hosts_decouverts))
btn_scan_avance.pack(pady=10)

btn_scan_avance_2 = tk.Button(root, text="Scan Avancé 2 (-sC -sV)",
                              command=lambda: lancer_scan_avance_2(hosts_decouverts))
btn_scan_avance_2.pack(pady=10)

root.mainloop()
