#!/bin/bash

echo "Vérification de l'environnement virtuel..."
if [ ! -d "venv" ]; then
    echo "Création de l'environnement virtuel..."
    python3 -m venv venv
fi

echo "Activation de l'environnement virtuel..."
source venv/bin/activate
# installation de pip et de python3.11-venvpip python3-tk nmap
echo "Installation des dépendances depuis requirements.txt..."
pip install -r requirements.txt


echo "Lancement de main.py..."
python3 main.py

echo "Exécution terminée !"
