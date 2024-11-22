#!/bin/bash

echo "Vérification de l'environnement virtuel..."
if [ ! -d "venv" ]; then
    echo "Création de l'environnement virtuel..."
    python3 -m venv venv
fi

echo "Activation de l'environnement virtuel..."
source venv/bin/activate

echo "Installation des dépendances depuis requirements.txt..."
pip install -r requirements.txt
pip install gunicorn

echo "Lancement de main.py..."
python3 main.py
gunicorn -w 4 -b 127.0.0.1:5000 api:app &

echo "Exécution terminée !"
