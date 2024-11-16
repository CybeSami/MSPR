@echo off
echo Vérification de l'environnement virtuel...
if not exist "venv" (
    echo Création de l'environnement virtuel...
    python -m venv venv
)

echo Activation de l'environnement virtuel...
venv\Scripts\activate

echo Installation des dépendances depuis requirements.txt...
pip install -r requirements.txt

echo Lancement de main.py...
python main.py

echo Exécution terminée ! Appuyez sur une touche pour quitter.
pause
