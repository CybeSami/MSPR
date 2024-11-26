from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os

# Initialisation de l'application Flask
app = Flask(__name__)

# Configuration de la base de données
# Remplacez les credentials sensibles par des variables d'environnement dans un vrai projet
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 'postgresql://seahawks_user:seahawksdb@192.168.1.109/seahawks_db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialisation de SQLAlchemy
db = SQLAlchemy(app)

# Modèle de la table "Report"
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)

# Route pour ajouter des rapports
@app.route("/reports", methods=["POST"])
def add_reports():
    try:
        data = request.get_json()

        # Vérifier que les données sont une liste
        if not isinstance(data, list):
            return jsonify({"error": "Les données doivent être une liste de rapports."}), 400

        for report in data:
            # Validation des champs requis
            if not all(key in report for key in ("ip", "port", "status", "timestamp")):
                return jsonify({"error": "Un ou plusieurs champs manquent dans les rapports."}), 400

            # Création et ajout du rapport
            new_report = Report(
                ip=report["ip"],
                port=int(report["port"]),
                status=report["status"],
                timestamp=report["timestamp"]
            )
            db.session.add(new_report)

        # Validation et écriture dans la base
        db.session.commit()
        return jsonify({"message": "Rapports ajoutés avec succès"}), 200

    except Exception as e:
        # Gestion des erreurs générales
        return jsonify({"error": str(e)}), 500

# Route pour initialiser la base de données (uniquement pour la première fois)
@app.route("/init-db", methods=["GET"])
def init_db():
    try:
        db.create_all()
        return jsonify({"message": "Base de données initialisée avec succès."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route pour récupérer tous les rapports
@app.route("/reports", methods=["GET"])
def get_reports():
    try:
        reports = Report.query.all()
        result = [
            {"id": report.id, "ip": report.ip, "port": report.port, "status": report.status, "timestamp": report.timestamp}
            for report in reports
        ]
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
