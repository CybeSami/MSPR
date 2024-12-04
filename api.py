from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
import ipaddress

app = Flask(__name__)

# Configuration de la base de données
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 'postgresql://seahawks_user:seahawksdb@192.168.1.109/seahawks_db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialisation de SQLAlchemy
db = SQLAlchemy(app)

# Modèle Report
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)

@app.route("/reports", methods=["POST"])
def add_reports():
    try:
        data = request.get_json()

        if not isinstance(data, list):
            return jsonify({"error": "Les données doivent être une liste."}), 400

        for report in data:
            # Validation des données
            if not all(key in report for key in ("ip", "port", "status", "timestamp")):
                return jsonify({"error": "Un ou plusieurs champs manquent."}), 400

            try:
                ipaddress.ip_address(report["ip"])
            except ValueError:
                return jsonify({"error": f"Adresse IP invalide : {report['ip']}"}), 400

            new_report = Report(
                ip=report["ip"],
                port=int(report["port"]),
                status=report["status"],
                timestamp=report["timestamp"]
            )
            db.session.add(new_report)

        db.session.commit()
        return jsonify({"message": f"{len(data)} rapports ajoutés avec succès."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/reports", methods=["GET"])
def get_reports():
    try:
        ip_filter = request.args.get("ip")
        port_filter = request.args.get("port")
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 10))

        query = Report.query
        if ip_filter:
            query = query.filter_by(ip=ip_filter)
        if port_filter:
            query = query.filter_by(port=int(port_filter))

        reports = query.paginate(page=page, per_page=per_page)
        result = [
            {"id": report.id, "ip": report.ip, "port": report.port, "status": report.status, "timestamp": report.timestamp}
            for report in reports.items
        ]
        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/init-db", methods=["GET"])
def init_db():
    try:
        db.create_all()
        return jsonify({"message": "Base de données initialisée avec succès."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "False").lower() == "true", host="0.0.0.0")
