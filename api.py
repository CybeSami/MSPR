from flask import Flask, request, jsonify
from flask import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://seahawks_user:seahawksdb@192.168.1.109/seahawks_db'
db = SQLAlchemy(app)
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15))
    port = db.Column(db.Integer)
    status = db.Column(db.String(10))
    timestamp = db.Column(db.String(50))

@app.route("/reports", methods=["POST"])
def add_reports():
    data = request.get_json()
    if isinstance(data, list):  # Vérifie si plusieurs rapports sont envoyés
        for report in data:
            new_report = Report(
                ip=report["ip"],
                port=report["port"],
                status=report["status"],
                timestamp=report["timestamp"]
            )
            db.session.add(new_report)
        db.session.commit()
        return jsonify({"message": "Rapports ajoutés avec succès"}), 200
    else:
        return jsonify({"error": "Données invalides"}), 400

if __name__ == "__main__":
    app.run(debug=True)