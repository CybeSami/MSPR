from flask import Flask, request, jsonify
from sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://seahawks_user:seahawksdb@192.168.1.109/seahawks_db'
db = SQLAlchemy(app)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100))
    status = db.Column(db.String(100))
    scan_time = db.Column(db.DateTime)

@app.route('/scan', methods=['POST'])
def add_scan_result():
    data = request.get_json()
    new_scan = ScanResult(
        ip_address=data['ip_address'],
        status=data['status'],
        scan_time=data['scan_time']
    )
    db.session.add(new_scan)
    db.session.commit()
    return jsonify({"message": "Scan result added successfully"}), 201

@app.route('/scans', methods=['GET'])
def get_scan_results():
    scans = ScanResult.query.all()
    return jsonify([{
        'id': scan.id,
        'ip_address': scan.ip_address,
        'status': scan.status,
        'scan_time': scan.scan_time
    } for scan in scans])

if __name__ == '__main__':
    app.run(debug=True)
