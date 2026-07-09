from flask import Flask, request, jsonify

# HIER FLIEGEN DIE SCORING-IMPORTE RAUS! Wir brauchen nur noch den Validator und Koordinator:
from validator import ip_testung
from coordinator import run_complete_scan

app = Flask(__name__)

# ... (home und health Endpunkte bleiben exakt so, wie sie sind) ...

@app.route("/check", methods=["GET"])
def check_ip():
    ip_address = request.args.get("ip")

    if not ip_address:
        return jsonify({
            "success": False,
            "error": "Es wurde keine IP-Adresse übergeben. Beispiel: /check?ip=8.8.8.8"
        }), 400

    if not ip_testung(ip_address):
        return jsonify({
            "success": False,
            "error": "Die IP-Adresse ist ungültig."
        }), 400

    # 1. Wir rufen das Backend auf
    result = run_complete_scan(ip_address)

    # 2. Fehler abfangen
    if not result["success"]:
        return jsonify(result), 500

    # 3. Den fertigen IP-String noch zum Payload hinzufügen, damit die Antwort perfekt ist
    result["ip_address"] = ip_address

    # 4. Die direkte, unveränderte Ausgabe! Kein Auspacken, kein Rechnen mehr nötig.
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True, port=5001)

