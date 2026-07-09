"""
Flask REST API für den IP-Checker.

Diese Datei stellt eine REST-Schnittstelle bereit, damit IP-Adressen
nicht nur über die Streamlit-Oberfläche, sondern auch über HTTP-Anfragen
geprüft werden können.
"""

from flask import Flask, request, jsonify

from validator import ip_testung
from coordinator import run_complete_scan
from scoring import calculate_final_score, calculate_risk_level


app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "IP-Checker REST API läuft.",
        "endpoints": {
            "single_check": "/check?ip=8.8.8.8",
            "health": "/health"
        }
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok"
    })


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

    result = run_complete_scan(ip_address)

    if not result["success"]:
        return jsonify(result), 500

    threat = result["threat_data"]
    blacklist = result["blacklist_data"]
    geo = result["geo_data"]

    final_score = calculate_final_score(
        threat_data=threat,
        blacklist_data=blacklist,
        geo_data=geo
    )

    risk = calculate_risk_level(final_score)

    return jsonify({
        "success": True,
        "ip_address": ip_address,
        "cache_hit": result.get("cache_hit", False),
        "final_score": final_score,
        "risk_level": risk["level"],
        "risk_explanation": risk["explanation"],
        "threat_data": result["threat_data"],
        "geo_data": result["geo_data"],
        "blacklist_data": result["blacklist_data"]
    })


if __name__ == "__main__":
    app.run(debug=True, port=5001)