"""
REST-API-Schnittstelle für den IP-Scanner.
REST (Representational State Transfer) ist ein Architekturstil für Webservices.

Diese API arbeitet "zustandslos" (stateless): Sie nimmt lediglich eingehende HTTP-Anfragen entgegen, 
validiert die Eingaben (z.B. IP-Format) und leitet die eigentliche Verarbeitung an den Koordinator weiter.
Die fertigen Ergebnisse werden dann als standardisierte JSON-Pakete zurückgegeben.

Kurz und knapp: Dieses Modul stellt die Endpunkte der Anwendung nach außen zur Verfügung.
"""

from flask import Flask, request, jsonify # Flask zur Erstellung des API-Servers, request, um auf Daten der Anfrage zuzugreifen, jsonify, um JSON-Antworten zu erstellen
from validator import ip_testung # Eigenes Validierungsmodul, um die IP-Adresse auf formale Gültigkeit zu prüfen
from coordinator import run_complete_scan # Orchestriert den gesamten Scan-Prozess und bündelt die API-Ergebnisse

app = Flask(__name__) # Initialisierung der Flask-Anwendung

#Definiert den URL-Pfad ("/check") und erlaubt nur GET-Anfragen
@app.route("/check", methods=["GET"])
def check_ip():
    """
    Endpunkt für die Überprüfung einer IP-Adresse.

    Nimmt eine IP-Adresse als GET-Parameter entgegen, validiert das Format und leitet die Anfrage an den Koordinator weiter.

    Erwartete GET-Parameter:
        ip (str): Die zu überprüfende IP-Adresse.
    
    Returns:
        JSON-Antwort mit dem Ergebnis der Überprüfung oder einem Fehlerhinweis.
            - HTTP 200: Erfolgreicher Scan
            - HTTP 400: Fehlende oder ungültige IP-Adresse
            - HTTP 500: Fehler im Koordinator oder bei externen APIs
    """
    # Parameter aus der Anfrage extrahieren: Zieht den Wert nach dem "?ip=" aus der URL
    ip_address = request.args.get("ip")

    # Erste Validierungsstufe: Prüfen, ob üerhaupt eine IP übergeben wurde - wenn keine übergeben wurde, wird Fehler 400 zurückgegeben
    if not ip_address:
        return jsonify({
            "success": False,
            "error": "Es wurde keine IP-Adresse übergeben. Beispiel: /check?ip=8.8.8.8"
        }), 400

    # Zweite Validierungsstufe: Nutzt unser eigenes Validator-Modul, um die IP-Adresse auf formale Gültigkeit zu prüfen - wenn die IP ungültig ist, wird Fehler 400 zurückgegeben.
    if not ip_testung(ip_address):
        return jsonify({
            "success": False,
            "error": "Die IP-Adresse ist ungültig."
        }), 400

    # Verarbeitung: Der Koordinator wird aufgerufen, um den Scan durchzuführen und liefert ein fertiges Ergebnis zurück
    result = run_complete_scan(ip_address)

    # Fehlerbehandlung: Wenn eine externe API oder der Koordinator selbst einen Fehler zurückliefert, wird Fehler 500 zurückgegeben
    if not result["success"]:
        return jsonify(result), 500

    # Ergebnis zusammenstellen: Die IP-Adresse wird dem Ergebnis hinzugefügt, um die Rückgabe zu vervollständigen
    result["ip_address"] = ip_address

    # Das fertige Dictionary wird als JSON-Antwort zurückgegeben und an den Client geschickt - Flask sendet automatisch den HTTP-Statuscode 200
    return jsonify(result)

# Dieser Block stellt sicher, dass die Flask-Anwendung nur dann gestartet wird, wenn das Skript direkt ausgeführt wird
if __name__ == "__main__":
    app.run(debug=True, port=5001)

