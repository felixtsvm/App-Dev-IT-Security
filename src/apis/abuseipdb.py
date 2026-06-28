"""
Schnittstellen-Modul für die AbuseIPDB-API.
Insbesondere nützlich wegen des 'Abuse Confidence Score', der die Wahrscheinlichkeit angibt, dass eine IP-Adresse missbräuchlich ist.

Dieses Modul fragt die AbuseIPDB-API ab und liefert sicherheitsrelevante
Informationen zu einer IP-Adresse zurück. Dazu gehören unter anderem der
Abuse Confidence Score, Whitelist-Status, Domain, Hostname, Usage Type,
Anzahl der Reports und Tor-Status.
"""

import os # Nötig, um die Umgebungsvariablen zu laden
import requests # Nötig, um HTTP-Anfragen an die API zu senden
import streamlit as st # Nötig für die Cloud-Secrets
from dotenv import load_dotenv # Funktion zum Laden der Umgebungsvariablen aus der .env-Datei

load_dotenv() # Lädt die .env-Datei


def get_api_key():
    """
    Holt den AbuseIPDB-API-Key.

    Zuerst wird versucht, den Key aus Streamlit Secrets zu laden, falls die App auf Streamlit Cloud geöffnet wird.
    Falls die App lokal läuft, wird der Key aus den Umgebungsvariablen geladen.

    Returns:
        str | None: API-Key oder None.
    """

    try:
        return st.secrets["AbuseIPDB_KEY"] # Versucht, den Key aus Streamlit Secrets zu laden
    
    except Exception:
        return os.getenv("AbuseIPDB_KEY") # Versucht, den Key aus den Umgebungsvariablen zu laden


def get_abuseipdb_info(ip_address):
    """
    Sendet eine IP-Adresse an die AbuseIPDB-API (abuseipdb.com), um Reputationsdaten 
    über die Vertrauenswürdigkeit der IP-Adresse zu erhalten.

    Args:
        ip_address (str): Die zu überprüfende IPv4- oder IPv6-Adresse.

    Returns:
        dict: Ein Dictionary, das entweder die erfolgreichen Analysedaten der API enthält 
              (z. B. 'abuseConfidenceScore') oder eine Fehlermeldung unter dem Schlüssel 'error'.
    """

    
    api_key = get_api_key() # Holt den API-Key aus den Secrets oder Umgebungsvariablen

    # Wenn kein API-Key gefunden wird, wird eine Fehlermeldung zurückgegeben
    if not api_key:
        return {"error": "Kein AbuseIPDB API-Key gefunden."}
    
    """
    Zuerst werden die drei zwingend erforderlichen Komponenten (URL, Parameter und Headers) für die API-Anfrage vorbereitet
    Diese dienen als Argumente für den späteren Aufruf der requests.get()-Funktion, die die eigentliche HTTP-Anfrage an die API sendet
    """

    # URL der AbuseIPDB-API
    url = "https://api.abuseipdb.com/api/v2/check"

    # Die Parameter-Namen sind von der AbuseIPDB-API exakt so vorgeschrieben ('ipAddress' und 'maxAgeInDays')
    parameters = {
        "ipAddress": ip_address, # Die zu überprüfende IP-Adresse
        "maxAgeInDays": 90 # Rückschau-Zeitraum für die Überprüfung (max. 90 Tage) - Lang genug, um Angriffe zu erkennen, aber kurz genug, um Fehlalarme durch IP-Wechsel der Provider zu verhindern
    }

    # Headers sind die Metadaten der HTTP-Anfrage, die der API wichtige Informationen über die Anfrage geben
    headers = {
        "Accept": "application/json", # HTTP-Header, um anzugeben, dass wir JSON als Antwort erwarten
        "Key": api_key # Wird von AbuseIPDB zur Authentifizierung benötigt, damit die API weiß, wer die Anfrage stellt
    }

    
    # Wenn die Anfrage fehlschlägt (z. B. Netzwerkfehler, ungültige URL), wird eine Ausnahme ausgelöst, die unten abgefangen wird
    try:
        # Hier werden URL, Headers und Parameter an die requests.get()-Funktion übergeben, um die 'response' zu erzeugen
        response = requests.get(
            url,
            headers=headers,
            params=parameters,
            timeout=10
        )

        # status_code 200 bedeutet, dass die Anfrage erfolgreich war (Internet-Standard) und die API eine gültige Antwort zurückgegeben hat
        if response.status_code == 200:
            # Die Antwort wird als JSON geparst und das 'data'-Feld wird extrahiert, das die relevanten Informationen enthält
            return response.json().get("data", {})

         # Wenn die API einen Fehler zurückgibt (z. B. ungültige Anfrage, Serverfehler), wird eine Fehlermeldung mit dem Error-Code zurückgegeben
        return {
            "error": f"API-Fehler: Status {response.status_code}"
        }

    # Wenn im try-Block ein Fehler auftritt, greift dieser except-Block und fängt die Ausnahme ab
    except Exception as e:
         # Das e wird automatisch mit der Fehlermeldung gefüllt (z. B. 'Netzwerkfehler', 'Ungültige URL')
        return {
            "error": f"Anfragefehler AbuseIPDB: {str(e)}"
        }