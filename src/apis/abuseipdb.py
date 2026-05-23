"""
Schnittstellen-Modul für die AbuseIPDB-API.
Insbesondere nützlich wegen des 'Abuse Confidence Score', der die Vertrauenswürdigkeit einer IP-Adresse bewertet.

Es wird ein API-Schlüssel benötigt, der in der .env-Datei als "AbuseIPDB_KEY" gespeichert ist.
"""

import requests # Nötig, um HTTP-Anfragen an die API zu senden
import os # Nötig, um die Umgebungsvariablen zu laden
import streamlit as st # Nötig für die Cloud-Secrets
from dotenv import load_dotenv # Funktion zum Laden der Umgebungsvariablen aus der .env-Datei

load_dotenv() # Lädt die .env-Datei
api_key = st.secrets.get("AbuseIPDB_KEY", os.getenv("AbuseIPDB_KEY")) # Sucht erst in den Cloud-Secrets nach dem API-Key. Fall leer oder nicht da, greift der lokale Key aus der .env
def get_abuseipdb_info(ip_address):

    """
    Sendet eine IP-Adresse an die AbuseIPDB-API (abuseipdb.com), um Informationen über die Vertrauenswürdigkeit der IP-Adresse zu erhalten.

    Args:
        ip_address (str): Die zu überprüfende IPv4- odder IPv6-Adresse.

    Returns:
        dict: Ein Dictionary, das entweder die erfolgreichen Analysedaten der API erhält (z.B. 'abuseConfidenceScore')
        oder eine Fehlermeldung unter dem Schlüssel 'error'.
    """
   
    # Zuerst werden die drei zwingend erforderlichen Komponenten (URL, Parameter und Headers) für die API-Anfrage vorbereitet
    # Diese dienen als Argumente für den späteren Aufruf der requests.get()-Funktion, die die eigentliche HTTP-Anfrage an die API sendet
   
    # URL der AbuseIPDB-API
    url = "https://api.abuseipdb.com/api/v2/check" 

     # Die Parameter-Namen sind von der AbuseIPDB-API exakt so vorgeschrieben ('ipAddress' und 'maxAgeInDays')
    parameters = {
        'ipAddress': ip_address, # Die zu prüfende IP-Adresse
        'maxAgeInDays': 90 # Rückschau-Zeitraum für die Überprüfung (max. 90 Tage) - Lang genug, um Angriffe zu erkennen, aber kurz genug, um Fehlalarme durch IP-Wechsel der Provider zu verhindern
    }

     # Headers sind die Metadaten der HTTP-Anfrage, die der API wichtige Informationen über die Anfrage geben
    headers = {
        'Accept': 'application/json', # HTTP-Header, um anzugeben, dass wir JSON als Antwort erwarten
        'Key': api_key # Wird von AbuseIPDB zur Authentifizierung benötigt, damit die API weiß, wer die Anfrage stellt
    }

    # Wenn die Anfrage fehlschlägt (z.B. Netzwerkfehler, ungültige URL), wird eine Ausnahme ausgelöst, die unten (Exception) abgefangen wird
    try: 
       
       # Hier werden URL, Headers und Parameter an die requests.get()-Funktion übergeben, um die 'response' zu erzeugen
        response = requests.get(url, headers = headers, params = parameters)

        if response.status_code == 200: # status_code 200 bedeutet, dass die Anfrage erfolgreich war (Internet-Standard) und die API eine gültige Antwort zurückgegeben hat
            return response.json()['data'] # .json()['data'] öffmet die äußere 'data'-Hülle der API-Antwort, damit app.py sofort auf den Score, das Land etc. zugreifen kann
       
        # Wenn die API einen Fehler zurückgibt (z.B. ungültige Anfrage, Serverfehler), wird eine Fehlermeldung mit dem Error-Code zurückgegeben
        else:
            return {"error": f"API-Fehler: Status {response.status_code}"} 

    # Wenn im try-Block ein Fehler auftritt, greift dieser except-Block und fängt die Ausnahme ab
    except Exception as e:
        return {"error": f"Anfragefehler AbuseIPDB: {str(e)}"} # Das e wird automatisch mit der Fehlermeldung gefüll (z.B. "Netzwerkfehler", "Ungültige URL")