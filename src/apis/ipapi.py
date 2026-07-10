"""
Schnittstellen-Modul für die IP-API.
Bietet geografische (z. B. Land, Stadt, PLZ) und ISP-Daten (z. B. Internetanbieter) zu einer IP-Adresse.

Es wird kein API-Schlüssel benötigt.
"""

import requests  # Nötig, um HTTP-Anfragen an die API zu senden


def get_ipapi_info(ip_address):
    """
    Sendet eine IP-Adresse an die ip-api (ip-api.com), um geografische und ISP-Daten abzurufen.

    Args:
        ip_address (str): Die zu überprüfende IPv4- oder IPv6-Adresse.
    
    Returns:
        dict: Ein Dictionary mit den Standortdaten (z. B. 'country', 'city', 'isp') 
              oder eine Fehlermeldung unter 'error'.
    """
    
    # Alles, was die API erwartet, ist die IP-Adresse als Teil der URL (am Ende) - Es sind keine zusätzlichen Parameter oder Headers nötig.
    url = f'http://ip-api.com/json/{ip_address}'

    # Wenn die Anfrage fehlschlägt (z. B. Netzwerkfehler, ungültige URL), wird eine Ausnahme ausgelöst, die unten (Exception) abgefangen wird
    try:
        # Hier wird die URL an die requests.get()-Funktion übergeben, um die 'response' zu erzeugen
        response = requests.get(url, timeout=10)

        # status_code 200 bedeutet, dass die Anfrage erfolgreich war (Internet-Standard) und die API eine gültige Antwort zurückgegeben hat
        if response.status_code == 200:
            data = response.json()  # .json() wandelt die API-Antwort von einem JSON-String in ein Python-Dictionary um, damit app.py sofort auf die Daten zugreifen kann

            # Fall A: Logischer Fehler - die API hat unsere Anfrage technisch empfangen, meldet uns aber im JSON-Inhalt einen fachlichen Fehler
            if data.get('status') == 'fail':
                return {'error': f"IP-API meldet: {data.get('message', 'Unbekannter Fehler')}"}
            
            # Wenn alles erfolgreich war, wird das Dictionary mit den Standortdaten zurückgegeben
            return data
        
        # Fall B: Technischer Fehler - es gibt ein Problem mit dem Server selbst oder der Verbindung. Wir erhalten kein gültiges JSON-Paket
        else:
            return {'error': f'IP-API-Fehler: Status {response.status_code}'}

    # Wenn im try-Block ein Fehler auftritt, greift dieser except-Block und fängt die Ausnahme ab
    except Exception as e:
        # Das e wird automatisch mit der Fehlermeldung gefüllt (z. B. 'Netzwerkfehler', 'Ungültige URL')
        return {'error': f'Anfragefehler IP-API: {str(e)}'}