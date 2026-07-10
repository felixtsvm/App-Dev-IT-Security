import requests # Importiert die requests-Bibliothek, um HTTP-Anfragen an die lokale REST-API zu senden

def run_batch_scan(ip_addresses):
    """
    Sendet eine Liste von IP-Adressen an die lokale REST-API zur Sicherheitsanalyse.
    Dient dazu, nicht IPs einzeln über den Browser oder das Terminal zu prüfen, sondern mehrere IPs in einem Rutsch zu analysieren.

    Args:
        ip_addresses (list): Eine Liste von Strings, die die zu prüfenden IP-Adressen enthält.
        
    Returns:
        None: Die Ergebnisse werden direkt in der Konsole ausgegeben.
    """

    print(f"Sende {len(ip_addresses)} Abfragen an die REST-API...\n")

    for ip in ip_addresses:
        # Die URL für die lokale Flask-API wird dynamisch erstellt, wobei die IP-Adresse als GET-Parameter übergeben wird
        url = f"http://127.0.0.1:5001/check?ip={ip}"
        
        try:
            # Senden der GET-Anfrage an die lokale API und Umwandeln der Antwort in JSON
            response = requests.get(url)
            data = response.json()
            
            # Wenn nicht erfolgreich, direkt Fehler ausgeben und Schleife fortsetzen
            if not data.get("success"):
                print(f"IP: {ip} | Fehler: {data.get('error', 'Unbekannt')}")
                continue
                
            # Erfolgsfall
            score = data.get('final_score')
            empfehlung = data.get('handlungsempfehlung', 'Keine Info')
            
            # ip:<15 füllt die IP mit Leerzeichen auf 15 Zeichen auf (maximale Länge IPv4)
            # score:>3 richtet den Score rechtsbündig auf 3 Zeichen aus (für Scores von 0 bis 100)
            print(f"IP: {ip:<15} | Score: {score:>3} | Empfehlung: {empfehlung}")
                
        except requests.exceptions.ConnectionError:

            # Spezifischer Fehler, falls der API-Server nicht gestartet wurde
            print(f"IP: {ip} | Fehler: API-Server nicht erreichbar.")
            
        except Exception as e:
            # Abfangen sonstiger Laufzeitfehler (z.B. Timeout oder Verbindungsabbruch)
            print(f"IP: {ip} | Unerwarteter Fehler: {e}")

if __name__ == "__main__":

    # Test-Liste der IPs
    ips_zum_pruefen = ["8.8.8.8", "1.1.1.1", "185.220.101.1"]
    
    # Aufruf der Funktion
    run_batch_scan(ips_zum_pruefen)