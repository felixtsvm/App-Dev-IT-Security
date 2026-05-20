"""
Zentraler API-Koordinator.

Dieses Modul koordiniert die Abfragen an allen externen APIs (AbuseIPDB, IP-API, etc.).
Es ruft die einzelnen API-Funktionen nacheinander auf, fängt Fehler ab und bündelt die Ergebnisse
zu einem standardisierten Gesamtpaket für das Streamlit-Frontend.
"""

# Importe der jeweiligen API-Methoden aus dem 'apis'-Unterordner mittels Punktnotation
from apis.abuseipdb import get_abuseipdb_info
from apis.ipapi import get_ipapi_info
from apis.ipsum import get_ipsum_info

def run_complete_scan(ip_address):
    
    """
    Diese Funktion steuert den gesamten Ablauf. Sie fragt alle drei APIs nacheinander ab (Schritt 1),
    packt die Ergebnisse zusammen und gibt sie an die App weiter (Schritt 2).

    Args:
        ip_address (str): Die zu überprüfende IPv4- oder IPv6-Adresse.

    Returns:
        dict: Ein Dicitionary mit einem "success"-Statusflag und den jeweiligen Daten- oder Fehlerbereichen.
    """

    try:
        
        # ======================================================================================
        # 1. APIs nacheinander abfragen und auf Fehler prüfen
        # ======================================================================================
        # Sobald eine API einen Fehler liefert, springt Python in das jeweilige 'if' zutrifft.
        # Das dortige 'return' beendet die Funktion sofort und liefert nur die Fehlermeldung.
        # Das Ergebnispaket ganz unten wird also nur dann gebaut und zurückgegeben, wenn alle
        # drei Abfragen fehlerfrei durchgelaufen sind.
        # ---------------------------------------------------------------------------------------

        # 1. AbuseIPDB nach sicherheitsrelevanten Daten fragen
        abuseipdb_data = get_abuseipdb_info(ip_address)
        # Wenn in der Antwort das Wort "error" steckt (z.B. Key falsch),
        # brechen wir sofort ab und schicken die Fehlermeldung zurück.
        if "error" in abuseipdb_data:
            return {"success": False, "error": f"AbuseIPDB-Fehler: {abuseipdb_data['error']}"}
        
        # 2. IP-API nach Standortdaten fragen (nur, wenn AbuseIPDB fehlerfrei war)
        ipapi_data = get_ipapi_info(ip_address)
        # Auch hier: Wenn ein Fehler auftritt, brechen wir sofort ab.
        if "error" in ipapi_data:
            return {"success": False, "error": f"IP-API-Fehler: {ipapi_data['error']}"}
        
        # 3. IPsum (GitHub-Liste) nach Blacklist-Einträgen fragen (nur, wenn AbuseIPDB und IP-API fehlerfrei waren)
        ipsum_data = get_ipsum_info(ip_address)
        # Wenn GitHub nicht erreichbar ist, brechen wir ebenfalls ab.
        if "error" in ipsum_data:
            return {"success": False, "error": f"IPsum-Fehler: {ipsum_data['error']}"}
        
        # ==========================================
        # 2. Ergebnipaket für die App zusammenbauen
        # ==========================================

        return {
                "success": True, # Signal für die App, dass alles geklappt hat

                # Sicherheitsrelevanten Daten von AbuseIPDB
                "threat_data": {
                    "score": abuseipdb_data.get("abuseConfidenceScore", 0),
                    "whitelisted": abuseipdb_data.get("isWhitelisted", False)
                },
                
                # Ort- und Netzwerkinfos von IP-API
                "geo_data": {
                    "country_code": ipapi_data.get("countryCode", "Unbekannt"), # 🗺️ JETZT HIER (von IP-API geholt)
                    "city": ipapi_data.get("city", "Unbekannt"),
                    "region": ipapi_data.get("regionName", "Unbekannt"),
                    "isp": ipapi_data.get("isp", "Unbekannt"),
                    "timezone": ipapi_data.get("timezone", "Unbekannt")
                },
                
                # Ergebnis des GitHub-Abgleichs (IPsum))
                "blacklist_data": {
                    "listed": ipsum_data.get("listed", False),
                    "status": ipsum_data.get("status_text", "Keine Daten")
                }
            }
    
    # Wenn im try-Block ein Fehler auftritt, greift dieser except-Block und fängt die Ausnahme ab
    except Exception as e:
        return {"success": False, "error": f"Kritischer Fehler im Koordinator: {str(e)}"}