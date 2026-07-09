"""
Zentraler API-Koordinator.

Dieses Modul koordiniert die Abfragen an allen externen APIs.
Es ruft die einzelnen API-Funktionen nacheinander auf, bündelt die Ergebnisse,
nutzt den Cache, falls verfügbar, und erstellt ein standardisiertes Datenpaket für die Anwendung.
"""

# Importe der jeweiligen API-Methoden aus dem 'apis'-Unterordner mittels Punktnotation
from apis.abuseipdb import get_abuseipdb_info
from apis.ipapi import get_ipapi_info
from apis.ipsum import get_ipsum_info

# Importe der Cache-Funktionen aus dem 'cache'-Modul
from cache import get_cached_result, set_cached_result

# Scoring-Module importieren
from scoring import calculate_final_score, calculate_risk_level


def run_complete_scan(ip_address):
    """
    Diese Funktion steuert den gesamten Ablauf. Sie fragt alle drei APIs nacheinander ab (Schritt 1),
    packt die Ergebnisse zusammen und gibt sie an die App weiter (Schritt 2).

    Args:
        ip_address (str): IPv4- oder IPv6-Adresse.

    Returns:
        dict: Ergebnis mit success-Status, Datenpaketen oder Fehlermeldung.
    """

    try:

        # ==========================
        # 1. Cache prüfen
        # ==========================

        cached_result = get_cached_result(ip_address) # Prüft, ob die IP-Adresse bereits im Cache liegt und ein gültiges Ergebnis vorliegt. Wenn ja, wird das gespeicherte Ergebnis zurückgegeben

        # Wenn ein gültiges Cache-Ergebnis vorliegt, wird es zurückgegeben und die API-Abfragen werden übersprungen. Zusätzlich wird das Feld "cache_hit" auf True gesetzt, um anzuzeigen, dass die Daten aus dem Cache stammen
        if cached_result is not None:
            cached_result["cache_hit"] = True
            return cached_result

        # ==========================
        # 2. Externe APIs abfragen
        # ==========================
        # Liegt kein gültiges Cache-Ergebnis vor, werden die drei APIs nacheinander abgefragt.
        # Sobald eine API einen Fehler liefert, springt Python in das jeweilige 'if'.
        # Das dortige 'return' beendet die Funktion sofort und liefert nur die Fehlermeldung.
        # Das Ergebnispaket ganz unten wird also nur dann gebaut und zurückgegeben, wenn alle
        # drei Abfragen fehlerfrei durchgelaufen sind.
        # --------------------------------------------------------------------------------------

        # ==========================
        # 2.1 AbuseIPDB
        # ==========================

        abuseipdb_data = get_abuseipdb_info(ip_address)

        # Wenn in der Antwort der AbuseIPDB-API ein Fehler enthalten ist, wird sofort ein Fehlerpaket zurückgegeben und die Funktion beendet. Die anderen APIs werden nicht mehr abgefragt
        if "error" in abuseipdb_data:
            return {
                "success": False,
                "error": f"AbuseIPDB-Fehler: {abuseipdb_data['error']}"
            }

        # ==========================
        # 2.2 IP-API
        # ==========================

        ipapi_data = get_ipapi_info(ip_address)

        # Wenn in der Antwort der IP-API ein Fehler enthalten ist, wird sofort ein Fehlerpaket zurückgegeben und die Funktion beendet. Die dritte API wird nicht mehr abgefragt
        if "error" in ipapi_data:
            return {
                "success": False,
                "error": f"IP-API-Fehler: {ipapi_data['error']}"
            }

        # ==========================
        # 2.3 IPsum
        # ==========================

        ipsum_data = get_ipsum_info(ip_address)

        # Wenn in der Antwort der IPsum-API ein Fehler enthalten ist, wird sofort ein Fehlerpaket zurückgegeben und die Funktion beendet
        if "error" in ipsum_data:
            return {
                "success": False,
                "error": f"IPsum-Fehler: {ipsum_data['error']}"
            }

        # ==========================
        # Ergebnispaket
        # ==========================

        result = {

            "success": True,
            "cache_hit": False,

            # ====================================
            # 3. Reputations- und Bedrohungsdaten
            # ====================================
            # Hier werden die gewünschten Daten aus den drei APIs zusammengefasst und in einem einheitlichen Format zurückgegeben.
            # ----------------------------------------------------------------------------------------------------------------------

            # ==========================
            # 3.1 AbuseIPDB
            # ==========================

            "threat_data": {

                "score": abuseipdb_data.get(
                    "abuseConfidenceScore",
                    "Unbekannt"
                ),

                "whitelisted": abuseipdb_data.get(
                    "isWhitelisted", 
                    False
                ),
                
                "domain": abuseipdb_data.get(
                    "domain", 
                    "Unbekannt"
                ),

                "hostname": ", ".join(
                    abuseipdb_data.get("hostnames", [])
                    ) if abuseipdb_data.get("hostnames") else "Unbekannt",

                "usage_type": abuseipdb_data.get(
                    "usageType",
                    "Unbekannt"
                ),

                "reports": abuseipdb_data.get(
                    "totalReports",
                    "Unbekannt"
                ),

                "tor": abuseipdb_data.get(
                    "isTor",
                    False
                )

            },


            # ==========================
            # 3.2 IP-API
            # ==========================

            "geo_data": {

                "country_code": ipapi_data.get(
                    "countryCode",
                    "Unbekannt"
                ),

                "city": ipapi_data.get(
                    "city",
                    "Unbekannt"
                ),

                "region": ipapi_data.get(
                    "regionName",
                    "Unbekannt"
                ),

                "isp": ipapi_data.get(
                    "isp",
                    "Unbekannt"
                ),

                "timezone": ipapi_data.get(
                    "timezone",
                    "Unbekannt"
                )

            },

            # ==========================
            # 3.3 IP-sum
            # ==========================

            "blacklist_data": {

                "listed": ipsum_data.get(
                    "listed",
                    False
                ),

                "status": ipsum_data.get(
                    "status_text",
                    "Keine Daten"
                )

            }

        }

        # Score direkt im Backend berechnen
        final_score = calculate_final_score(
            threat_data=result["threat_data"], 
            blacklist_data=result["blacklist_data"], 
            geo_data=result["geo_data"]
        )
        risk = calculate_risk_level(final_score)

        # Ergebnisse direkt als neue Felder ins fertige Paket packen
        result["final_score"] = final_score
        result["risk_level"] = risk["level"]
        result["risk_explanation"] = risk["explanation"]

        set_cached_result(ip_address, result) # Speichert das fertige Ergebnis-Paket im Cache, damit bei einer erneuten Abfrage der gleichen IP-Adresse innerhalb von 10 Minuten die Daten direkt aus dem RAM abgerufen werden können

        return result # Gibt das fertige Ergebnis-Paket zurück, nachdem alle drei APIs erfolgreich abgefragt wurden und die Daten im Cache gespeichert wurden

     # Wenn im try-Block ein Fehler auftritt, greift dieser except-Block und fängt die Ausnahme ab
    except Exception as e:

        return {
            "success": False,
            "error": f"Kritischer Fehler im Koordinator: {str(e)}"
        }