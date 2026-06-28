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
        # Cache prüfen
        # ==========================

        cached_result = get_cached_result(ip_address)

        if cached_result is not None:
            cached_result["cache_hit"] = True
            return cached_result

        # ==========================
        # AbuseIPDB
        # ==========================

        abuseipdb_data = get_abuseipdb_info(ip_address)

        if "error" in abuseipdb_data:
            return {
                "success": False,
                "error": f"AbuseIPDB-Fehler: {abuseipdb_data['error']}"
            }

        # ==========================
        # IP-API
        # ==========================

        ipapi_data = get_ipapi_info(ip_address)

        if "error" in ipapi_data:
            return {
                "success": False,
                "error": f"IP-API-Fehler: {ipapi_data['error']}"
            }

        # ==========================
        # IPsum
        # ==========================

        ipsum_data = get_ipsum_info(ip_address)

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

            "threat_data": {

                # bereits vorhanden
                "score": abuseipdb_data.get("abuseConfidenceScore", 0),
                "whitelisted": abuseipdb_data.get("isWhitelisted", False),

                # neu
                "domain": abuseipdb_data.get("domain", "Unbekannt"),

                "hostname":
                    ", ".join(abuseipdb_data.get("hostnames", []))
                    if abuseipdb_data.get("hostnames")
                    else "Unbekannt",

                "usage_type": abuseipdb_data.get(
                    "usageType",
                    "Unbekannt"
                ),

                "reports": abuseipdb_data.get(
                    "totalReports",
                    0
                ),

                "tor": abuseipdb_data.get(
                    "isTor",
                    False
                )

            },

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

        set_cached_result(ip_address, result)

        return result

    except Exception as e:

        return {
            "success": False,
            "error": f"Kritischer Fehler im Koordinator: {str(e)}"
        }