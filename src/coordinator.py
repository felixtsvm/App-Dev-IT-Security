"""
Zentraler API-Koordinator.

Dieses Modul koordiniert die Abfragen an allen externen APIs.
Es ruft die einzelnen API-Funktionen nacheinander auf, fängt Fehler ab
und bündelt die Ergebnisse zu einem standardisierten Gesamtpaket
für das Streamlit-Frontend.
"""

from apis.abuseipdb import get_abuseipdb_info
from apis.ipapi import get_ipapi_info
from apis.ipsum import get_ipsum_info


def run_complete_scan(ip_address):
    """
    Führt eine vollständige IP-Analyse durch.

    Args:
        ip_address (str): Die zu überprüfende IPv4- oder IPv6-Adresse.

    Returns:
        dict: Ergebnis mit success-Status, Datenpaketen oder Fehlermeldung.
    """

    try:
        abuseipdb_data = get_abuseipdb_info(ip_address)

        if "error" in abuseipdb_data:
            return {
                "success": False,
                "error": f"AbuseIPDB-Fehler: {abuseipdb_data['error']}"
            }

        ipapi_data = get_ipapi_info(ip_address)

        if "error" in ipapi_data:
            return {
                "success": False,
                "error": f"IP-API-Fehler: {ipapi_data['error']}"
            }

        ipsum_data = get_ipsum_info(ip_address)

        if "error" in ipsum_data:
            return {
                "success": False,
                "error": f"IPsum-Fehler: {ipsum_data['error']}"
            }

        return {
            "success": True,

            "threat_data": {
                "score": abuseipdb_data.get("abuseConfidenceScore", 0),
                "whitelisted": abuseipdb_data.get("isWhitelisted", False)
            },

            "geo_data": {
                "country_code": ipapi_data.get("countryCode", "Unbekannt"),
                "city": ipapi_data.get("city", "Unbekannt"),
                "region": ipapi_data.get("regionName", "Unbekannt"),
                "isp": ipapi_data.get("isp", "Unbekannt"),
                "timezone": ipapi_data.get("timezone", "Unbekannt")
            },

            "blacklist_data": {
                "listed": ipsum_data.get("listed", False),
                "status": ipsum_data.get("status_text", "Keine Daten")
            }
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Kritischer Fehler im Koordinator: {str(e)}"
        }