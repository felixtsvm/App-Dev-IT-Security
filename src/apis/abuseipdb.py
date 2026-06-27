"""
Schnittstellen-Modul für die AbuseIPDB-API.

Dieses Modul fragt die AbuseIPDB-API ab und liefert sicherheitsrelevante
Informationen zu einer IP-Adresse zurück. Dazu gehören unter anderem der
Abuse Confidence Score, Whitelist-Status, Domain, Hostname, Usage Type,
Anzahl der Reports und Tor-Status.
"""

import os
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()


def get_api_key():
    """
    Holt den AbuseIPDB-API-Key.

    Zuerst wird versucht, den Key aus Streamlit Secrets zu laden.
    Falls das nicht möglich ist, wird die .env-Datei verwendet.

    Returns:
        str | None: API-Key oder None.
    """

    try:
        return st.secrets["AbuseIPDB_KEY"]
    except Exception:
        return os.getenv("AbuseIPDB_KEY")


def get_abuseipdb_info(ip_address):
    """
    Sendet eine IP-Adresse an die AbuseIPDB-API und ruft Reputationsdaten ab.

    Args:
        ip_address (str): Die zu überprüfende IPv4- oder IPv6-Adresse.

    Returns:
        dict: Erfolgreiche Analysedaten oder Fehlermeldung unter 'error'.
    """

    api_key = get_api_key()

    if not api_key:
        return {"error": "Kein AbuseIPDB API-Key gefunden."}

    url = "https://api.abuseipdb.com/api/v2/check"

    parameters = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=parameters,
            timeout=10
        )

        if response.status_code == 200:
            return response.json().get("data", {})

        return {
            "error": f"API-Fehler: Status {response.status_code}"
        }

    except Exception as e:
        return {
            "error": f"Anfragefehler AbuseIPDB: {str(e)}"
        }