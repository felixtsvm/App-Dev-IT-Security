"""
Cache-Modul für den IP-Checker.

Dieses Modul speichert Analyse-Ergebnisse kurzfristig im Arbeitsspeicher,
damit identische IP-Adressen nicht mehrfach direkt hintereinander über
externe APIs abgefragt werden müssen.
"""

import time
import copy

CACHE = {}
CACHE_TTL_SECONDS = 600


def get_cached_result(ip_address):
    """
    Prüft, ob für eine IP-Adresse ein gültiges Cache-Ergebnis existiert.

    Args:
        ip_address (str): Die geprüfte IP-Adresse.

    Returns:
        dict | None: Gespeichertes Ergebnis oder None.
    """

    if ip_address not in CACHE:
        return None

    cached_entry = CACHE[ip_address]
    age = time.time() - cached_entry["timestamp"]

    if age > CACHE_TTL_SECONDS:
        del CACHE[ip_address]
        return None

    return copy.deepcopy(cached_entry["result"])


def set_cached_result(ip_address, result):
    """
    Speichert ein Analyse-Ergebnis im Cache.

    Args:
        ip_address (str): Die geprüfte IP-Adresse.
        result (dict): Analyse-Ergebnis.
    """

    CACHE[ip_address] = {
        "timestamp": time.time(),
        "result": copy.deepcopy(result)
    }