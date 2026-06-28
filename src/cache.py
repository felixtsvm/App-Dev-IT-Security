"""
Cache-Modul für den IP-Checker.

Dieses Modul speichert Analyse-Ergebnisse kurzfristig im Arbeitsspeicher,
damit identische IP-Adressen nicht mehrfach direkt hintereinander über
externe APIs abgefragt werden müssen.

Das spart zum einen API-Rate-Limits (da exteren Dienste wie AbuseIPDB Anfragen pro Minute/Tag limitieren)
und zum anderen beschleunigt es die Performance, da der RAM-Zugriff um ein Vielfaches schneller ist als eine HTTP-Anfrage an einen externen Server.
"""

import time # Lädt das Standard-Python-Modul 'time', um Zeitstempel zu erzeugen und damit berechnen, wie lange eine IP-Adresse bereits im Cache liegt
import copy # Lädt das Standard-Python-Modul 'copy', um tiefe Kopien von Dictionaries zu erstellen, damit die Originaldaten im Cache nicht versehentlich verändert werden

CACHE = {} # Erstellt ein leeres Dictionary - hier werden später alle IP-Adressen gesammelt
CACHE_TTL_SECONDS = 600 # Nach genau 600 Sekunden (10 Minuten) werden die Cache-Einträge automatisch gelöscht, damit die Daten nicht veralten und die App nicht zu viel RAM verbraucht


def get_cached_result(ip_address):
    """
    Prüft, ob für eine IP-Adresse ein gültiges Cache-Ergebnis existiert.

    Prüft zuerst, ob die IP-Adresse im Speicher hinterlegt ist. Falls ja, wird geprüft, ob das Ergebnis noch gültig ist (nicht älter als 10 Minuten).
    Ist die Lebensdauer (TTL) überschritten, wird der Eintrag gelöscht. Bei einem gültigen Eintrag wird das gespeicherte Ergebnis zurückgegeben.

    Args:
        ip_address (str): Die geprüfte IP-Adresse.

    Returns:
        dict | None: Eine tiefe Kopie des API-Ergebnispakets bei einem gültigen Cache-Treffer.
                     Gibt None zurück, wenn die IP nicht im Cache ist oder der Eintrag abgelaufen ist.
    """

    # Die if-Bedingung prüft, ob die IP-Adresse im  CACHE-Dictionary existiert. Wenn nicht, wird None zurückgegeben - sprich wir müssen die echte API-Abfrage durchführen
    if ip_address not in CACHE:
        return None

    else:
        cached_entry = CACHE[ip_address] # IP existiert im Cache, daher werden die gespeicherten Daten in der Variable cached_entry abgelegt
        age = time.time() - cached_entry["timestamp"] # Berechnet, wie lange die IP-Adresse bereits im Cache liegt

        # Wenn das berechnete Alter age größer ist als die erlaubten 10 Minuten, wird die IP mitsamt ihren Daten komplett aus dem Cache gelöscht und None zurückgegeben, damit die App die echte API-Abfrage durchführen muss
        if age > CACHE_TTL_SECONDS:
            del CACHE[ip_address]
            return None
        
        # Ist die IP-Adresse im Cache noch gültig, wird das gespeicherte API-Ergebnis zurückgegeben
        else:
         return copy.deepcopy(cached_entry["result"]) 



def set_cached_result(ip_address, result):
    """
    Speichert ein API-Analyse-Ergebnis im Cache.

    Args:
        ip_address (str): Die geprüfte IP-Adresse.
        result (dict): Das dazugehörige API-Analyse-Ergebnis.
    """
    
    # Programm greift auf das globale CACHE-Dictionary zu. Durch [ip_address] wird ein neuer Eintrag für die IP-Adresse erstellt (quasi ein Unter-Dictionary)
    CACHE[ip_address] = {
        "timestamp": time.time(), # Aktuelle Systemzeit wird abgerufen, damit wir später berechnen können, wie lange die IP-Adresse bereits im Cache liegt
        "result": copy.deepcopy(result) # Das Ergebnis wird als tiefe Kopie gespeichert, damit die Originaldaten im Cache nicht versehentlich verändert werden
    }