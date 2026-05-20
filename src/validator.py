"""
Prüft, ob eine Zeichenkette eine formal gültige IPv4- oder eine IPv6-Adresse ist.

Die Funktion nutzt das interne Python-Modul 'ipaddress', um die Eingabe zu validieren.
Dabei wird versucht, ein IP-Objekt zu erstellen. Schägt dies fehl (ValueError), so wird die Adresse als ungültig markiert.
"""

import ipaddress # Nötig, um die Funktion ipaddress.ip_address() zu verwenden

def ip_testung(ip):

    try:
        ipaddress.ip_address(ip)
        return True
    
    except ValueError:
        return False