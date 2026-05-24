"""
Prüft, ob eine Zeichenkette eine formal gültige IPv4- oder eine IPv6-Adresse ist.

Die Funktion nutzt das interne Python-Modul 'ipaddress', um die Eingabe zu validieren.
Dabei wird versucht, ein IP-Objekt zu erstellen. Schlägt dies fehl (ValueError), 
so wird die Adresse als ungültig markiert.
"""

import ipaddress  # Nötig, um die Funktion ipaddress.ip_address() zu verwenden


def ip_testung(ip):
    """
    Überprüft eine übergebene Zeichenkette auf ein gültiges IPv4- oder IPv6-Format.

    Args:
        ip (str): Die zu prüfende IP-Adresse als String.

    Returns:
        bool: True, wenn das Format valide ist, andernfalls False.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False