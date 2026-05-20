"""
Schnittstellen-Modul für den IPsum Threat Intelligence Feed.
Basiert auf 30+ verschiedenen öffentlich zugänglichen Listen von auffälligen/bösartigen IP-Adressen.

Es wird kein API-Schlüssel benötigt.
"""

import requests # Nötig, um HTTP-Anfragen an die API zu senden

def get_ipsum_info(ip_address):

    """
    Prüft, ob eine IP im Bedrohungsfeed (Level 3+) steht.
    https://github.com/stamparm/ipsum/blob/master/levels/3.txt

    Args:
        ip_address (str): Die zu überprüfende IPv4- oder IPv6-Adresse.
    
    Returns:
        dict: Ein Dictionary mit dem Status der Liste
    """

    # Statt der oben genannten URL wird die RAW-URL der GitHub-Datei verwendet, damit wir den reinen Textinhalt erhalten
    url = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" 

    try:

        # Feed wird heruntergeladen (wenn nach 5 Sekuden GitHub nicht antwortet, wird die Anfrage abgebrochen, damit die App nicht einfriert)
        response = requests.get(url, timeout = 5)
        response.raise_for_status() # Wenn GitHub einen Fehler meldet, wird sofort unten in den except-Block gesprungen

        # Es wird gepürft, ob die IP-Adresse irgendwo im Text des Feeds vorkommt
        if ip_address in response.text:

            # Wenn die IP-Adresse im Text gefunden wird, stoppt die Funktion sofort und schickt ein Paket samt Warntext zurück
            return {
                "listed": True,
                "status_text": "Kritisch (Auf mindestens 3 globalen Blacklists)"
            }
        
        # Trifft die if-Bedingung oben nicht zu (IP nicht auf der Liste), wird dieses Paket zurückgegeben
        return {
            "listed": False,
            "status_text": "Sauber oder unauffällig"
        }
    
     # Wenn im try-Block ein Fehler auftritt, greift dieser except-Block und fängt die Ausnahme ab
    except Exception as e:
        return {"error": f"Anfragefehler IPsum: {str(e)}"} # Das e wird automatisch mit der Fehlermeldung gefüll (z.B. "Netzwerkfehler", "Ungültige URL")


