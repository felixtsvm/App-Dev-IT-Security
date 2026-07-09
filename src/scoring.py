"""
Scoring-Modul für den IP-Checker.

Dieses Modul berechnet einen differenzierten Final Risk Score auf Basis 
netzwerkspezifischer, historischer und geografischer Parameter.

Das Scoring wird letztendlich die Basis dafür sein, ob eine IP-Adresse als "sicher" oder "gefährlich" eingestuft wird.
Und damit, ob die IP-Adresse in einer Firewall blockiert oder zugelassen wird.
"""

def calculate_final_score(threat_data, blacklist_data, geo_data):
    """
    Berechnet einen Enterprise-Risiko-Score anhand multipler Parameter.

    Args:
        threat_data (dict): Das Threat-Paket aus dem Koordinator (AbuseIPDB).
        blacklist_data (dict): Das Blacklist-Paket aus dem Koordinator (IPsum).
        geo_data (dict): Das Geo-Paket aus dem Koordinator (IP-API).

    Returns:
        int: Final Risk Score zwischen 0 und 100.
    """
    score = 0

    # =====================================================
    # 1. Abuse Confidence Score (Maximal 40 Punkte)
    # =====================================================
    # Score aus der AbuseIPDB, der bereits eine gute Indikation für die Vertrauenswürdigkeit einer IP-Adresse liefert.
    abuse_score = threat_data["score"]
    if abuse_score != "Unbekannt":
        score += int(float(abuse_score) * 0.4)

    # =====================================================
    # 2. Blacklist-Prüfung (+30 Punkte)
    # =====================================================
    # Ist der Status "listed" auf True gesetzt, ist die IP-Adresse in mindestens 3 Blacklists enthalten
    if blacklist_data["listed"]:
        score += 30

    # =====================================================
    # 3. Tor-Netzwerk (+20 Punkte)
    # =====================================================
    # Ist die IP-Adresse im Tor-Netzwerk aktiv, deutet dies auf eine Verschleierung der Identität hin und ist ein Indikator für potenziell schädliches Verhalten
    if threat_data["tor"]:
        score += 20

    # =====================================================
    # 4. Usage Type / Rechenzentrum (+10 Punkte)
    # =====================================================
    # Viele Angriffe stammen von IP-Adressen, die in Rechenzentren oder Webhosting-Umgebungen gehostet werden 
    usage_type = str(threat_data["usage_type"]).lower()
    if "data center" in usage_type or "web hosting" in usage_type:
        score += 10

    # =====================================================
    # 5. Hohes Meldevolumen (+10 Punkte)
    # =====================================================
    # Wenn eine IP-Adresse in der AbuseIPDB mehr als 50 Meldungen erhalten hat, deutet dies auf ein hohes Maß an schädlichem Verhalten hin
    reports = threat_data["reports"]
    if reports != "Unbekannt" and int(reports) > 50:
        score += 10

    # ==========================================
    # 6. Hostname & Domain Analyse (+15 Punkte)
    # ==========================================
    hostname = str(threat_data["hostname"]).lower()
    domain = str(threat_data["domain"]).lower()
    
    # 6.1 Dynamisches DNS (Oft von Hackern zur Verschleierung genutzt)
    ddns_providers = ["dyndns", "duckdns", "no-ip", "hopto", "bounceme"]
    if any(provider in hostname or provider in domain for provider in ddns_providers):
        score += 15
        
    # 6.2 Private Einwahlknoten / Consumer-ISPs (Deutet auf kompromittierte Privat-PCs / Botnets hin)
    consumer_patterns = ["dsl.", "pool.", "dip.", "dialin.", "dynamic."]
    if any(pattern in hostname for pattern in consumer_patterns):
        score += 15

    # ==========================================
    # 7. Geografische Plausibilität (+15 Punkte)
    # ==========================================
    # Ländercodes, aus denen statistisch am häufigsten Angriffe erfolgen
    high_risk_countries = ["RU", "CN", "KP", "IR", "BY", "SY"]
    country = str(geo_data["country_code"]).upper()
    
    if country in high_risk_countries:
        score += 15

    # ==========================================
    # 8. Whitelist-Bonus (-20 Punkte)
    # ==========================================
    # Whitelisted IP-Adressen werden als vertrauenswürdig eingestuft und erhalten daher einen Bonus, der den Score reduziert
    if threat_data["whitelisted"]:
        score -= 20

    # ==========================================
    # 9. Finale Begrenzung
    # ==========================================
    # Der Score wird nach unten auf 0 und nach oben auf 100 begrenzt
    return max(0, min(int(score), 100))


def calculate_risk_level(final_score):
    """
    Wandelt den Score in ein Risiko-Level und eine maschinelle Handlungsempfehlung um.
    """
    if final_score >= 70:
        return {
            "level": "Hohes Risiko",
            "icon": "🔴",
            "color": "red",
            "action": "Sperren",
            "explanation": "Massive Indikatoren für schädliches Verhalten. Automatisierte Sperrung empfohlen."
        }

    if final_score >= 30:
        return {
            "level": "Mittleres Risiko",
            "icon": "🟡",
            "color": "orange",
            "action": "Manuelle Prüfung",
            "explanation": "Auffällige Netzwerkparameter. IP sollte gemonitort oder manuell geprueft werden."
        }

    return {
        "level": "Niedriges Risiko",
        "icon": "🟢",
        "color": "green",
        "action": "Zulassen",
        "explanation": "Keine signifikanten Auffaelligkeiten. Traffic kann passieren."
    }