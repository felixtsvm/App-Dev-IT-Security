"""
Scoring-Modul für den IP-Checker.

Dieses Modul berechnet einen eigenen Final Risk Score auf Basis mehrerer Quellen.
Der Score liegt zwischen 0 und 100.
"""

def calculate_final_score(abuse_score, is_blacklisted, is_whitelisted):
    """
    Berechnet einen eigenen Risiko-Score.

    Args:
        abuse_score (int): Abuse Confidence Score von AbuseIPDB.
        is_blacklisted (bool): Ergebnis aus IPsum.
        is_whitelisted (bool): Whitelist-Status von AbuseIPDB.

    Returns:
        int: Final Risk Score zwischen 0 und 100.
    """

    score = 0

    # AbuseIPDB ist die stärkste Quelle und zählt maximal 60 Punkte.
    score += int(abuse_score * 0.6)

    # Wenn IPsum die IP findet, ist das ein starker Risikohinweis.
    if is_blacklisted:
        score += 30

    # Wenn die IP nicht auf einer Whitelist steht, gibt es einen kleinen Risikoaufschlag.
    if not is_whitelisted:
        score += 10

    # Score darf nie über 100 gehen.
    return min(score, 100)


def calculate_risk_level(final_score):
    """
    Wandelt den Final Risk Score in ein verständliches Risiko-Level um.
    """

    if final_score >= 70:
        return {
            "level": "Hohes Risiko",
            "icon": "🔴",
            "color": "red",
            "explanation": "Die IP-Adresse weist deutliche Hinweise auf schädliches Verhalten auf."
        }

    if final_score >= 30:
        return {
            "level": "Mittleres Risiko",
            "icon": "🟡",
            "color": "orange",
            "explanation": "Die IP-Adresse ist auffällig, aber nicht eindeutig kritisch."
        }

    return {
        "level": "Niedriges Risiko",
        "icon": "🟢",
        "color": "green",
        "explanation": "Die IP-Adresse zeigt aktuell keine starken Auffälligkeiten."
    }