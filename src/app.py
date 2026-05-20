"""
IP-Checker Web-Applikation

Dieses Modul stellt die Benutzeroberfläche (UI) der Web-Applikation mittels Streamlit bereit.
Es dient als Haupteinstiegspunkt der Anwendung, nimmt Benutzereingaben entgegen und kooridiniert 
die Interaktion mit dem Validator (Logik) und dem API-Koordinator.
"""

# ====================================================================
# 1. Importe
# ====================================================================
import streamlit as st # Streamlit-Bibliothek importieren (Framework für die UI)
from coordinator import run_complete_scan # Koordiniert die einzelnen API-Abfragen
from validator import ip_testung # Methode, welche die formale Richtigkeit der IP-Adresse validiert

# ====================================================================
# 2. Metadaten für den Browser-Tab
# ===================================================================
st.set_page_config (
    page_title = "IP-Checker", # Text, der oben im Browser-Tab angezeigt wird
    page_icon = "🛡️" # Icon neben dem Tab-Titel
)

# ====================================================================
# 3. Graphische Oberfläche (UI-Layout & Texte)
# ====================================================================

# Hauptüberschrift der Seite
st.title("IP-Checker")

# Unterüberschrift
st.markdown(""" Prüfe verdächtige IP-Adressen auf ihre Vertrauenswürdigkeit! """)

# ====================================================================
# 4. Benutzeingabe
# ====================================================================

# Eingabefeld für die IP-Adresse, die der Benutzer überprüfen möchte
ip_input = st.text_input (
    "Gewünschte IP-Adresse zur Prüfung:",
    placeholder = "z.B. 92.208.35.210"
)

# ====================================================================
# 5. Hauptlogik
# ====================================================================

# Wird wahr, wenn der Benutzer auf den unten erstellten "Prüfen"-Button klickt
if st.button("Prüfen"):

    # Stufe 1: Formale Validierung über das importierte Validator-Modul
    if ip_testung(ip_input):

        # Visuelles Lade-Feedback, während die API-Anfragen im Hintergrund laufen
        with st.spinner(f"Prüfe {ip_input}... in der Datenbank"):

            # Es wird der Koordinator aufgerufen. Dieser erledigt alle 3 API-Abfragen
            result = run_complete_scan (ip_input)

            # Stufe 2: Fehlerbehandlung, falls der Koordintor einen Fehler zurückgibt (success == False)
            if not result ["success"]:
                st.error(result["error"])

            else:
                # Erfolgsmeldung bei erfolgreicher Analyse
                st.success(f"Analyse für {ip_input} abgeschlossen!")

                # ==============================================================================================
                # 5.1 Datenvisualiserung
                # ==============================================================================================
                # Anzeige der ausgewählten und sortierten Metriken aus unserem Koordinator-Paket
                # Hinweis: Die technische Datenanalyse ist an dieser Stelle vollständig abgeschlossen.
                # Die folgenden Zeilen dienen rein der grafischen Aufbereitung der Ergebnisse für den Benutzer.
                # ----------------------------------------------------------------------------------------------
                
                # --------------------------------------------------------------------
                # Bereich A: IP-Sicherheitsdaten (AbuseIPDB)
                # --------------------------------------------------------------------
                st.subheader("🛡️ IT-Sicherheitsreputation")
                threat = result["threat_data"] # Sicherheits-Paket aus dem Gesamtpaket
                
                # Es werden 2 nebeneinanderliegende Spalten für die wichtigsten Kennzahlen erstellt
                col_t1, col_t2 = st.columns(2)

                col_t1.metric("Abuse Score", f"{threat['score']}%") # Abuse-Score in Prozent
                col_t2.metric("Whitelist-Status", "Ja" if threat['whitelisted'] else "Nein") # "Ja" oder "Nein", je nachdem, ob die IP auf einer Whitelist steht

                st.divider() # Trennlinie für eine saubere Optik

                # --------------------------------------------------------------------
                # Bereich B: Geografische Informationen (IP-API)
                # --------------------------------------------------------------------
                st.subheader("📍 Geografische Lokalisierung")
                geo = result["geo_data"] # Standort-Unterpaket aus dem Gesamtpaket
                
                # Es wird ein dreispaltiges Layout für Land, Stadt und Region erstellt.
                col_g1, col_g2, col_g3 = st.columns(3)

                col_g1.metric("Land (Code)", geo["country_code"]) # Anzeige des Ländercodes
                col_g2.metric("Stadt", geo["city"]) # Anzeige des Stadtnamens
                col_g3.metric("Region", geo["region"]) # Anzeige des Bundeslands
                
                # Anzeige von ISP und Zeitzone darunter
                st.write(f"**Internet-Provider (ISP):** {geo['isp']}")
                st.write(f"**Zeitzone:** {geo['timezone']}")

                st.divider() # Erneute Trennlinie vor dem letzten Block

                # --------------------------------------------------------------------
                # Bereich C: Globale Blacklists (IPsum via GitHub)
                # --------------------------------------------------------------------
                st.subheader("📋 Globaler Blacklist-Abgleich")
                blacklist = result["blacklist_data"] # Blacklist-Unterpaket aus dem Gesamtpaket
                
                # Es werden 2 Spalten für die Auswertung des GitHub-Feeds erstellt
                col_b1, col_b2 = st.columns(2)

                status_icon = "🔴 JA" if blacklist['listed'] else "🟢 NEIN" # Je nach (Nicht-)Listung ändert sich die Farbe des Status-Punkts
                col_b1.write(f"**Auf Verbotsliste gefunden:** {status_icon}") # Anzeige, ob die IP generell auf der Liste steht
                col_b2.write(f"**Detail-Status:** {blacklist['status']}") # Anzeige, auf wie vielen Blacklists die IP steht

    else:
        # Fehlermeldung, wenn die der Validator feststellt, dass die IP-Adresse ungültig ist
        st.error("Die IP-Adresse ist ungültig!")