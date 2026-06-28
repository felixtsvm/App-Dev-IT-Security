"""
IP-Checker Web-Applikation

Dieses Modul stellt die Benutzeroberfläche (UI) der Web-Applikation mittels Streamlit bereit.
Es dient als visueller Haupteinstiegspunkt der Anwendung, nimmt Benutzereingaben entgegen und koordiniert
die Interaktion mit dem Validator, dem API-Koordinator und dem Scoring-Modul.

Die Architektur der Benutzeroberfläche ist in zwei Hauptmodi unterteilt:

1. Einzelprüfung: Konzipiert für manuelle, tiefgehende Analysen. Dieser Modus
   richtet sich an private Anwender oder Security-Analysten und visualisiert detaillierte 
   Threat-Intelligence-Metriken, geografische Daten und Blacklist-Einträge zur individuellen Auswertung

2. Batch-Scan (Massenverarbeitung): Speziell entwickelt für den betrieblichen Kontext.
   Hierbei liegt der Fokus auf der performanten, gleichzeitigen  Verarbeitung vieler IP-Adressen. 
   Die Ausgabe ist bewusst auf das Wesentliche reduziert und liefert insbesondere maschinenlesbare, binäre Handlungsempfehlungen.
"""

import streamlit as st

from coordinator import run_complete_scan
from validator import ip_testung
from scoring import calculate_final_score, calculate_risk_level


st.set_page_config(
    page_title="IP-Checker",
    page_icon="🛡️"
)

st.title("IP-Checker")
st.markdown("Prüfe verdächtige IP-Adressen auf ihre Vertrauenswürdigkeit!")

scan_mode = st.radio(
    "Scan-Modus auswählen:",
    ["Einzelprüfung", "Batch-Scan"]
)

# =====================================================
# Einzelprüfung
# =====================================================

if scan_mode == "Einzelprüfung":

    ip_input = st.text_input(
        "Gewünschte IP-Adresse zur Prüfung:",
        placeholder="z. B. 92.208.35.210"
    )

    if st.button("Prüfen"):

        if ip_testung(ip_input):

            with st.spinner(f"Prüfe {ip_input}... in der Datenbank"):

                result = run_complete_scan(ip_input)

                if not result["success"]:
                    st.error(result["error"])

                else:
                    st.success(f"Analyse für {ip_input} abgeschlossen!")

                    if result.get("cache_hit"):
                        st.info("⚡ Ergebnis wurde aus dem Cache geladen.")
                    else:
                        st.info("🌐 Ergebnis wurde neu über die APIs abgefragt.")

                    threat = result["threat_data"]
                    geo = result["geo_data"]
                    blacklist = result["blacklist_data"]

                    final_score = calculate_final_score(
                        abuse_score=threat["score"],
                        is_blacklisted=blacklist["listed"],
                        is_whitelisted=threat["whitelisted"]
                    )

                    risk = calculate_risk_level(final_score)

                    st.subheader("🚦 Risiko-Bewertung")

                    st.markdown(
                        f"""
                        <div style="
                            padding:18px;
                            border-radius:10px;
                            border:2px solid {risk['color']};
                            background-color:rgba(128,128,128,0.08);
                        ">
                        <h3>{risk['icon']} {risk['level']}</h3>
                        <p>{risk['explanation']}</p>
                        <h2>Final Risk Score: {final_score}/100</h2>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                    st.progress(final_score / 100)

                    st.divider()

                    st.subheader("🛡️ IT-Sicherheitsreputation")

                    col1, col2, col3 = st.columns(3)

                    col1.metric("Abuse Score", f"{threat['score']}%")
                    col2.metric("Final Risk Score", f"{final_score}/100")
                    col3.metric("Risk Level", risk["level"])

                    st.write(f"**Whitelist:** {'Ja' if threat['whitelisted'] else 'Nein'}")
                    st.write(f"**Usage Type:** {threat['usage_type']}")
                    st.write(f"**Domain:** {threat['domain']}")
                    st.write(f"**Hostname:** {threat['hostname']}")
                    st.write(f"**Total Reports:** {threat['reports']}")
                    st.write(f"**Tor Exit Node:** {'Ja' if threat['tor'] else 'Nein'}")

                    st.divider()

                    st.subheader("📍 Geografische Lokalisierung")

                    col1, col2, col3 = st.columns(3)

                    col1.metric("Land", geo["country_code"])
                    col2.metric("Stadt", geo["city"])
                    col3.metric("Region", geo["region"])

                    st.write(f"**Internet-Provider:** {geo['isp']}")
                    st.write(f"**Zeitzone:** {geo['timezone']}")

                    st.divider()

                    st.subheader("📋 Globaler Blacklist-Abgleich")

                    col1, col2 = st.columns(2)

                    status = "🔴 JA" if blacklist["listed"] else "🟢 NEIN"

                    col1.write(f"**Blacklist:** {status}")
                    col2.write(f"**Status:** {blacklist['status']}")

        else:
            st.error("Die IP-Adresse ist ungültig!")


# =====================================================
# Batch-Scan
# =====================================================

if scan_mode == "Batch-Scan":

    st.subheader("📦 Batch-Scan")

    batch_input = st.text_area(
        "Mehrere IP-Adressen eingeben, jeweils eine IP pro Zeile:",
        placeholder="8.8.8.8\n1.1.1.1\n185.220.101.1",
        height=180
    )

    if st.button("Batch prüfen"):

        ip_list = [
            ip.strip()
            for ip in batch_input.splitlines()
            if ip.strip()
        ]

        if not ip_list:
            st.error("Bitte mindestens eine IP-Adresse eingeben.")

        else:
            results_table = []

            with st.spinner("Batch-Scan läuft..."):

                for ip_address in ip_list:

                    if not ip_testung(ip_address):
                        results_table.append({
                            "IP-Adresse": ip_address,
                            "Status": "Ungültige IP",
                            "Final Score": "-",
                            "Risk Level": "-",
                            "Blacklist": "-",
                            "Cache": "-"
                        })
                        continue

                    result = run_complete_scan(ip_address)

                    if not result["success"]:
                        results_table.append({
                            "IP-Adresse": ip_address,
                            "Status": result["error"],
                            "Final Score": "-",
                            "Risk Level": "-",
                            "Blacklist": "-",
                            "Cache": "-"
                        })
                        continue

                    threat = result["threat_data"]
                    blacklist = result["blacklist_data"]

                    final_score = calculate_final_score(
                        abuse_score=threat["score"],
                        is_blacklisted=blacklist["listed"],
                        is_whitelisted=threat["whitelisted"]
                    )

                    risk = calculate_risk_level(final_score)

                    results_table.append({
                        "IP-Adresse": ip_address,
                        "Status": "Erfolgreich",
                        "Final Score": final_score,
                        "Risk Level": f"{risk['icon']} {risk['level']}",
                        "Abuse Score": f"{threat['score']}%",
                        "Blacklist": "Ja" if blacklist["listed"] else "Nein",
                        "Land": result["geo_data"]["country_code"],
                        "ISP": result["geo_data"]["isp"],
                        "Cache": "Ja" if result.get("cache_hit") else "Nein"
                    })

            st.success("Batch-Scan abgeschlossen!")

            st.dataframe(
                results_table,
                use_container_width=True
            )