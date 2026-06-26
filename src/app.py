"""
IP-Checker Web-Applikation

Dieses Modul stellt die Benutzeroberfläche der Web-Applikation mittels Streamlit bereit.
Es dient als Haupteinstiegspunkt der Anwendung, nimmt Benutzereingaben entgegen und koordiniert
die Interaktion mit dem Validator, dem API-Koordinator und dem Scoring-Modul.
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
                    st.info("Ergebnis wurde aus dem Cache geladen.")
                else:
                    st.info("Ergebnis wurde neu über die APIs abgefragt.")

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
                        padding: 18px;
                        border-radius: 10px;
                        border: 2px solid {risk["color"]};
                        background-color: rgba(128, 128, 128, 0.08);
                    ">
                        <h3>{risk["icon"]} {risk["level"]}</h3>
                        <p>{risk["explanation"]}</p>
                        <p><b>Final Risk Score:</b> {final_score}/100</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                st.divider()

                st.subheader("🛡️ IT-Sicherheitsreputation")

                col_t1, col_t2, col_t3 = st.columns(3)

                col_t1.metric("Abuse Score", f"{threat['score']}%")
                col_t2.metric("Final Risk Score", f"{final_score}/100")
                col_t3.metric("Risk Level", risk["level"])

                st.write(
                    f"**Whitelist-Status:** {'Ja' if threat['whitelisted'] else 'Nein'}"
                )

                st.divider()

                st.subheader("📍 Geografische Lokalisierung")

                col_g1, col_g2, col_g3 = st.columns(3)

                col_g1.metric("Land (Code)", geo["country_code"])
                col_g2.metric("Stadt", geo["city"])
                col_g3.metric("Region", geo["region"])

                st.write(f"**Internet-Provider (ISP):** {geo['isp']}")
                st.write(f"**Zeitzone:** {geo['timezone']}")

                st.divider()

                st.subheader("📋 Globaler Blacklist-Abgleich")

                col_b1, col_b2 = st.columns(2)

                status_icon = "🔴 JA" if blacklist["listed"] else "🟢 NEIN"
                col_b1.write(f"**Auf Verbotsliste gefunden:** {status_icon}")
                col_b2.write(f"**Detail-Status:** {blacklist['status']}")

    else:
        st.error("Die IP-Adresse ist ungültig!")