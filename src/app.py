import time
import io
import pandas as pd
import streamlit as st

from coordinator import run_complete_scan
from validator import ip_testung
from scoring import calculate_final_score, calculate_risk_level


st.set_page_config(page_title="IP-Checker", page_icon="🛡️")

st.title("IP-Checker")
st.markdown("Prüfe verdächtige IP-Adressen auf ihre Vertrauenswürdigkeit!")

scan_mode = st.radio("Scan-Modus auswählen:", ["Einzelprüfung", "Batch-Scan"])


if scan_mode == "Einzelprüfung":
    ip_input = st.text_input(
        "Gewünschte IP-Adresse zur Prüfung:",
        placeholder="z. B. 92.208.35.210"
    )

    if st.button("Prüfen"):
        if ip_testung(ip_input):
            with st.spinner(f"Prüfe {ip_input}..."):
                start_time = time.perf_counter()
                result = run_complete_scan(ip_input)
                end_time = time.perf_counter()

                response_time_ms = (end_time - start_time) * 1000

                if not result["success"]:
                    st.error(result["error"])
                else:
                    threat = result["threat_data"]
                    geo = result["geo_data"]
                    blacklist = result["blacklist_data"]

                    final_score = calculate_final_score(threat, blacklist, geo)
                    risk = calculate_risk_level(final_score)

                    st.success(f"Analyse für {ip_input} abgeschlossen!")

                    st.metric("⏱️ Antwortzeit der IP-Bewertung", f"{response_time_ms:.2f} ms")

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

                    status = "🔴 JA" if blacklist["listed"] else "🟢 NEIN"
                    st.write(f"**Blacklist:** {status}")
                    st.write(f"**Status:** {blacklist['status']}")

                    if result.get("cache_hit"):
                        st.info("⚡ Ergebnis wurde aus dem Cache geladen.")
                    else:
                        st.info("🌐 Ergebnis wurde neu über die APIs abgefragt.")
        else:
            st.error("Die IP-Adresse ist ungültig!")


if scan_mode == "Batch-Scan":
    st.subheader("📦 Batch-Scan")

    batch_input = st.text_area(
        "Mehrere IP-Adressen eingeben, jeweils eine IP pro Zeile:",
        placeholder="8.8.8.8\n1.1.1.1\n185.220.101.1",
        height=180
    )

    if st.button("Batch prüfen"):
        ip_list = [ip.strip() for ip in batch_input.splitlines() if ip.strip()]

        if not ip_list:
            st.error("Bitte mindestens eine IP-Adresse eingeben.")
        else:
            results_table = []
            response_times = []

            with st.spinner("Batch-Scan läuft..."):
                for ip_address in ip_list:
                    if not ip_testung(ip_address):
                        results_table.append({
                            "IP-Adresse": ip_address,
                            "Status": "Ungültige IP",
                            "Antwortzeit (ms)": "-",
                            "Final Risk Score": "-",
                            "Risk Level": "-",
                            "Abuse Score": "-",
                            "Whitelist": "-",
                            "Usage Type": "-",
                            "Domain": "-",
                            "Hostname": "-",
                            "Total Reports": "-",
                            "Tor Exit Node": "-",
                            "Land": "-",
                            "Stadt": "-",
                            "Region": "-",
                            "ISP": "-",
                            "Zeitzone": "-",
                            "Blacklist": "-",
                            "Blacklist Status": "-",
                            "Cache": "-"
                        })
                        continue

                    start_time = time.perf_counter()
                    result = run_complete_scan(ip_address)
                    end_time = time.perf_counter()

                    response_time_ms = (end_time - start_time) * 1000
                    response_times.append(response_time_ms)

                    if not result["success"]:
                        results_table.append({
                            "IP-Adresse": ip_address,
                            "Status": result["error"],
                            "Antwortzeit (ms)": round(response_time_ms, 2),
                            "Final Risk Score": "-",
                            "Risk Level": "-",
                            "Abuse Score": "-",
                            "Whitelist": "-",
                            "Usage Type": "-",
                            "Domain": "-",
                            "Hostname": "-",
                            "Total Reports": "-",
                            "Tor Exit Node": "-",
                            "Land": "-",
                            "Stadt": "-",
                            "Region": "-",
                            "ISP": "-",
                            "Zeitzone": "-",
                            "Blacklist": "-",
                            "Blacklist Status": "-",
                            "Cache": "-"
                        })
                        continue

                    threat = result["threat_data"]
                    geo = result["geo_data"]
                    blacklist = result["blacklist_data"]

                    final_score = calculate_final_score(threat, blacklist, geo)
                    risk = calculate_risk_level(final_score)

                    results_table.append({
                        "IP-Adresse": ip_address,
                        "Status": "Erfolgreich",
                        "Antwortzeit (ms)": round(response_time_ms, 2),
                        "Final Risk Score": final_score,
                        "Risk Level": risk["level"],
                        "Abuse Score": threat["score"],
                        "Whitelist": "Ja" if threat["whitelisted"] else "Nein",
                        "Usage Type": threat["usage_type"],
                        "Domain": threat["domain"],
                        "Hostname": threat["hostname"],
                        "Total Reports": threat["reports"],
                        "Tor Exit Node": "Ja" if threat["tor"] else "Nein",
                        "Land": geo["country_code"],
                        "Stadt": geo["city"],
                        "Region": geo["region"],
                        "ISP": geo["isp"],
                        "Zeitzone": geo["timezone"],
                        "Blacklist": "Ja" if blacklist["listed"] else "Nein",
                        "Blacklist Status": blacklist["status"],
                        "Cache": "Ja" if result.get("cache_hit") else "Nein"
                    })

            st.success("Batch-Scan abgeschlossen!")

            df_results = pd.DataFrame(results_table)
            st.dataframe(df_results, use_container_width=True)

            statistics_data = []

            if response_times:
                sorted_times = sorted(response_times)
                n = len(sorted_times)

                mean_time = sum(sorted_times) / n

                if n % 2 == 1:
                    median_time = sorted_times[n // 2]
                else:
                    median_time = (sorted_times[n // 2 - 1] + sorted_times[n // 2]) / 2

                variance = sum((x - mean_time) ** 2 for x in sorted_times) / n
                standard_deviation = variance ** 0.5

                min_time = min(sorted_times)
                max_time = max(sorted_times)

                st.subheader("📊 Statistische Auswertung der Antwortzeiten")

                col1, col2, col3 = st.columns(3)
                col1.metric("Anzahl Messungen", n)
                col2.metric("Mittelwert μ", f"{mean_time:.2f} ms")
                col3.metric("Median Md", f"{median_time:.2f} ms")

                col4, col5, col6 = st.columns(3)
                col4.metric("Standardabweichung σ", f"{standard_deviation:.2f} ms")
                col5.metric("Minimum", f"{min_time:.2f} ms")
                col6.metric("Maximum", f"{max_time:.2f} ms")

                statistics_data = [
                    {"Kennzahl": "Anzahl Messungen", "Wert": n},
                    {"Kennzahl": "Mittelwert μ (ms)", "Wert": round(mean_time, 2)},
                    {"Kennzahl": "Median Md (ms)", "Wert": round(median_time, 2)},
                    {"Kennzahl": "Standardabweichung σ (ms)", "Wert": round(standard_deviation, 2)},
                    {"Kennzahl": "Minimum (ms)", "Wert": round(min_time, 2)},
                    {"Kennzahl": "Maximum (ms)", "Wert": round(max_time, 2)}
                ]

            excel_buffer = io.BytesIO()

            with pd.ExcelWriter(excel_buffer, engine="openpyxl") as writer:
                df_results.to_excel(writer, index=False, sheet_name="IP-Bewertungen")

                if statistics_data:
                    df_statistics = pd.DataFrame(statistics_data)
                    df_statistics.to_excel(writer, index=False, sheet_name="Statistik")

            excel_buffer.seek(0)

            st.download_button(
                label="📥 Ergebnisse als Excel herunterladen",
                data=excel_buffer,
                file_name="ip_bewertung_messwerte.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )