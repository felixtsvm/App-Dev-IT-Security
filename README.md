# App Development - Projekt 4: IT Security

🌐 **Live-Demo:** [ip-reputation-checken.streamlit.app](https://ip-reputation-checken.streamlit.app/)

---

## 👥 Team

- **Felix Kant**
- **Fikri Kaba**
- **Cemre Yazgan**

---

## 📝 Kurzbeschreibung

Dieses Projekt ist im Rahmen des Moduls **App-Development** entstanden. Es bietet ein professionelles, zweigeteiltes System zur Analyse von IP-Adressen, um potenzielle Bot-Aktivitäten und Sicherheitsrisiken frühzeitig zu erkennen.

Das System besteht aus einer **REST-API (Backend)** für schnelle, maschinelle Abfragen und einem interaktiven **Streamlit-Dashboard (Frontend)** für die visuelle Detail-Analyse. 

Durch die Bündelung verschiedener API-Quellen (AbuseIPDB, IP-API, IPsum) und eine intelligente Caching-Logik liefert unsere Anwendung sofortige Risiko-Scores und klare Handlungsempfehlungen (Blockieren, Überprüfen, Zulassen).

---

## ⚙️ Nutzung 1: Die REST-API (Für automatisierte Systeme)

Neben der grafischen Oberfläche bietet unser System eine schlanke, zustandslose REST-API. Diese API ist speziell für externe Systeme (z. B. Firewalls, Router oder Batch-Skripte) konzipiert, die in Millisekunden eine maschinenlesbare Handlungsempfehlung benötigen, ohne unnötigen Datenballast zu laden.

### 1. Lokale Installation & API-Server starten

Klonen Sie zuerst das Repository und wechseln Sie in das Projektverzeichnis:

```bash
git clone [https://github.com/felixtsvm/App-Dev-IT-Security.git](https://github.com/felixtsvm/App-Dev-IT-Security.git)
cd App-Dev-IT-Security
```

Richten Sie nun die virtuelle Umgebung passend zu Ihrem Betriebssystem ein:

#### 🪟 Windows Setup
```powershell
# 1. Sperre für lokale Skripte temporär aufheben
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# 2. Virtuelle Umgebung aktivieren
.\venv\Scripts\activate

# 3. Benötigte Pakete installieren
pip install -r requirements.txt
```

#### 🍎 Mac / Linux Setup
```bash
# 1. Virtuelle Umgebung aktivieren
source venv/bin/activate

# 2. Benötigte Pakete installieren
pip install -r requirements.txt
```

Sobald die Pakete installiert sind, starten Sie den Server:

```bash
python src/api.py
```

### 2. Abfrage senden & Ergebnisse
Sie können die API nun in einem zweiten Terminal-Fenster abfragen oder direkt über einen Webbrowser aufrufen.

#### A) Nutzung via Terminal
Nutze diesen Befehl, um die Antwort direkt als formatiertes JSON in deinem Terminal zu erhalten:

```bash
(curl "http://127.0.0.1:5001/check?ip=8.8.8.8" -UseBasicParsing).Content
```

#### B) Nutzung via Webbrowser
Gib die folgende URL einfach in die Adresszeile deines Browsers ein:

```bash
http://127.0.0.1:5001/check?ip=8.8.8.8
```

#### Ergebnis-Struktur
Die API liefert ein strukturiertes JSON-Objekt zurück, das Ihnen sofortige Handlungssicherheit gibt:

```json
{
  "final_score": 0,
  "handlungsempfehlung": "Zulassen",
  "ip_address": "8.8.8.8",
  "risk_level": "Niedriges Risiko",
  "success": true
}
```

Um die Berechnung des Scores exakt nachvollziehen zu können, kannst die detaillierte Gewichtung der einzelnen Quellen jederzeit im Quellcode unter src/scoring.py einsehen. Dort ist definiert, ab welchem Schwellenwert eine IP als "hohes Risiko" eingestuft wird.


## 📊 Nutzung 2: Das Streamlit-Dashboard (Frontend)

Das Dashboard bietet eine intuitive grafische Oberfläche für die visuelle Detail-Analyse.

### a) Web-Version
Du kannst das Tool direkt ohne Installation nutzen:
🌐 **[Zum Dashboard](https://ip-reputation-checken.streamlit.app/)**

### b) Lokales Dashboard starten
Falls du das Dashboard lokal ausführen möchtest (Voraussetzung: Windows- / Mac- / Linux-Setup vollzogen):
```bash
streamlit run src/app.py
```
*Das Dashboard öffnet sich anschließend automatisch unter `http://localhost:8501`.*