# 🔑 Lizenzmanager

[![GitHub release](https://img.shields.io/github/v/release/Speedy2524/lizenzmanager?include_prereleases&style=flat-square&color=blue)](https://github.com/Speedy2524/lizenzmanager/releases)
[![Docker Image](https://img.shields.io/badge/docker-ghcr.io-blue?style=flat-square&logo=docker)](https://github.com/Speedy2524/lizenzmanager/pkgs/container/lizenzmanager)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Security Hardened](https://img.shields.io/badge/security-OWASP%20Hardened-success?style=flat-square&logo=shield)](https://github.com/Speedy2524/lizenzmanager)

Ein modernes, benutzerfreundliches Web-Tool zur vollständigen Erfassung, Kosten- und Budgetüberwachung sowie automatisierten Fristenkontrolle aller Software-Lizenzen, Verträge und Abonnements.

Ausgestattet mit **Active Directory / LDAP**-Anbindung, einem integrierten **KI-Rechnungsassistenten (vLLM / OpenAI)**, gehärteter **OWASP-Sicherheitsarchitektur** und voller **Docker- & Windows-Unterstützung**.

---

## ✨ Hauptfunktionen

* 📊 **Dashboard & Kostenkontrolle:** Echtzeit-Metriken für aktive Verträge, monatliche Kostenäquivalente (MRR) und Jahresäquivalente (ARR), Kategorie- und Herstellerstatistiken.
* ⏰ **Automatisierter Fristenwarner:** Dynamische Berechnung der Kündigungs- und Ablauffristen nach einem 4-stufigen Ampelsystem (*Aktiv*, *Bald fällig*, *Dringend*, *Abgelaufen*).
* 📅 **Kalender- & Fristenübersicht:** Interaktive Fristenansicht zur gezielten Planung anstehender Verlängerungen oder Kündigungen.
* 👥 **Platzverwaltung (Seats):** Überwachung von lizenzierten vs. tatsächlich genutzten Arbeitsplätzen inkl. Überbuchungswarnung.
* 🛡️ **Lokaler Administrator & Setup-Wizard:** Interaktiver Ersteinrichtungs-Assistent beim ersten Programmstart (`/setup`) mit sicherer PBKDF2-Kennwortverschlüsselung – garantiert jederzeit Vollzugriff auch ohne Domänenverbindung.
* 👤 **Integrierte Benutzerverwaltung mit 3 Berechtigungsstufen:** Beliebig viele lokale Benutzer mit individuellen Gruppenrollen direkt im Menü anlegen und verwalten:
  * **Administrator:** Vollzugriff auf Lizenzen, Benutzerkonten, Revisionsprotokolle, Backups & Systemwartung.
  * **Bearbeiter:** Darf Lizenzen erstellen, bearbeiten, verlängern, archivieren & löschen sowie CSV- und KI-Importe durchführen.
  * **Betrachter (Read-Only):** Reine Leserechte für Lizenzen, Dashboard, Fristenkalender und Kostenanalyse.
* 📋 **Revisionssicheres Aktivitätsprotokoll & Audit-Log:** Lückenloses Protokoll aller Benutzeraktionen mit Zeitstempel, IP-Adresse und Benutzername. Löschvorgänge werden inklusive vollständigem Datensatz-Snapshot gesichert, sodass gelöschte Verträge jederzeit detailgenau eingesehen und rekonstruiert werden können (inkl. Such-/Filterfunktion & CSV-Export).
* 🏛️ **Active Directory & LDAP:** Sichere Benutzerauthentifizierung gegen Windows Server Domain Controller mit striktem Fail-Closed Berechtigungskonzept und Gruppenverwaltung (`LDAP_ADMIN_GROUP` und `LDAP_EDITOR_GROUP`).
* 🤖 **KI-Rechnungsimport (vLLM / Ollama / OpenAI):** Kopierte Rechnungstexte, Bestellmails oder PDF-Auszüge einfügen – die KI erkennt Software, Hersteller, Kosten, Fristen und Lizenzschlüssel und erzeugt einen fertigen Entwurf.
* 📥 **CSV-Massenimport & -Export:** Schneller Import bestehender Tabellen und bereinigter CSV-Export mit automatischem Schutz vor CSV-Formel-/DDE-Injection.
* 🔒 **Geprüfte IT-Sicherheit:**
  * Dynamische 256-Bit Sessionschlüssel (`SECRET_KEY`).
  * Schutz vor CSRF auf allen mutierenden API-Endpunkten.
  * Rate-Limiting gegen Brute-Force & Active Directory Account-Lockouts.
  * LDAP-Filter-Escaping gegen LDAP-Injections.
  * Strikte URL-Sanitization gegen Stored-XSS in Kundenportalen.
  * SQLite WAL-Modus (`PRAGMA journal_mode = WAL;`) für hohe Concurrency ohne Dateisperren.
* 🔔 **Automatische Update-Anzeige im Hauptmenü:** Prüft im Hintergrund diskret und asynchron auf neue GitHub Releases und signalisiert verfügbare Updates über eine pulsierende Benachrichtigung im Hauptmenü inkl. Versionsdetails und Update-Befehlen.
* 🌓 **Dark- & Light-Mode:** Angenehme Benutzeroberfläche mit modernem Farbschema und Design-Umschalter.

---

## 🚀 Schnellstart

### Option 1: Mit Docker Compose (Empfohlen für Server / NAS)

1. **Repository klonen:**
   ```bash
   git clone https://github.com/Speedy2524/lizenzmanager.git
   cd lizenzmanager
   ```

2. **(Optional) Konfiguration anpassen:**
   Kopiere die Konfigurationsvorlage und passe bei Bedarf deine Umgebung an:
   ```bash
   cp .env.example .env
   ```

3. **Container starten:**
   ```bash
   docker compose up -d
   ```

4. **Im Browser öffnen:**
   👉 **[http://localhost:5000](http://localhost:5000)** (bzw. die IP deines Servers)

---

### Option 2: Fertiges Docker-Image über GHCR (GitHub Packages)

Ohne manuelles Kompilieren direkt aus der GitHub Container Registry starten:

```bash
# 1. Datenverzeichnis für Persistenz anlegen
mkdir -p data

# 2. Container herunterladen und starten
docker run -d \
  --name lizenzmanager \
  --restart unless-stopped \
  -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  ghcr.io/speedy2524/lizenzmanager:latest
```

---

### Option 3: Lokaler Start unter Windows (ohne Docker)

1. Repository herunterladen oder klonen.
2. Doppelklick auf die beiliegende Datei **`start.bat`**.
3. Das Skript prüft automatisch die Python-Installation, installiert benötigte Abhängigkeiten und öffnet die Anwendung direkt im Standard-Browser.

---

### Option 4: Manueller Start mit Python (Linux / macOS / Windows)

```bash
# 1. Virtuelle Umgebung erstellen und aktivieren
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 2. Abhängigkeiten installieren
pip install -r requirements.txt

# 3. Server starten
python app.py
```

---

## 🛡️ Ersteinrichtung (Erster Programmstart)

Beim ersten Start prüft der Lizenzmanager, ob bereits ein lokaler Administrator existiert. Ist dies nicht der Fall, leitet die Anwendung automatisch auf den **Einrichtungs-Assistenten** (`/setup`) um:

1. **Administrator-Benutzername:** Standardmäßig `admin` (kann frei gewählt werden).
2. **Kennwort:** Frei wählbares Administrator-Kennwort (mindestens 8 Zeichen).
3. **Konto erstellen:** Das Kennwort wird gehasht in der SQLite-Datenbank hinterlegt und Sie werden sofort als Administrator angemeldet.

> [!TIP]
> **Headless / Unbeaufsichtigtes Setup:**  
> Für automatisierte Deployments (z. B. Ansible, Docker CI/CD) kann das Kennwort in der `.env` vorab definiert werden:
> ```env
> INITIAL_ADMIN_USER=admin
> INITIAL_ADMIN_PASSWORD=MeinSicheresKennwort123!
> ```
> In diesem Fall überspringt das System die Ersteinrichtungsseite automatisch.

---

## 👥 Lokale Benutzerverwaltung (Betrieb ohne Domäne)

Der Lizenzmanager benötigt **kein Active Directory**, um im Mehrbenutzerbetrieb produktiv eingesetzt zu werden. Im Tab **„Daten & Backup“** (bzw. Einstellungen) können Administratoren beliebig viele weitere lokale Benutzer anlegen:

* **🛡️ Administratoren:** Voller Schreib- und Lesezugriff auf alle Lizenzen, CSV-Import/Export, Datenbank-Backups und die Benutzerverwaltung.
* **👤 Standard-Benutzer (Betrachter):** Lesezugriff auf das Dashboard, die Lizenzlisten, Kostenanalysen und den Kalender. Keine Berechtigung zum Ändern, Hinzufügen oder Löschen von Daten.
* **🔒 Integrierte Schutzmechanismen:**
  * Der aktuell angemeldete Benutzer kann sein eigenes Konto nicht versehentlich löschen.
  * Der letzte verbleibende Administrator kann weder gelöscht noch zum Standard-Benutzer herabgestuft werden (Schutz vor Aussperrung).
  * Jeder Benutzer kann sein persönliches Kennwort über das Schlüssel-Symbol in der Kopfzeile eigenständig ändern.

---

## ⚙️ Konfigurationsreferenz (`.env`)

Kopieren Sie `.env.example` nach `.env`, um Einstellungen vorzunehmen:

| Variable | Standardwert | Beschreibung |
|---|---|---|
| **Sicherheit & Sitzung** | | |
| `SECRET_KEY` | *(automatisch generiert)* | 256-Bit Zufallsschlüssel für Flask-Sessions. In Produktivumgebungen manuell festlegen! |
| `AUTH_ENABLED` | `True` | Authentifizierung aktivieren (`True`) oder deaktivieren (`False`). |
| `SESSION_COOKIE_SECURE` | `False` | Auf `True` setzen, wenn der Lizenzmanager über HTTPS (Reverse Proxy / SSL) betrieben wird. |
| `MAX_CONTENT_LENGTH` | `10485760` (10 MB) | Maximale Dateigröße für Uploads in Bytes. |
| **Lokaler Administrator** | | |
| `INITIAL_ADMIN_USER` | `admin` | Benutzername für das initiale Administratorkonto. |
| `INITIAL_ADMIN_PASSWORD` | *(leer)* | Optionales Vorab-Kennwort zur automatischen Ersteinrichtung. |
| `ALLOW_DEMO_FALLBACK` | `False` | Notfall-Fallback nur bei explizitem DC-Ausfall im Labor aktivieren. |
| **Active Directory / LDAP** | | |
| `LDAP_HOST` | `dc01.firma.local` | Hostname oder IP-Adresse des Active Directory Domain Controllers. |
| `LDAP_PORT` | `389` | LDAP-Port (389 für Standard LDAP, 636 für LDAPS). |
| `LDAP_USE_SSL` | `False` | SSL-Verschlüsselung aktivieren (erforderlich bei Port 636). |
| `LDAP_DOMAIN` | `FIRMA.LOCAL` | Domänenname (z. B. `firma.local` oder NetBIOS `FIRMA`). |
| `LDAP_SEARCH_BASE` | `DC=firma,DC=local` | Base DN für Benutzer- und Gruppenabfragen. |
| `LDAP_REQUIRED_GROUP` | *(leer)* | Optionale AD-Gruppe: Nur Mitglieder dieser Gruppe erhalten Zugang (leer = alle). |
| `LDAP_ADMIN_GROUP` | `Lizenz-Admins` | AD-Sicherheitsgruppe für Vollzugriff (Lizenzen ändern, löschen, DB-Export). |
| **KI-Server (vLLM / Ollama / OpenAI)** | | |
| `AI_ENABLED` | `True` | KI-Texterkennung für Rechnungen aktivieren (`True`/`False`). |
| `AI_API_BASE` | `https://api.openai.com/v1` | URL des vLLM / Ollama / OpenAI API-Endpunkts (z. B. `http://localhost:8000/v1`). |
| `AI_MODEL` | `openai/gpt-oss-120b` | Modellbezeichnung (z. B. `llama3`, `mistral`, `gpt-4o-mini`). |
| `AI_API_KEY` | *(leer)* | API-Schlüssel, falls für den Endpunkt Authentifizierung erforderlich ist. |
| `AI_TIMEOUT` | `60` | Maximales Timeout für KI-Analysen in Sekunden. |
| **System & Updates** | | |
| `CHECK_FOR_UPDATES` | `True` | Automatische Prüfung auf GitHub-Releases und Docker-Builds (`True`/`False`). |

---

## 🏛️ Active Directory Anbindung

Der Lizenzmanager integriert sich nahtlos in bestehende Microsoft Active Directory Umgebungen:

1. **Anmeldung:** Mitarbeiter melden sich mit ihrem gewohnten Windows-Domänenkonto an (`vorname.nachname` oder `DOMÄNE\user`).
2. **Rechteverwaltung (RBAC):**
   - **Administratoren:** Mitglieder der in `LDAP_ADMIN_GROUP` definierten AD-Gruppe (Standard: `Lizenz-Admins`) sowie der lokale Administrator erhalten Schreibrechte (Lizenzen anlegen, bearbeiten, löschen, Backups laden).
   - **Normale Benutzer:** Alle anderen angemeldeten Mitarbeiter haben standardmäßig **Nur-Lese-Rechte** (Fail-Closed).
3. **Ausfallsicherheit:** Fällt der Domain Controller aus oder ist nicht erreichbar, kann sich der Administrator stets mit den lokalen Zugangsdaten aus der Ersteinrichtung anmelden.

---

## 🤖 KI-Rechnungsimport einrichten

Der Lizenzmanager kann mit jedem OpenAI-kompatiblen API-Endpunkt betrieben werden:

### Lokales vLLM / Ollama
- **Ollama:** `AI_API_BASE=http://localhost:11434/v1`, `AI_MODEL=llama3:8b`
- **vLLM:** `AI_API_BASE=http://localhost:8000/v1`, `AI_MODEL=openai/gpt-oss-120b`
- **LM Studio:** `AI_API_BASE=http://localhost:1234/v1`, `AI_MODEL=local-model`

### Cloud-Modelle (OpenAI)
- Tragen Sie in `.env` Ihren API-Key ein:
  ```env
  AI_API_BASE=https://api.openai.com/v1
  AI_MODEL=gpt-4o-mini
  AI_API_KEY=sk-proj-...
  ```

---

## 💾 Datensicherung & Persistenz

Alle Daten liegen in einer schlanken SQLite-Datenbank:
* **Pfad im Container:** `/app/data/licenses.db`
* **Pfad auf dem Host:** `./data/licenses.db`

### Backup erstellen
- **Über die Web-Oberfläche:** Navigieren Sie zu den Einstellungen und laden Sie das vollständige Datenbank-Backup mit einem Klick herunter (`/api/export/db` – nur für Administratoren).
- **Dateibasiert:** Kopieren Sie einfach den Ordner `./data/` an einen sicheren Ort.

---

## 📄 Lizenz

Dieses Projekt ist unter der **MIT-Lizenz** lizenziert – siehe die [LICENSE](LICENSE) Datei für Details.
