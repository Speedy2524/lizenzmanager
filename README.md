# 🔑 Lizenzmanager (Docker & GitHub Edition)

Ein modernes, benutzerfreundliches Web-Tool zur vollständigen Erfassung, Budgetüberwachung und Fristenkontrolle all deiner Software-Lizenzen, Verträge und Abonnements.

Inklusive **Active Directory / LDAP** Authentifizierung, **KI-Rechnungsextraktion** und vollständiger **Docker-Unterstützung**.

---

## 🚀 Schnellstart mit Docker

### Option 1: Mit Docker Compose (Empfohlen)

1. **Repository klonen:**
   ```bash
   git clone https://github.com/Speedy2524/lizenzmanager.git
   cd lizenzmanager
   ```

2. **(Optional) Konfiguration anpassen:**
   Kopiere die Vorlage und passe bei Bedarf AD/LDAP- oder KI-Einstellungen an:
   ```bash
   cp .env.example .env
   ```

3. **Container starten:**
   ```bash
   docker compose up -d
   ```

4. **Im Browser öffnen:**
   👉 **[http://localhost:5000](http://localhost:5000)**

---

### Option 2: Direkt als fertiges Image ziehen (über GitHub Packages / GHCR)

Sobald dieses Repository auf GitHub liegt, baut die integrierte **GitHub Action** automatisch ein fertiges Docker-Image.

Jeder kann den Container dann ohne manuelles Bauen einfach herunterladen und starten:

```bash
# 1. Datenordner für Persistenz anlegen
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

## 💾 Datensicherung & Persistenz

Alle Lizenzen, Verträge und Einstellungen werden in einer **SQLite-Datenbank** im Ordner `./data` auf dem Host-System gespeichert (`./data/licenses.db`).

* **Datensicherheit:** Container können jederzeit aktualisiert, gestoppt oder neu erstellt werden (`docker compose down && docker compose pull && docker compose up -d`), ohne dass Daten verloren gehen.
* **Backup:** Es genügt, die Datei `data/licenses.db` zu sichern.

---

## ⚙️ Konfiguration (.env)

Die wichtigsten Umgebungsvariablen (siehe auch `.env.example`):

| Variable | Standardwert | Beschreibung |
|---|---|---|
| `AUTH_ENABLED` | `True` | Active Directory Anmeldung aktivieren (`True`/`False`) |
| `ALLOW_DEMO_FALLBACK` | `True` | Fallback-Login (`admin`/`admin`), falls kein DC erreichbar ist |
| `LDAP_HOST` | `dc01.firma.local` | IP oder DNS deines Active Directory Domain Controllers |
| `LDAP_PORT` | `389` | LDAP-Port (389 für LDAP, 636 für LDAPS) |
| `LDAP_DOMAIN` | `FIRMA.LOCAL` | Domänenname |
| `LDAP_ADMIN_GROUP` | `Lizenz-Admins` | AD-Gruppe mit vollen Rechten |
| `AI_ENABLED` | `True` | KI-Texterkennung für Rechnungen aktivieren |
| `AI_API_BASE` | `https://************/v1` | URL des vLLM / OpenAI API-Endpunkts |
| `AI_MODEL` | `openai/gpt-oss-120b` | Modellname des KI-Servers |

---

