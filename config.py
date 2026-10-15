import os

# ==============================================================================
# LIZENZMANAGER - KONFIGURATION (ACTIVE DIRECTORY / LDAP / .ENV)
# ==============================================================================
# Lädt Umgebungsvariablen automatisch aus einer vorhandenen .env-Datei.
def _load_env_file():
    env_candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'),
        os.path.join(os.getcwd(), '.env')
    ]
    for env_path in env_candidates:
        if os.path.isfile(env_path):
            try:
                with open(env_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#') or '=' not in line:
                            continue
                        k, v = line.split('=', 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k and k not in os.environ:
                            os.environ[k] = v
                break
            except Exception:
                pass

_load_env_file()

import secrets

# Geheimer Schlüssel für Flask-Sessions
_env_secret = os.environ.get('SECRET_KEY')
if not _env_secret or _env_secret == 'lizenzmanager-super-secret-key-change-in-production':
    if os.environ.get('FLASK_ENV') == 'production' or os.environ.get('ENV') == 'production':
        raise RuntimeError("CRITICAL: Die Umgebungsvariable SECRET_KEY muss im Produktivbetrieb gesetzt sein!")
    # Im Entwicklungs-/Standardmodus zufälligen 256-Bit Schlüssel generieren
    SECRET_KEY = secrets.token_hex(32)
else:
    SECRET_KEY = _env_secret

# Authentifizierung aktivieren (True = Anmeldeseite aktiv, False = ohne Login)
AUTH_ENABLED = os.environ.get('AUTH_ENABLED', 'True').lower() in ('true', '1', 'yes')

# IP-Adresse oder Hostname des Active Directory Domain Controllers
# Beispiel: 'dc01.firma.local' oder '192.168.1.10'
LDAP_HOST = os.environ.get('LDAP_HOST', 'dc01.firma.local')

# LDAP-Port: 389 für unverschlüsseltes LDAP / StartTLS, 636 für LDAPS (SSL)
LDAP_PORT = int(os.environ.get('LDAP_PORT', '389'))

# Verschlüsselung (SSL/TLS): True bei Port 636
LDAP_USE_SSL = os.environ.get('LDAP_USE_SSL', 'False').lower() in ('true', '1', 'yes')

# Windows-Domänenname (NetBIOS-Name oder DNS-Domäne)
# Beispiele: 'MEINEFIRMA' oder 'firma.local'
LDAP_DOMAIN = os.environ.get('LDAP_DOMAIN', 'FIRMA.LOCAL')

# Suchbasis (Base DN) für AD-Abfragen (Benutzerdetails, Gruppen)
# Beispiel: 'DC=firma,DC=local'
LDAP_SEARCH_BASE = os.environ.get('LDAP_SEARCH_BASE', 'DC=firma,DC=local')

# Optionale AD-Sicherheitsgruppe, in der ein Benutzer sein MUSS, um sich anzumelden.
# Leer lassen (''), falls sich JEDER gültige Domänen-Benutzer anmelden darf.
LDAP_REQUIRED_GROUP = os.environ.get('LDAP_REQUIRED_GROUP', '')

# Optionale AD-Sicherheitsgruppe für Administratoren.
# Mitglieder dieser Gruppe erhalten Admin-Rechte (Lizenzen bearbeiten, löschen, DB-Backup).
# Wenn leer (''), haben Benutzer standardmäßig NUR Leserechte (Fail-Closed).
LDAP_ADMIN_GROUP = os.environ.get('LDAP_ADMIN_GROUP', 'Lizenz-Admins')

# Lokaler Notfall- & Fallback-Modus (Standardmäßig DEAKTIVIERT):
# Nur bei Bedarf im Labor oder bei DC-Ausfall über .env aktivieren.
ALLOW_DEMO_FALLBACK = os.environ.get('ALLOW_DEMO_FALLBACK', 'False').lower() in ('true', '1', 'yes')
LOCAL_ADMIN_USER = os.environ.get('LOCAL_ADMIN_USER', 'admin')
LOCAL_ADMIN_PASSWORD = os.environ.get('LOCAL_ADMIN_PASSWORD', '')

# ==============================================================================
# KI-SERVER KONFIGURATION (vLLM / OPENAI-KOMPATIBEL)
# ==============================================================================
# Ermöglicht das automatische Auslesen von Rechnungstexten & Erstellen von Lizenzentwürfen
AI_ENABLED = os.environ.get('AI_ENABLED', 'True').lower() in ('true', '1', 'yes')
AI_API_BASE = os.environ.get('AI_API_BASE', 'https://api.openai.com/v1')
AI_MODEL = os.environ.get('AI_MODEL', 'openai/gpt-oss-120b')
AI_API_KEY = os.environ.get('AI_API_KEY', '')
AI_TIMEOUT = int(os.environ.get('AI_TIMEOUT', '60'))
