import os
import ast
import calendar
import json
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
import config

logger = logging.getLogger(__name__)

# Erlaubte Kategorien im Lizenzmanager
VALID_CATEGORIES = [
    'Office & Produktivität',
    'Design & Kreativität',
    'Entwicklung & Tools',
    'Sicherheit & Antivirus',
    'Cloud & Hosting',
    'Betriebssysteme',
    'Finanzen & ERP',
    'Kommunikation',
    'Sonstiges'
]

VALID_LICENSE_TYPES = ['subscription', 'perpetual', 'perpetual_maintenance', 'free']

VALID_BILLING_CYCLES = [
    'monthly',
    'quarterly',
    'semi_annually',
    'yearly',
    'two_yearly',
    'three_yearly',
    'custom',
    'once'
]

CYCLE_MONTH_MAP = {
    'monthly': 1,
    'quarterly': 3,
    'semi_annually': 6,
    'yearly': 12,
    'two_yearly': 24,
    'three_yearly': 36,
    'once': 12,
}

CURRENT_ACTIVE_MODEL = None


def _create_ssl_context():
    """Erstellt einen sicheren SSL-Kontext mit optionalem Firmen-/Schul-CA-Zertifikat."""
    ca_bundle = getattr(config, 'SSL_CERT_PATH', None)
    if ca_bundle and os.path.isfile(ca_bundle):
        return ssl.create_default_context(cafile=ca_bundle)
    return ssl.create_default_context()


def check_ai_status():
    """Prüft die Verbindung zum vLLM KI-Server und gibt Modell-Informationen zurück."""
    global CURRENT_ACTIVE_MODEL
    if not getattr(config, 'AI_ENABLED', True):
        return {
            'enabled': False,
            'connected': False,
            'message': 'KI-Assistent ist in der Konfiguration deaktiviert (AI_ENABLED=False).'
        }

    api_base = getattr(config, 'AI_API_BASE', 'http://localhost:8000/v1').rstrip('/')
    url = f"{api_base}/models"
    api_key = getattr(config, 'AI_API_KEY', '')
    timeout = min(3, getattr(config, 'AI_TIMEOUT', 30))

    if 'api.openai.com' in api_base and not api_key:
        return {
            'enabled': True,
            'connected': False,
            'api_base': api_base,
            'message': 'OpenAI API-Key fehlt (AI_API_KEY nicht gesetzt).'
        }

    headers = {
        'User-Agent': 'Lizenzmanager/1.0',
        'Accept': 'application/json'
    }
    if api_key:
        headers['Authorization'] = f'Bearer {api_key}'

    try:
        req = urllib.request.Request(url, headers=headers, method='GET')
        ctx = _create_ssl_context()
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            models = [m.get('id') for m in data.get('data', []) if m.get('id')]
            configured_model = getattr(config, 'AI_MODEL', 'openai/gpt-oss-120b')
            active_model = configured_model if configured_model in models else (models[0] if models else configured_model)
            CURRENT_ACTIVE_MODEL = active_model
            return {
                'enabled': True,
                'connected': True,
                'api_base': api_base,
                'models': models,
                'active_model': active_model,
                'message': f'Verbunden mit {api_base} (Modell: {active_model})'
            }
    except Exception as e:
        logger.warning(f"Fehler bei KI-Statusprüfung: {e}")
        return {
            'enabled': True,
            'connected': False,
            'api_base': api_base,
            'error': str(e),
            'message': f'Verbindung zum KI-Server nicht möglich: {e}'
        }


def _get_system_prompt():
    return """Du bist ein präziser Datenextraktions-Assistent für ein professionelles Lizenzmanagement-System.
Deine Aufgabe ist es, aus vorgelegtem Rechnungstext, E-Mails, Lizenzbestätigungen oder Verträgen alle relevanten Daten für eine neue Lizenz strukturiert zu extrahieren.

WICHTIGSTE REGELN ZUM FORMAT:
1. Antworte AUSSCHLIESSLICH mit einem validen JSON-Objekt (RFC 8259 konform).
2. Kein Text vor oder nach dem JSON.
3. Verwende KEINE doppelten Anführungszeichen innerhalb von Zeichenketten (Textfeldern wie notes oder name), es sei denn sie sind mit Backslash maskiert (\"). Verwende stattdessen bevorzugt einfache Anführungszeichen ('...').
4. Keine Trailing Commas vor schließenden geschweiften Klammern.

Felder im JSON:
- name: (String, Pflichtfeld) Exakter Software-, Produkt- oder Servicename (z. B. "Adobe Creative Cloud All Apps", "Microsoft 365 Business Standard", "JetBrains All Products Pack").
- vendor: (String) Hersteller / Softwareanbieter (z. B. "Adobe", "Microsoft", "JetBrains", "Canva").
- category: (String) Genau eine der folgenden Optionen:
  ["Office & Produktivität", "Design & Kreativität", "Entwicklung & Tools", "Sicherheit & Antivirus", "Cloud & Hosting", "Betriebssysteme", "Finanzen & ERP", "Kommunikation", "Sonstiges"]
- license_type: (String) Genau eine der Optionen:
  "subscription" (Abo / regelmäßige Abrechnung), "perpetual" (Einmalkauf/Dauerlizenz), "perpetual_maintenance" (Dauerlizenz mit Wartung), "free" (Kostenlos)
- billing_cycle: (String) Genau eine der Optionen:
  "monthly" (1 Monat), "quarterly" (3 Monate), "semi_annually" (6 Monate), "yearly" (12 Monate), "two_yearly" (24 Monate), "three_yearly" (36 Monate), "custom" (benutzerdefiniert), "once" (einmalig)
- billing_cycle_months: (Integer) Monate der Abrechnung (z. B. 12 bei jährlich, 1 bei monatlich, 36 bei 3 Jahren).
- cost: (Float) Rechnungsbetrag / Kosten als Zahl (z. B. 149.50). Bevorzuge Netto-Betrag falls ausgewiesen, sonst Rechnungsgesamtbetrag. Keine Währungszeichen im cost-Feld.
- currency: (String) Währung: "EUR", "USD" oder "CHF" (Standard: "EUR").
- seats_total: (Integer) Gekaufte Plätze / Seats / Benutzerlizenzen (Standard: 1).
- seats_used: (Integer) Genutzte / zugewiesene Plätze (Standard: seats_total oder 1).
- purchase_date: (String oder null) Kaufdatum / Rechnungsdatum / Beginn im Format "YYYY-MM-DD".
- expiration_date: (String oder null) Ablaufdatum / nächste Vertragsverlängerung im Format "YYYY-MM-DD". Wenn nicht explizit genannt, aber Kaufdatum und Zyklus bekannt sind, berechne das Enddatum.
- notice_period_days: (Integer) Kündigungsfrist in Tagen (Standard: 30 falls nicht im Text angegeben).
- auto_renewal: (Integer 1 oder 0) 1 wenn sich Vertrag automatisch verlängert oder typisches SaaS-Abo ist (Standard für Abos: 1), 0 bei Einmalkauf, Dauerlizenz oder wenn Vertrag explizit ausläuft.
- invoice_number: (String oder null) Rechnungsnummer, Belegnummer oder Bestellnummer.
- license_key: (String oder null) Seriennummer, Aktivierungscode oder Lizenzschlüssel falls im Text vorhanden.
- assigned_to: (String oder null) Mitarbeiter, Abteilung, Team oder Kostenstelle falls erwähnt.
- login_portal_url: (String oder null) Webadresse zum Kunden- oder Lizenzportal falls genannt.
- notes: (String) Relevante Notizen zur Rechnung (z. B. Rechnungsdetails, Zahlungsart, Konditionen).
"""


def _clean_json_string(s: str) -> str:
    """Bereinigt Markdown-Blöcke und schneidet das JSON heraus."""
    s = s.strip()
    if '```json' in s:
        s = s.split('```json', 1)[1].split('```', 1)[0].strip()
    elif '```' in s:
        s = s.split('```', 1)[1].split('```', 1)[0].strip()

    start = s.find('{')
    end = s.rfind('}')
    if start != -1 and end != -1 and end > start:
        s = s[start:end+1]
    return s


def _regex_field_extract(text: str) -> dict:
    """
    Extrahier-Fallback: Parst die bekannten Felder per Regex direkt aus dem Text,
    selbst wenn das JSON schwerwiegende Syntaxfehler hat.
    """
    fields = [
        'name', 'vendor', 'category', 'license_type', 'billing_cycle',
        'billing_cycle_months', 'cost', 'currency', 'seats_total', 'seats_used',
        'purchase_date', 'expiration_date', 'notice_period_days', 'auto_renewal',
        'invoice_number', 'license_key', 'assigned_to', 'login_portal_url', 'notes'
    ]
    data = {}
    for f in fields:
        pat = rf'["\']?{f}["\']?\s*:\s*([^,\n}}\]]+)'
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            elif val.lower() == 'null':
                val = None
            elif val.lower() in ('true', '1'):
                val = 1
            elif val.lower() in ('false', '0'):
                val = 0
            data[f] = val
    return data


def _fix_unescaped_quotes_in_json(text: str) -> str:
    """
    Repariert unmaskierte Anführungszeichen innerhalb von Werten,
    z. B. "notes": "Rechnung für "Projekt 1" bezahlt".
    """
    lines = text.split('\n')
    fixed_lines = []
    for line in lines:
        # Prüfe ob Zeile ein "key": "value" Muster hat
        m = re.match(r'^(\s*"[a-zA-Z0-9_]+"\s*:\s*")(.*)("\s*,?\s*)$', line)
        if m:
            prefix, inner, suffix = m.groups()
            # Wenn im inneren Teil unmaskierte Anführungszeichen vorkommen
            # maskieren wir sie oder ersetzen sie durch Hochkommas
            inner_fixed = re.sub(r'(?<!\\)"', "'", inner)
            fixed_lines.append(f"{prefix}{inner_fixed}{suffix}")
        else:
            fixed_lines.append(line)
    return '\n'.join(fixed_lines)


def _robust_parse_json(content: str) -> dict:
    """
    Parst JSON mehrstufig mit automatischer Fehlerkorrektur bei LLM-Syntaxproblemen.
    """
    cleaned = _clean_json_string(content)

    # 1. Normales json.loads
    try:
        return json.loads(cleaned)
    except Exception:
        pass

    # 2. Bereinigung gängiger LLM-Fehler (Kommentare, Trailing Commas, Python-Konstanten)
    attempt = re.sub(r'//[^\n]*', '', cleaned)
    attempt = re.sub(r'/\*.*?\*/', '', attempt, flags=re.DOTALL)
    attempt = re.sub(r',\s*([\}\]])', r'\1', attempt)
    attempt = re.sub(r'\bNone\b', 'null', attempt)
    attempt = re.sub(r'\bTrue\b', 'true', attempt)
    attempt = re.sub(r'\bFalse\b', 'false', attempt)

    try:
        return json.loads(attempt)
    except Exception:
        pass

    # 3. Reparatur von unmaskierten Anführungszeichen in Strings
    try:
        fixed_quotes = _fix_unescaped_quotes_in_json(attempt)
        return json.loads(fixed_quotes)
    except Exception:
        pass

    # 4. Versuch mit ast.literal_eval (falls Modell Python-Dict-Syntax oder Single-Quotes nutzte)
    try:
        parsed = ast.literal_eval(attempt)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # 5. Regex-Fallback: Felder direkt auslesen
    fallback = _regex_field_extract(cleaned)
    if fallback and any(k in fallback for k in ('name', 'cost', 'vendor', 'invoice_number', 'billing_cycle')):
        logger.info(f"JSON-Fallback-Extraktion erfolgreich für {len(fallback)} Felder.")
        return fallback

    logger.error(f"Konnte Antwort der KI nicht als JSON interpretieren: {content}")
    raise RuntimeError(f"Konnte Antwort der KI nicht als JSON interpretieren: {content[:150]}...")


def _sanitize_extracted_data(data: dict) -> dict:
    """Überprüft und bereinigt die vom LLM gelieferten Daten für die Datenbank."""
    if not isinstance(data, dict):
        data = {}

    # Name
    name = str(data.get('name') or '').strip()
    if not name or name.lower() in ('null', 'none'):
        name = "Unbenannte Lizenz (aus Beleg)"

    # Vendor
    vendor = str(data.get('vendor') or '').strip()
    if vendor.lower() in ('null', 'none'):
        vendor = ''

    # Category
    category = data.get('category')
    if category not in VALID_CATEGORIES:
        category = 'Sonstiges'

    # License Type
    license_type = str(data.get('license_type') or 'subscription').lower().strip()
    if license_type not in VALID_LICENSE_TYPES:
        if 'perpetual' in license_type or 'dauer' in license_type or 'einmal' in license_type:
            license_type = 'perpetual'
        elif 'free' in license_type or 'kostenlos' in license_type:
            license_type = 'free'
        else:
            license_type = 'subscription'

    # Billing Cycle
    billing_cycle = str(data.get('billing_cycle') or 'yearly').lower().strip()
    if billing_cycle not in VALID_BILLING_CYCLES:
        if 'year' in billing_cycle or 'jahr' in billing_cycle or 'annual' in billing_cycle:
            billing_cycle = 'yearly'
        elif 'month' in billing_cycle or 'monat' in billing_cycle:
            billing_cycle = 'monthly'
        elif 'quart' in billing_cycle:
            billing_cycle = 'quarterly'
        elif 'halb' in billing_cycle or 'semi' in billing_cycle:
            billing_cycle = 'semi_annually'
        elif '2' in billing_cycle:
            billing_cycle = 'two_yearly'
        elif '3' in billing_cycle:
            billing_cycle = 'three_yearly'
        elif 'once' in billing_cycle or 'einmal' in billing_cycle:
            billing_cycle = 'once'
        else:
            billing_cycle = 'yearly'

    # Billing Cycle Months
    try:
        cycle_months = int(data.get('billing_cycle_months') or CYCLE_MONTH_MAP.get(billing_cycle, 12))
        if cycle_months < 1:
            cycle_months = CYCLE_MONTH_MAP.get(billing_cycle, 12)
    except (ValueError, TypeError):
        cycle_months = CYCLE_MONTH_MAP.get(billing_cycle, 12)

    # Cost
    cost_val = data.get('cost')
    try:
        if cost_val is None:
            cost = 0.0
        else:
            cost = round(float(str(cost_val).replace(',', '.').strip()), 2)
            if cost < 0:
                cost = 0.0
    except (ValueError, TypeError):
        cost = 0.0

    # Currency
    currency = str(data.get('currency') or 'EUR').upper().strip()
    if currency not in ('EUR', 'USD', 'CHF'):
        currency = 'EUR'

    # Seats
    try:
        seats_total = max(1, int(data.get('seats_total') or 1))
    except (ValueError, TypeError):
        seats_total = 1

    try:
        seats_used = max(0, int(data.get('seats_used') or seats_total))
    except (ValueError, TypeError):
        seats_used = seats_total

    # Dates
    def _clean_date(d_val):
        if not d_val or str(d_val).lower() in ('null', 'none'):
            return None
        d_str = str(d_val).strip()
        m = re.search(r'(\d{4})-(\d{2})-(\d{2})', d_str)
        if m:
            return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
        m2 = re.search(r'(\d{1,2})\.(\d{1,2})\.(\d{4})', d_str)
        if m2:
            return f"{m2.group(3)}-{int(m2.group(2)):02d}-{int(m2.group(1)):02d}"
        return None

    purchase_date = _clean_date(data.get('purchase_date'))
    expiration_date = _clean_date(data.get('expiration_date'))

    # Notice Period
    try:
        notice_period_days = max(0, int(data.get('notice_period_days') if data.get('notice_period_days') is not None else 30))
    except (ValueError, TypeError):
        notice_period_days = 30

    # Auto Renewal
    if license_type in ('perpetual', 'free'):
        auto_renewal = 0
    else:
        ar_raw = data.get('auto_renewal')
        if ar_raw is None or str(ar_raw).lower() in ('null', 'none'):
            auto_renewal = 1
        elif str(ar_raw).strip().lower() in ('0', 'false', 'nein', 'no'):
            auto_renewal = 0
        else:
            auto_renewal = 1

    def _clean_str_field(val):
        if val is None or str(val).lower() in ('null', 'none'):
            return ''
        return str(val).strip()

    return {
        'name': name,
        'vendor': vendor,
        'category': category,
        'license_type': license_type,
        'billing_cycle': billing_cycle,
        'billing_cycle_months': cycle_months,
        'cost': cost,
        'currency': currency,
        'seats_total': seats_total,
        'seats_used': seats_used,
        'purchase_date': purchase_date or '',
        'expiration_date': expiration_date or '',
        'notice_period_days': notice_period_days,
        'auto_renewal': auto_renewal,
        'status': 'active',
        'invoice_number': _clean_str_field(data.get('invoice_number')),
        'license_key': _clean_str_field(data.get('license_key')),
        'assigned_to': _clean_str_field(data.get('assigned_to')),
        'login_portal_url': _clean_str_field(data.get('login_portal_url')),
        'notes': _clean_str_field(data.get('notes')),
    }


def _heuristic_extract_invoice(raw_text: str) -> dict:
    """
    Offline-/Schnellerkennungs-Fallback:
    Liest typische Rechnungsdaten (Software, Anbieter, Beträge, Rechnungsnummer,
    Abrechnungszyklus, Daten) regelbasiert aus, falls kein KI-Server verfügbar ist.
    """
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

    extracted = {
        'name': '',
        'vendor': '',
        'category': 'Sonstiges',
        'license_type': 'subscription',
        'billing_cycle': 'yearly',
        'billing_cycle_months': 12,
        'cost': 0.0,
        'currency': 'EUR',
        'seats_total': 1,
        'seats_used': 1,
        'purchase_date': None,
        'expiration_date': None,
        'notice_period_days': 30,
        'auto_renewal': 1,
        'invoice_number': '',
        'license_key': '',
        'assigned_to': '',
        'login_portal_url': '',
        'notes': f"Automatisch per Schnellerkennung erfasst ({datetime.now().strftime('%d.%m.%Y')})"
    }

    KNOWN_SOFTWARE = [
        ('Microsoft 365 Business Standard', 'Microsoft', 'Office & Produktivität'),
        ('Microsoft 365 Business Basic', 'Microsoft', 'Office & Produktivität'),
        ('Microsoft 365 Business Premium', 'Microsoft', 'Office & Produktivität'),
        ('Microsoft 365', 'Microsoft', 'Office & Produktivität'),
        ('Office 365', 'Microsoft', 'Office & Produktivität'),
        ('Windows Server', 'Microsoft', 'Betriebssysteme'),
        ('Adobe Creative Cloud Alle Applikationen', 'Adobe Inc.', 'Design & Kreativität'),
        ('Adobe Creative Cloud', 'Adobe Inc.', 'Design & Kreativität'),
        ('Adobe Photoshop', 'Adobe Inc.', 'Design & Kreativität'),
        ('Adobe Acrobat Pro', 'Adobe Inc.', 'Office & Produktivität'),
        ('Adobe Illustrator', 'Adobe Inc.', 'Design & Kreativität'),
        ('IntelliJ IDEA Ultimate', 'JetBrains s.r.o.', 'Entwicklung & Tools'),
        ('IntelliJ IDEA', 'JetBrains s.r.o.', 'Entwicklung & Tools'),
        ('PyCharm Professional', 'JetBrains s.r.o.', 'Entwicklung & Tools'),
        ('PyCharm', 'JetBrains s.r.o.', 'Entwicklung & Tools'),
        ('WebStorm', 'JetBrains s.r.o.', 'Entwicklung & Tools'),
        ('JetBrains All Products Pack', 'JetBrains s.r.o.', 'Entwicklung & Tools'),
        ('JetBrains', 'JetBrains s.r.o.', 'Entwicklung & Tools'),
        ('1Password Business', 'AgileBits / 1Password', 'Sicherheit & Antivirus'),
        ('1Password', 'AgileBits / 1Password', 'Sicherheit & Antivirus'),
        ('Bitdefender GravityZone', 'Bitdefender', 'Sicherheit & Antivirus'),
        ('Bitdefender', 'Bitdefender', 'Sicherheit & Antivirus'),
        ('Sophos Intercept X', 'Sophos', 'Sicherheit & Antivirus'),
        ('Hetzner', 'Hetzner Online GmbH', 'Cloud & Hosting'),
        ('AWS Cloud Services', 'Amazon Web Services', 'Cloud & Hosting'),
        ('Google Workspace', 'Google Cloud', 'Office & Produktivität'),
        ('Slack Pro', 'Salesforce / Slack', 'Kommunikation'),
        ('Slack Business', 'Salesforce / Slack', 'Kommunikation'),
        ('Slack', 'Salesforce / Slack', 'Kommunikation'),
        ('Zoom Pro', 'Zoom Video Communications', 'Kommunikation'),
        ('Zoom Business', 'Zoom Video Communications', 'Kommunikation'),
        ('Zoom', 'Zoom Video Communications', 'Kommunikation'),
        ('Figma Professional', 'Figma Inc.', 'Design & Kreativität'),
        ('Figma', 'Figma Inc.', 'Design & Kreativität'),
        ('Canva Pro', 'Canva Pty Ltd', 'Design & Kreativität'),
        ('GitHub Enterprise', 'GitHub Inc.', 'Entwicklung & Tools'),
        ('GitHub Team', 'GitHub Inc.', 'Entwicklung & Tools'),
        ('Docker Business', 'Docker Inc.', 'Entwicklung & Tools'),
        ('Docker Pro', 'Docker Inc.', 'Entwicklung & Tools'),
        ('GitLab Ultimate', 'GitLab Inc.', 'Entwicklung & Tools'),
        ('Atlassian Jira', 'Atlassian', 'Entwicklung & Tools'),
        ('Atlassian Confluence', 'Atlassian', 'Office & Produktivität'),
        ('Jira Software', 'Atlassian', 'Entwicklung & Tools'),
        ('Confluence', 'Atlassian', 'Office & Produktivität'),
        ('Lexware Buchhaltung Pro', 'Haufe-Lexware', 'Finanzen & ERP'),
        ('Lexware Buchhaltung', 'Haufe-Lexware', 'Finanzen & ERP'),
        ('Lexware', 'Haufe-Lexware', 'Finanzen & ERP'),
        ('DATEV', 'DATEV eG', 'Finanzen & ERP'),
        ('SAP Business One', 'SAP SE', 'Finanzen & ERP'),
        ('TeamViewer', 'TeamViewer SE', 'Entwicklung & Tools'),
        ('AnyDesk', 'AnyDesk Software GmbH', 'Entwicklung & Tools'),
        ('NordVPN Teams', 'Nord Security', 'Sicherheit & Antivirus'),
    ]

    for soft_name, vendor_name, cat in KNOWN_SOFTWARE:
        if re.search(r'\b' + re.escape(soft_name) + r'\b', raw_text, re.IGNORECASE):
            extracted['name'] = soft_name
            extracted['vendor'] = vendor_name
            extracted['category'] = cat
            break

    if not extracted['name']:
        for line in lines:
            m = re.match(r'^(?:Produkt|Software|Artikel|Position|Description|Item)\s*[:.\-]\s*(.+)$', line, re.IGNORECASE)
            if m:
                extracted['name'] = m.group(1).strip()
                break

    if not extracted['name']:
        for line in lines:
            if not re.search(r'^(?:rechnung|invoice|datum|date|seite|page|tel|fax|e-?mail|iban|bic|hrb|ust|tax)\b', line, re.IGNORECASE):
                if len(line) >= 3:
                    extracted['name'] = line[:80].strip()
                    break

    if not extracted['vendor']:
        for line in lines:
            m = re.match(r'^(?:Firma|Hersteller|Anbieter|Company|Vendor|Aussteller)\s*[:.\-]\s*(.+)$', line, re.IGNORECASE)
            if m:
                extracted['vendor'] = m.group(1).strip()
                break

    inv_match = re.search(r'(?:Rechnungs?(?:-|\s)?(?:Nr|Nummer|No)?|Invoice\s*(?:No|Number|#)?|Beleg(?:-|\s)?Nr)\s*[:.\-]?\s*([A-Za-z0-9\-_/]+)', raw_text, re.IGNORECASE)
    if inv_match:
        extracted['invoice_number'] = inv_match.group(1).strip()

    curr_match = re.search(r'\b(EUR|€|USD|\$|CHF)\b', raw_text)
    if curr_match:
        c_raw = curr_match.group(1)
        if c_raw in ('€', 'EUR'):
            extracted['currency'] = 'EUR'
        elif c_raw in ('$', 'USD'):
            extracted['currency'] = 'USD'
        elif c_raw == 'CHF':
            extracted['currency'] = 'CHF'

    cost_patterns = [
        r'(?:Netto(?:betrag)?|Gesamt(?:betrag)?|Endbetrag|Total|Summe|Zahlbetrag|Amount|Betrag)\s*[:.\-]?\s*(\d{1,3}(?:[.\s]\d{3})*,\d{2}|\d+[\.,]\d{2})',
        r'(\d{1,3}(?:[.\s]\d{3})*,\d{2}|\d+[\.,]\d{2})\s*(?:EUR|€|\$|CHF)',
        r'(?:EUR|€|\$|CHF)\s*(\d{1,3}(?:[.\s]\d{3})*,\d{2}|\d+[\.,]\d{2})'
    ]
    for pat in cost_patterns:
        m = re.search(pat, raw_text, re.IGNORECASE)
        if m:
            val_str = m.group(1).replace(' ', '').replace('.', '').replace(',', '.')
            try:
                val_flt = float(val_str)
                if val_flt > 0:
                    extracted['cost'] = round(val_flt, 2)
                    break
            except Exception:
                pass

    seats_match = re.search(r'(\d+)\s*(?:Benutzer|Lizenzen|Plätze|Plaetze|Seats|User|Accounts|Arbeitsplätze)', raw_text, re.IGNORECASE)
    if seats_match:
        try:
            s_val = int(seats_match.group(1))
            if s_val > 0:
                extracted['seats_total'] = s_val
                extracted['seats_used'] = s_val
        except Exception:
            pass

    all_dates = []
    for dm in re.finditer(r'\b(\d{1,2})\.(\d{1,2})\.(\d{4})\b', raw_text):
        try:
            d_obj = datetime(int(dm.group(3)), int(dm.group(2)), int(dm.group(1))).date()
            all_dates.append(d_obj)
        except Exception:
            pass
    for dm in re.finditer(r'\b(\d{4})-(\d{2})-(\d{2})\b', raw_text):
        try:
            d_obj = datetime(int(dm.group(1)), int(dm.group(2)), int(dm.group(3))).date()
            all_dates.append(d_obj)
        except Exception:
            pass

    if all_dates:
        all_dates.sort()
        today = datetime.now().date()
        past_dates = [d for d in all_dates if d <= today]
        future_dates = [d for d in all_dates if d > today]

        if past_dates:
            extracted['purchase_date'] = past_dates[-1].strftime('%Y-%m-%d')
        elif all_dates:
            extracted['purchase_date'] = all_dates[0].strftime('%Y-%m-%d')

        if future_dates:
            extracted['expiration_date'] = future_dates[0].strftime('%Y-%m-%d')
        elif len(all_dates) > 1:
            extracted['expiration_date'] = all_dates[-1].strftime('%Y-%m-%d')

    if re.search(r'\b(monatlich|per month|monthly|pro monat|/mo)\b', raw_text, re.IGNORECASE):
        extracted['billing_cycle'] = 'monthly'
        extracted['billing_cycle_months'] = 1
    elif re.search(r'\b(quartal|quarterly|vierteljährlich|alle 3 monate)\b', raw_text, re.IGNORECASE):
        extracted['billing_cycle'] = 'quarterly'
        extracted['billing_cycle_months'] = 3
    elif re.search(r'\b(halbjährlich|semi-annually|alle 6 monate)\b', raw_text, re.IGNORECASE):
        extracted['billing_cycle'] = 'semi_annually'
        extracted['billing_cycle_months'] = 6
    elif re.search(r'\b(2 jahre|2-jährlich|two years|24 monate)\b', raw_text, re.IGNORECASE):
        extracted['billing_cycle'] = 'two_yearly'
        extracted['billing_cycle_months'] = 24
    elif re.search(r'\b(3 jahre|3-jährlich|three years|36 monate)\b', raw_text, re.IGNORECASE):
        extracted['billing_cycle'] = 'three_yearly'
        extracted['billing_cycle_months'] = 36
    elif re.search(r'\b(einmalig|dauerlizenz|perpetual|onetime|einmalkauf)\b', raw_text, re.IGNORECASE):
        extracted['license_type'] = 'perpetual'
        extracted['billing_cycle'] = 'once'
        extracted['auto_renewal'] = 0
        extracted['billing_cycle_months'] = 12

    if extracted['purchase_date'] and not extracted['expiration_date'] and extracted['billing_cycle'] != 'once':
        try:
            p_date = datetime.strptime(extracted['purchase_date'], '%Y-%m-%d').date()
            m_add = extracted['billing_cycle_months']
            y = p_date.year + (p_date.month + m_add - 1) // 12
            m = (p_date.month + m_add - 1) % 12 + 1
            max_d = calendar.monthrange(y, m)[1]
            extracted['expiration_date'] = datetime(y, m, min(p_date.day, max_d)).strftime('%Y-%m-%d')
        except Exception:
            pass

    key_match = re.search(r'(?:Lizenzschlüssel|Lizenz-Key|Lizenzkey|License\s*Key|Seriennummer|Serial(?:\s*Number)?|Product\s*Key)\s*[:.\-]?\s*([A-Za-z0-9\-_]+)', raw_text, re.IGNORECASE)
    if key_match:
        extracted['license_key'] = key_match.group(1).strip()
    else:
        key_match2 = re.search(r'\b([A-Z0-9]{2,8}(?:-[A-Z0-9]{2,8}){2,})\b', raw_text)
        if key_match2:
            extracted['license_key'] = key_match2.group(1)

    url_match = re.search(r'https?://(?:admin|portal|account|login|manage)[^\s"\'>]+', raw_text, re.IGNORECASE)
    if url_match:
        extracted['login_portal_url'] = url_match.group(0).rstrip('.,;:')

    notice_match = re.search(r'(\d+)\s*(?:Tage[n]?\s*Kündigungsfrist|Tage[n]?\s*vor\s*(?:Ablauf|Verlängerung))', raw_text, re.IGNORECASE)
    if notice_match:
        try:
            extracted['notice_period_days'] = int(notice_match.group(1))
        except Exception:
            pass

    return extracted


def parse_invoice_text(raw_text: str):
    """
    Sendet den Rechnungs-/Vertragstext an den vLLM KI-Server und gibt
    einen strukturierten Lizenzentwurf als Dictionary zurück.
    Fällt bei Verbindungsfehlern oder deaktivierter KI nahtlos auf
    die heuristische Schnellerkennung zurück.
    """
    global CURRENT_ACTIVE_MODEL
    if not raw_text or not raw_text.strip():
        raise ValueError("Es wurde kein Rechnungstext übermittelt.")

    # Prüfen ob KI generell deaktiviert ist
    if not getattr(config, 'AI_ENABLED', True):
        logger.info("KI deaktiviert - nutze heuristische Schnellerkennung.")
        fallback = _heuristic_extract_invoice(raw_text)
        return _sanitize_extracted_data(fallback)

    api_base = getattr(config, 'AI_API_BASE', 'http://localhost:8000/v1').rstrip('/')
    api_key = getattr(config, 'AI_API_KEY', '')

    # Wenn OpenAI API gewählt ist, aber kein Key existiert -> direkt Heuristik
    if 'api.openai.com' in api_base and not api_key:
        logger.info("OpenAI API-Key nicht gesetzt - nutze heuristische Schnellerkennung.")
        fallback = _heuristic_extract_invoice(raw_text)
        sanitized = _sanitize_extracted_data(fallback)
        sanitized['notes'] = (sanitized.get('notes', '') + " (Hinweis: Schnellerkennung genutzt, da kein OpenAI API-Key hinterlegt ist.)").strip()
        return sanitized

    url = f"{api_base}/chat/completions"
    configured_model = getattr(config, 'AI_MODEL', 'openai/gpt-oss-120b')
    model = CURRENT_ACTIVE_MODEL or configured_model
    timeout = getattr(config, 'AI_TIMEOUT', 60)

    system_prompt = _get_system_prompt()
    user_prompt = f"Hier sind die Rechnungsdaten / der Vertragstext zur Auswertung:\n\n{raw_text.strip()}"

    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Lizenzmanager/1.0',
        'Accept': 'application/json'
    }
    if api_key:
        headers['Authorization'] = f'Bearer {api_key}'

    ctx = _create_ssl_context()

    # Anfrage mit response_format = {'type': 'json_object'} für erzwungene JSON-Grammatik
    payload = {
        'model': model,
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_prompt}
        ],
        'response_format': {'type': 'json_object'},
        'temperature': 0.1,
        'max_tokens': 1500
    }

    resp_body = None
    try:
        data_bytes = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method='POST')
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            resp_body = json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        # Falls Server response_format nicht unterstützt, Fallback ohne response_format
        if e.code == 400 and 'response_format' in payload:
            logger.info("Server unterstützt response_format nicht, versuche ohne...")
            del payload['response_format']
            data_bytes = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=data_bytes, headers=headers, method='POST')
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                    resp_body = json.loads(resp.read().decode('utf-8'))
            except Exception as e2:
                logger.warning(f"KI HTTP-Fehler ({e2}) - Rückfall auf Heuristik.")
                fallback = _heuristic_extract_invoice(raw_text)
                sanitized = _sanitize_extracted_data(fallback)
                sanitized['notes'] = (sanitized.get('notes', '') + f" (Hinweis: Schnellerkennung genutzt; KI-Fehler: {e2})").strip()
                return sanitized
        else:
            err_msg = e.read().decode('utf-8', errors='replace')
            logger.warning(f"vLLM HTTP Fehler ({e.code}): {err_msg} - Rückfall auf Heuristik.")
            fallback = _heuristic_extract_invoice(raw_text)
            sanitized = _sanitize_extracted_data(fallback)
            sanitized['notes'] = (sanitized.get('notes', '') + f" (Hinweis: Schnellerkennung genutzt; KI antwortete mit Fehler {e.code})").strip()
            return sanitized
    except Exception as e:
        logger.warning(f"KI-Verbindungsfehler ({e}) - Rückfall auf heuristische Schnellerkennung.")
        fallback = _heuristic_extract_invoice(raw_text)
        sanitized = _sanitize_extracted_data(fallback)
        sanitized['notes'] = (sanitized.get('notes', '') + " (Hinweis: Schnellerkennung genutzt; KI-Server offline)").strip()
        return sanitized

    choices = resp_body.get('choices', [])
    if not choices:
        logger.warning("Keine Choices in KI-Antwort - Rückfall auf Heuristik.")
        fallback = _heuristic_extract_invoice(raw_text)
        return _sanitize_extracted_data(fallback)

    assistant_msg = choices[0].get('message', {})
    content = assistant_msg.get('content') or ''

    # Falls der Reasoning-Content in einem separaten Feld liegt und content leer war:
    if not content and assistant_msg.get('reasoning'):
        content = assistant_msg.get('reasoning')

    if not content.strip():
        logger.warning("Leere KI-Antwort - Rückfall auf Heuristik.")
        fallback = _heuristic_extract_invoice(raw_text)
        return _sanitize_extracted_data(fallback)

    # Mehrstufiges und fehlertolerantes JSON-Parsing
    try:
        parsed_json = _robust_parse_json(content)
        sanitized = _sanitize_extracted_data(parsed_json)
        return sanitized
    except Exception as e:
        logger.warning(f"Fehler beim Parsen der KI-Antwort ({e}) - Rückfall auf Heuristik.")
        fallback = _heuristic_extract_invoice(raw_text)
        sanitized = _sanitize_extracted_data(fallback)
        return sanitized
