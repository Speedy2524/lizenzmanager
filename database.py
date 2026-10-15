import os
import sqlite3
import csv
import io
import calendar
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import config

DB_DIR = os.environ.get('DB_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data'))
DB_PATH = os.environ.get('DB_PATH', os.path.join(DB_DIR, 'licenses.db'))

def get_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 30000;")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                vendor TEXT,
                category TEXT DEFAULT 'Sonstiges',
                license_type TEXT DEFAULT 'subscription',
                license_key TEXT,
                seats_total INTEGER DEFAULT 1,
                seats_used INTEGER DEFAULT 1,
                purchase_date TEXT,
                expiration_date TEXT,
                notice_period_days INTEGER DEFAULT 30,
                auto_renewal INTEGER DEFAULT 1,
                cost REAL DEFAULT 0.0,
                billing_cycle TEXT DEFAULT 'yearly',
                billing_cycle_months INTEGER DEFAULT 12,
                currency TEXT DEFAULT 'EUR',
                invoice_number TEXT,
                assigned_to TEXT,
                login_portal_url TEXT,
                status TEXT DEFAULT 'active',
                notes TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        conn.commit()
        try:
            cursor.execute("ALTER TABLE licenses ADD COLUMN billing_cycle_months INTEGER DEFAULT 12")
            conn.commit()
        except Exception:
            pass

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS local_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                display_name TEXT,
                email TEXT,
                is_admin INTEGER DEFAULT 1,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        conn.commit()

        # Automatische Initialisierung, falls Kennwort über .env/Docker übergeben wurde
        init_pwd = getattr(config, 'INITIAL_ADMIN_PASSWORD', '')
        if init_pwd:
            cursor.execute("SELECT COUNT(*) FROM local_users WHERE is_admin = 1")
            if cursor.fetchone()[0] == 0:
                init_user = getattr(config, 'INITIAL_ADMIN_USER', 'admin') or 'admin'
                pwd_hash = generate_password_hash(init_pwd)
                now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute('''
                    INSERT INTO local_users (username, password_hash, display_name, email, is_admin, created_at, updated_at)
                    VALUES (?, ?, ?, ?, 1, ?, ?)
                ''', (init_user, pwd_hash, f"Administrator ({init_user})", f"{init_user.lower()}@localhost", now_str, now_str))
                conn.commit()
    finally:
        conn.close()

def has_local_admin():
    """Prüft, ob bereits mindestens ein lokales Administrator-Konto existiert."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM local_users WHERE is_admin = 1")
        row = cursor.fetchone()
        return bool(row and row[0] > 0)
    except sqlite3.OperationalError:
        return False
    finally:
        conn.close()

def create_local_admin(username, password, display_name=None, email=None):
    """Erstellt oder überschreibt das lokale Administrator-Konto mit sicherem Hash."""
    username = (username or '').strip()
    if not username:
        raise ValueError("Benutzername darf nicht leer sein.")
    if not password or len(password) < 6:
        raise ValueError("Das Kennwort muss mindestens 6 Zeichen lang sein.")

    password_hash = generate_password_hash(password)
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    display_name = (display_name or '').strip() or f"Administrator ({username})"
    email = (email or '').strip() or f"{username.lower()}@localhost"

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO local_users (username, password_hash, display_name, email, is_admin, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                password_hash = excluded.password_hash,
                display_name = excluded.display_name,
                email = excluded.email,
                is_admin = 1,
                updated_at = excluded.updated_at
        ''', (username, password_hash, display_name, email, now_str, now_str))
        conn.commit()
    finally:
        conn.close()

    return {
        'username': username,
        'display_name': display_name,
        'email': email,
        'is_admin': True
    }

def verify_local_user(username, password):
    """Prüft lokale Anmeldedaten gegen die PBKDF2-Hashes in der Datenbank."""
    if not username or not password:
        return None
    username = username.strip()
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM local_users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            return None
        row_dict = dict(row)
        if check_password_hash(row_dict.get('password_hash', ''), password):
            return {
                'username': row_dict['username'],
                'display_name': row_dict.get('display_name') or row_dict['username'],
                'email': row_dict.get('email') or f"{row_dict['username']}@localhost",
                'is_admin': bool(row_dict.get('is_admin', 0)),
                'auth_method': 'local_database'
            }
        return None
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()

def update_local_user_password(username, new_password):
    """Aktualisiert das Kennwort eines lokalen Benutzers."""
    if not new_password or len(new_password) < 6:
        raise ValueError("Das Kennwort muss mindestens 6 Zeichen lang sein.")
    password_hash = generate_password_hash(new_password)
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE local_users SET password_hash = ?, updated_at = ?
            WHERE username = ?
        ''', (password_hash, now_str, username.strip()))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()

def get_all_local_users():
    """Gibt alle lokalen Benutzerkonten zurück (ohne Passworthashes)."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, display_name, email, is_admin, created_at, updated_at FROM local_users ORDER BY username ASC")
        rows = cursor.fetchall()
        users = []
        for r in rows:
            u = dict(r)
            u['is_admin'] = bool(u.get('is_admin', 0))
            users.append(u)
        return users
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()

def get_local_user_by_id(user_id):
    """Gibt einen lokalen Benutzer anhand seiner ID zurück."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, display_name, email, is_admin, created_at, updated_at FROM local_users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        u = dict(row)
        u['is_admin'] = bool(u.get('is_admin', 0))
        return u
    finally:
        conn.close()

def add_local_user(username, password, display_name=None, email=None, is_admin=False):
    """Erstellt ein neues lokales Benutzerkonto (Admin oder Standard-Benutzer)."""
    username = (username or '').strip()
    if not username:
        raise ValueError("Benutzername darf nicht leer sein.")
    if not password or len(password) < 8:
        raise ValueError("Das Kennwort muss mindestens 8 Zeichen lang sein.")

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM local_users WHERE username = ?", (username,))
        if cursor.fetchone():
            raise ValueError(f"Ein Benutzer mit dem Namen '{username}' existiert bereits.")

        password_hash = generate_password_hash(password)
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        display_name = (display_name or '').strip() or username
        email = (email or '').strip() or f"{username.lower()}@local"

        cursor.execute('''
            INSERT INTO local_users (username, password_hash, display_name, email, is_admin, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, password_hash, display_name, email, 1 if is_admin else 0, now_str, now_str))
        conn.commit()
        new_id = cursor.lastrowid
    finally:
        conn.close()

    return get_local_user_by_id(new_id)

def update_local_user(user_id, display_name=None, email=None, is_admin=None, new_password=None):
    """Aktualisiert Profildaten, Rolle oder Kennwort eines lokalen Benutzers."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM local_users WHERE id = ?", (user_id,))
        existing = cursor.fetchone()
        if not existing:
            return None
        existing = dict(existing)

        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        target_is_admin = existing['is_admin']
        if is_admin is not None:
            target_is_admin = 1 if is_admin else 0
            if existing['is_admin'] == 1 and target_is_admin == 0:
                cursor.execute("SELECT COUNT(*) FROM local_users WHERE is_admin = 1 AND id != ?", (user_id,))
                other_admins = cursor.fetchone()[0]
                if other_admins == 0:
                    raise ValueError("Der letzte Administrator kann nicht zum Standard-Benutzer herabgestuft werden.")

        pwd_hash = existing['password_hash']
        if new_password:
            if len(new_password) < 8:
                raise ValueError("Das neue Kennwort muss mindestens 8 Zeichen lang sein.")
            pwd_hash = generate_password_hash(new_password)

        cursor.execute('''
            UPDATE local_users SET
                display_name = ?,
                email = ?,
                is_admin = ?,
                password_hash = ?,
                updated_at = ?
            WHERE id = ?
        ''', (
            (display_name if display_name is not None else existing['display_name']) or existing['username'],
            email if email is not None else existing['email'],
            target_is_admin,
            pwd_hash,
            now_str,
            user_id
        ))
        conn.commit()
    finally:
        conn.close()

    return get_local_user_by_id(user_id)

def delete_local_user(user_id, current_username=None):
    """Löscht ein lokales Benutzerkonto unter Wahrung von Schutzmechanismen."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM local_users WHERE id = ?", (user_id,))
        existing = cursor.fetchone()
        if not existing:
            return False
        existing = dict(existing)

        if current_username and existing['username'].lower() == current_username.lower():
            raise ValueError("Sie können Ihr eigenes aktuell angemeldetes Konto nicht löschen.")

        if existing['is_admin'] == 1:
            cursor.execute("SELECT COUNT(*) FROM local_users WHERE is_admin = 1 AND id != ?", (user_id,))
            other_admins = cursor.fetchone()[0]
            if other_admins == 0:
                raise ValueError("Der letzte verbleibende Administrator kann nicht gelöscht werden.")

        cursor.execute("DELETE FROM local_users WHERE id = ?", (user_id,))
        conn.commit()
        return True
    finally:
        conn.close()

def parse_date(d_str):
    if not d_str:
        return None
    try:
        return datetime.strptime(d_str.strip(), '%Y-%m-%d').date()
    except Exception:
        try:
            return datetime.strptime(d_str.strip(), '%d.%m.%Y').date()
        except Exception:
            return None

def format_date(d):
    if not d:
        return None
    return d.strftime('%Y-%m-%d')

def normalize_date_str(d_val):
    if not d_val:
        return None
    d = parse_date(str(d_val))
    return format_date(d) if d else None

def _safe_str(val, default=''):
    if val is None:
        return default
    return str(val).strip()

def _safe_int(val, default=0):
    if val is None:
        return default
    try:
        s = str(val).strip()
        if s == '':
            return default
        return int(float(s))
    except (ValueError, TypeError):
        return default

def _safe_float(val, default=0.0):
    if val is None:
        return default
    try:
        s = str(val).strip().replace(',', '.')
        if s == '':
            return default
        return float(s)
    except (ValueError, TypeError):
        return default

def get_cycle_months(cycle, custom_months=None):
    """Ermittelt die Anzahl der Monate für beliebige Standard- oder Custom-Zyklen."""
    if cycle == 'monthly': return 1
    if cycle == 'quarterly': return 3
    if cycle == 'semi_annually': return 6
    if cycle == 'yearly': return 12
    if cycle == 'two_yearly': return 24
    if cycle == 'three_yearly': return 36
    if cycle and cycle.startswith('custom_'):
        try:
            return int(cycle.split('_')[1])
        except Exception:
            return 12
    if cycle == 'custom' and custom_months is not None:
        val = _safe_int(custom_months, 12)
        return val if val > 0 else 12
    if custom_months is not None:
        val = _safe_int(custom_months, 12)
        if val > 0:
            return val
    return 12

def enrich_license(row_dict):
    """Fügt berechnete Fristen, Status-Ampeln und Kostenäquivalente hinzu."""
    today = date.today()
    exp_date = parse_date(row_dict.get('expiration_date'))
    purch_date = parse_date(row_dict.get('purchase_date'))
    notice_days = _safe_int(row_dict.get('notice_period_days'), 0)
    auto_renewal = bool(row_dict.get('auto_renewal', 1))
    status = row_dict.get('status', 'active')
    lic_type = row_dict.get('license_type', 'subscription')
    cost = _safe_float(row_dict.get('cost'), 0.0)
    cycle = row_dict.get('billing_cycle') or 'yearly'
    cycle_months = get_cycle_months(cycle, row_dict.get('billing_cycle_months'))
    row_dict['billing_cycle_months'] = cycle_months

    # Äquivalente Kosten berechnen (MRR und ARR)
    monthly_cost = 0.0
    yearly_cost = 0.0
    if status == 'active':
        if cycle == 'once':
            monthly_cost = 0.0
            yearly_cost = 0.0
        else:
            if cycle_months > 0:
                monthly_cost = cost / float(cycle_months)
                yearly_cost = (cost / float(cycle_months)) * 12.0
            else:
                monthly_cost = 0.0
                yearly_cost = 0.0

    row_dict['monthly_equivalent'] = round(monthly_cost, 2)
    row_dict['yearly_equivalent'] = round(yearly_cost, 2)

    # Fristen & Status
    cancellation_deadline = None
    days_until_expiration = None
    days_until_cancellation = None

    if exp_date:
        days_until_expiration = (exp_date - today).days
        if notice_days >= 0:
            cancellation_deadline = exp_date - timedelta(days=notice_days)
            days_until_cancellation = (cancellation_deadline - today).days

    row_dict['cancellation_deadline'] = format_date(cancellation_deadline)
    row_dict['days_until_expiration'] = days_until_expiration
    row_dict['days_until_cancellation'] = days_until_cancellation

    # Ampelsystem / Handlungsstatus
    badge_color = 'green'
    badge_label = 'Aktiv'
    urgency_level = 0 # 0=info/ok, 1=upcoming, 2=warning, 3=critical/urgent, 4=expired

    if status == 'cancelled':
        badge_color = 'gray'
        badge_label = 'Gekündigt'
        urgency_level = 0
    elif status == 'archived':
        badge_color = 'gray'
        badge_label = 'Archiviert'
        urgency_level = 0
    elif lic_type in ('perpetual', 'perpetual_maintenance') and not exp_date:
        badge_color = 'blue'
        badge_label = 'Dauerlizenz (Unbefristet)'
        urgency_level = 0
    elif lic_type == 'free':
        badge_color = 'blue'
        badge_label = 'Kostenlos'
        urgency_level = 0
    elif exp_date:
        if days_until_expiration < 0:
            badge_color = 'red'
            badge_label = f'Abgelaufen vor {abs(days_until_expiration)} Tagen'
            urgency_level = 4
        elif auto_renewal and days_until_cancellation is not None and days_until_cancellation < 0:
            badge_color = 'orange'
            badge_label = f'Kündigungsfrist verpasst (Verlängert sich automatisch)'
            urgency_level = 2
        elif auto_renewal and days_until_cancellation is not None and days_until_cancellation <= 30:
            badge_color = 'red' if days_until_cancellation <= 14 else 'orange'
            badge_label = f'Kündigungsfrist in {days_until_cancellation} Tagen!'
            urgency_level = 3 if days_until_cancellation <= 14 else 2
        elif not auto_renewal and days_until_expiration <= 30:
            badge_color = 'red' if days_until_expiration <= 14 else 'orange'
            badge_label = f'Endet in {days_until_expiration} Tagen'
            urgency_level = 3 if days_until_expiration <= 14 else 2
        elif days_until_expiration <= 30:
            badge_color = 'orange'
            badge_label = f'Verlängerung in {days_until_expiration} Tagen'
            urgency_level = 3 if days_until_expiration <= 14 else 2
        elif days_until_expiration <= 90:
            badge_color = 'yellow'
            badge_label = f'Fällig in {days_until_expiration} Tagen'
            urgency_level = 1
        else:
            badge_color = 'green'
            badge_label = f'Aktiv (Noch {days_until_expiration} Tage)'
            urgency_level = 0
    else:
        badge_color = 'green'
        badge_label = 'Aktiv'

    row_dict['badge_color'] = badge_color
    row_dict['badge_label'] = badge_label
    row_dict['urgency_level'] = urgency_level

    return row_dict

def get_all_licenses(search='', category='', status_filter='', sort_by='expiration_date', sort_order='asc'):
    conn = get_db()
    try:
        cursor = conn.cursor()
        query = 'SELECT * FROM licenses WHERE 1=1'
        params = []

        if search:
            search_pattern = f'%{search.strip()}%'
            query += ''' AND (
                name LIKE ? OR 
                vendor LIKE ? OR 
                license_key LIKE ? OR 
                assigned_to LIKE ? OR 
                notes LIKE ? OR 
                invoice_number LIKE ?
            )'''
            params.extend([search_pattern] * 6)

        if category and category != 'all':
            query += ' AND category = ?'
            params.append(category)

        if status_filter and status_filter != 'all':
            if status_filter in ('active', 'cancelled', 'archived'):
                query += ' AND status = ?'
                params.append(status_filter)

        cursor.execute(query, params)
        rows = cursor.fetchall()
    finally:
        conn.close()

    licenses = [enrich_license(dict(r)) for r in rows]

    # Spezifische Status-Filter im Memory (Ampelfilter)
    if status_filter == 'urgent': # <= 30 Tage oder Frist aktiv
        licenses = [l for l in licenses if l['urgency_level'] >= 2 and l['status'] == 'active']
    elif status_filter == 'upcoming': # 31-90 Tage
        licenses = [l for l in licenses if l['urgency_level'] == 1 and l['status'] == 'active']
    elif status_filter == 'expired':
        licenses = [l for l in licenses if l['urgency_level'] == 4 and l['status'] == 'active']
    elif status_filter == 'ok':
        licenses = [l for l in licenses if l['urgency_level'] == 0 and l['status'] == 'active']
    elif status_filter == 'perpetual':
        licenses = [l for l in licenses if l['license_type'] in ('perpetual', 'perpetual_maintenance')]

    # Sortierung
    reverse = (sort_order.lower() == 'desc')
    if sort_by == 'expiration_date':
        # Unbefristete ans Ende setzen wenn ASC
        def exp_sort_key(item):
            d = item.get('expiration_date')
            if not d:
                return '9999-99-99' if not reverse else '0000-00-00'
            return d
        licenses.sort(key=exp_sort_key, reverse=reverse)
    elif sort_by == 'cost':
        licenses.sort(key=lambda x: x.get('yearly_equivalent', 0), reverse=reverse)
    elif sort_by == 'name':
        licenses.sort(key=lambda x: (x.get('name') or '').lower(), reverse=reverse)
    elif sort_by == 'vendor':
        licenses.sort(key=lambda x: (x.get('vendor') or '').lower(), reverse=reverse)
    elif sort_by == 'urgency':
        # Höchste Dringlichkeit (4=abgelaufen, 3=dringend, 2=warnung) soll bei Standardsortierung oben stehen
        licenses.sort(key=lambda x: x.get('urgency_level', 0), reverse=(not reverse))

    return licenses

def get_license(license_id):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM licenses WHERE id = ?', (license_id,))
        row = cursor.fetchone()
    finally:
        conn.close()
    if row:
        return enrich_license(dict(row))
    return None

def add_license(data):
    conn = get_db()
    try:
        cursor = conn.cursor()
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        cycle = data.get('billing_cycle', 'yearly')
        cycle_months = get_cycle_months(cycle, data.get('billing_cycle_months'))

        notice_val = data.get('notice_period_days')
        notice_days = _safe_int(notice_val, default=30) if notice_val is not None and str(notice_val).strip() != '' else 30

        seats_tot = _safe_int(data.get('seats_total'), default=1)
        if seats_tot < 1:
            seats_tot = 1

        seats_u_val = data.get('seats_used')
        seats_used = _safe_int(seats_u_val, default=1) if seats_u_val is not None and str(seats_u_val).strip() != '' else 1

        cursor.execute('''
            INSERT INTO licenses (
                name, vendor, category, license_type, license_key,
                seats_total, seats_used, purchase_date, expiration_date,
                notice_period_days, auto_renewal, cost, billing_cycle,
                billing_cycle_months, currency, invoice_number, assigned_to,
                login_portal_url, status, notes, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            _safe_str(data.get('name')),
            _safe_str(data.get('vendor')),
            _safe_str(data.get('category'), 'Sonstiges') or 'Sonstiges',
            _safe_str(data.get('license_type'), 'subscription') or 'subscription',
            _safe_str(data.get('license_key')),
            seats_tot,
            seats_used,
            normalize_date_str(data.get('purchase_date')),
            normalize_date_str(data.get('expiration_date')),
            notice_days,
            1 if data.get('auto_renewal', 1) in (1, '1', True, 'true') else 0,
            _safe_float(data.get('cost'), 0.0),
            cycle,
            cycle_months,
            _safe_str(data.get('currency'), 'EUR') or 'EUR',
            _safe_str(data.get('invoice_number')),
            _safe_str(data.get('assigned_to')),
            _safe_str(data.get('login_portal_url')),
            _safe_str(data.get('status'), 'active') or 'active',
            _safe_str(data.get('notes')),
            now_str,
            now_str
        ))
        conn.commit()
        new_id = cursor.lastrowid
    finally:
        conn.close()
    return get_license(new_id)

def update_license(license_id, data):
    existing = get_license(license_id)
    if not existing:
        return None

    conn = get_db()
    try:
        cursor = conn.cursor()
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        cycle = data.get('billing_cycle') or existing.get('billing_cycle') or 'yearly'
        cycle_months = get_cycle_months(cycle, data.get('billing_cycle_months'))

        notice_val = data.get('notice_period_days')
        if notice_val is not None and str(notice_val).strip() != '':
            notice_days = _safe_int(notice_val, 30)
        else:
            notice_days = existing.get('notice_period_days', 30)

        seats_tot = _safe_int(data.get('seats_total'), default=existing.get('seats_total', 1))
        if seats_tot < 1:
            seats_tot = 1

        seats_u_val = data.get('seats_used')
        if seats_u_val is not None and str(seats_u_val).strip() != '':
            seats_used = _safe_int(seats_u_val, existing.get('seats_used', 1))
        else:
            seats_used = existing.get('seats_used', 1)

        status_val = data.get('status') or existing.get('status', 'active')

        name_val = _safe_str(data.get('name') if data.get('name') is not None else existing.get('name'))
        vendor_val = _safe_str(data.get('vendor') if 'vendor' in data else existing.get('vendor'))
        category_val = _safe_str(data.get('category') or existing.get('category'), 'Sonstiges')
        lic_type_val = _safe_str(data.get('license_type') or existing.get('license_type'), 'subscription')
        key_val = _safe_str(data.get('license_key') if 'license_key' in data else existing.get('license_key'))
        purch_val = normalize_date_str(data.get('purchase_date')) if 'purchase_date' in data else existing.get('purchase_date')
        exp_val = normalize_date_str(data.get('expiration_date')) if 'expiration_date' in data else existing.get('expiration_date')
        auto_ren = 1 if data.get('auto_renewal', existing.get('auto_renewal', 1)) in (1, '1', True, 'true') else 0
        cost_val = _safe_float(data.get('cost') if 'cost' in data else existing.get('cost', 0.0), 0.0)
        curr_val = _safe_str(data.get('currency') or existing.get('currency'), 'EUR')
        inv_val = _safe_str(data.get('invoice_number') if 'invoice_number' in data else existing.get('invoice_number'))
        assigned_val = _safe_str(data.get('assigned_to') if 'assigned_to' in data else existing.get('assigned_to'))
        portal_val = _safe_str(data.get('login_portal_url') if 'login_portal_url' in data else existing.get('login_portal_url'))
        notes_val = _safe_str(data.get('notes') if 'notes' in data else existing.get('notes'))

        cursor.execute('''
            UPDATE licenses SET
                name = ?, vendor = ?, category = ?, license_type = ?, license_key = ?,
                seats_total = ?, seats_used = ?, purchase_date = ?, expiration_date = ?,
                notice_period_days = ?, auto_renewal = ?, cost = ?, billing_cycle = ?,
                billing_cycle_months = ?, currency = ?, invoice_number = ?, assigned_to = ?,
                login_portal_url = ?, status = ?, notes = ?, updated_at = ?
            WHERE id = ?
        ''', (
            name_val,
            vendor_val,
            category_val,
            lic_type_val,
            key_val,
            seats_tot,
            seats_used,
            purch_val,
            exp_val,
            notice_days,
            auto_ren,
            cost_val,
            cycle,
            cycle_months,
            curr_val,
            inv_val,
            assigned_val,
            portal_val,
            status_val,
            notes_val,
            now_str,
            license_id
        ))
        conn.commit()
    finally:
        conn.close()
    return get_license(license_id)

def delete_license(license_id):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM licenses WHERE id = ?', (license_id,))
        conn.commit()
    finally:
        conn.close()
    return True

def renew_license(license_id, months=None):
    """Verlängert eine Lizenz automatisch um ihren Abrechnungszyklus (z.B. 12 oder 36 Monate)."""
    lic = get_license(license_id)
    if not lic or not lic.get('expiration_date'):
        return None

    current_exp = parse_date(lic['expiration_date'])
    today = date.today()

    base_date = current_exp if current_exp >= today else today

    if months is None or months <= 0:
        months = get_cycle_months(lic.get('billing_cycle', 'yearly'), lic.get('billing_cycle_months'))

    # Neues Datum berechnen
    year = base_date.year + (base_date.month + months - 1) // 12
    month = (base_date.month + months - 1) % 12 + 1
    max_days = calendar.monthrange(year, month)[1]
    day = min(base_date.day, max_days)
    new_exp = date(year, month, day)

    update_license(license_id, {
        **lic,
        'expiration_date': format_date(new_exp),
        'status': 'active'
    })
    return get_license(license_id)

def get_dashboard_stats():
    licenses = get_all_licenses()
    today = date.today()

    active_licenses = [l for l in licenses if l['status'] == 'active']
    
    total_mrr = sum(l['monthly_equivalent'] for l in active_licenses)
    total_arr = sum(l['yearly_equivalent'] for l in active_licenses)

    total_seats = sum(int(l.get('seats_total') or 0) for l in active_licenses)
    total_seats_used = sum(int(l.get('seats_used') or 0) for l in active_licenses)

    urgent_licenses = [l for l in active_licenses if l['urgency_level'] in (2, 3, 4)]
    upcoming_licenses = [l for l in active_licenses if l['urgency_level'] == 1]
    expired_licenses = [l for l in active_licenses if l['urgency_level'] == 4]

    # Kosten anstehend nächste 30 und 90 Tage
    cost_next_30 = 0.0
    cost_next_90 = 0.0
    for l in active_licenses:
        days_exp = l.get('days_until_expiration')
        cycle_m = l.get('billing_cycle_months') or 12
        lic_cost = float(l.get('cost') or 0.0)
        lic_cycle = l.get('billing_cycle')

        if lic_cycle == 'once':
            continue

        if days_exp is not None and 0 <= days_exp <= 30:
            cost_next_30 += lic_cost

        if days_exp is not None and 0 <= days_exp <= 90:
            if cycle_m == 1:
                occurrences = 1 + (90 - days_exp) // 30
                cost_next_90 += lic_cost * occurrences
            else:
                cost_next_90 += lic_cost

    # Kategorien-Verteilung
    cat_counts = {}
    cat_costs = {}
    for l in active_licenses:
        c = l.get('category') or 'Sonstiges'
        cat_counts[c] = cat_counts.get(c, 0) + 1
        cat_costs[c] = round(cat_costs.get(c, 0.0) + l['yearly_equivalent'], 2)

    # Hersteller-Verteilung
    vendor_costs = {}
    for l in active_licenses:
        v = l.get('vendor') or 'Unbekannt'
        vendor_costs[v] = round(vendor_costs.get(v, 0.0) + l['yearly_equivalent'], 2)

    # Top 5 teuerste
    top_expensive = sorted(active_licenses, key=lambda x: x['yearly_equivalent'], reverse=True)[:5]

    # Monatsverteilung der anstehenden Verlängerungskosten für die nächsten 12 Monate
    monthly_renewal_costs = [0.0] * 12
    month_labels = []
    for i in range(12):
        target_month_date = date(today.year + (today.month + i - 1) // 12, (today.month + i - 1) % 12 + 1, 1)
        month_labels.append(target_month_date.strftime('%b %Y'))

    for l in active_licenses:
        exp = parse_date(l.get('expiration_date'))
        cycle_m = l.get('billing_cycle_months') or 12
        lic_cost = float(l.get('cost') or 0.0)
        auto_ren = bool(l.get('auto_renewal'))
        if not exp or l.get('billing_cycle') == 'once':
            continue

        curr = exp
        while curr < today and auto_ren and cycle_m > 0:
            y = curr.year + (curr.month + cycle_m - 1) // 12
            m = (curr.month + cycle_m - 1) % 12 + 1
            max_d = calendar.monthrange(y, m)[1]
            curr = date(y, m, min(curr.day, max_d))

        while curr >= today:
            diff = (curr.year - today.year) * 12 + (curr.month - today.month)
            if 0 <= diff < 12:
                monthly_renewal_costs[diff] += lic_cost
            else:
                break
            if not auto_ren or cycle_m <= 0:
                break
            y = curr.year + (curr.month + cycle_m - 1) // 12
            m = (curr.month + cycle_m - 1) % 12 + 1
            max_d = calendar.monthrange(y, m)[1]
            curr = date(y, m, min(curr.day, max_d))

    return {
        'total_count': len(licenses),
        'active_count': len(active_licenses),
        'urgent_count': len(urgent_licenses),
        'upcoming_count': len(upcoming_licenses),
        'expired_count': len(expired_licenses),
        'total_seats': total_seats,
        'total_seats_used': total_seats_used,
        'total_mrr': round(total_mrr, 2),
        'total_arr': round(total_arr, 2),
        'cost_next_30': round(cost_next_30, 2),
        'cost_next_90': round(cost_next_90, 2),
        'categories': cat_counts,
        'category_costs': cat_costs,
        'vendor_costs': vendor_costs,
        'top_expensive': top_expensive,
        'urgent_licenses': urgent_licenses,
        'monthly_renewal_forecast': {
            'labels': month_labels,
            'costs': [round(c, 2) for c in monthly_renewal_costs]
        }
    }

def get_calendar_data(year=None):
    """Liefert alle Ereignisse (Verlängerungen & Kündigungsstichtage) gruppiert für das gesamte Jahr."""
    if year is None:
        year = date.today().year

    licenses = get_all_licenses()
    
    months_data = {m: {'month_num': m, 'renewals': [], 'cancellations': [], 'total_renewal_cost': 0.0} for m in range(1, 13)}
    events = []

    for l in licenses:
        if l['status'] in ('cancelled', 'archived'):
            continue

        exp = parse_date(l.get('expiration_date'))
        if not exp or l.get('billing_cycle') == 'once':
            continue

        cycle_m = l.get('billing_cycle_months') or 12
        auto_ren = bool(l.get('auto_renewal'))
        notice_days = int(l.get('notice_period_days') or 0)
        lic_cost = float(l.get('cost') or 0.0)

        curr_exp = exp
        if auto_ren and cycle_m > 0:
            while curr_exp.year < year:
                y = curr_exp.year + (curr_exp.month + cycle_m - 1) // 12
                m = (curr_exp.month + cycle_m - 1) % 12 + 1
                max_d = calendar.monthrange(y, m)[1]
                curr_exp = date(y, m, min(curr_exp.day, max_d))

        while curr_exp.year <= year:
            if curr_exp.year == year:
                event = {
                    'id': l['id'],
                    'name': l['name'],
                    'vendor': l.get('vendor') or '',
                    'date': format_date(curr_exp),
                    'day': curr_exp.day,
                    'month': curr_exp.month,
                    'year': curr_exp.year,
                    'type': 'renewal',
                    'title': f'Verlängerung: {l["name"]}',
                    'cost': lic_cost,
                    'currency': l.get('currency', 'EUR'),
                    'auto_renewal': 1 if auto_ren else 0,
                    'badge_color': l.get('badge_color', 'yellow')
                }
                months_data[curr_exp.month]['renewals'].append(event)
                months_data[curr_exp.month]['total_renewal_cost'] += lic_cost
                events.append(event)

                if auto_ren and notice_days > 0:
                    cand = curr_exp - timedelta(days=notice_days)
                    if cand.year == year:
                        cand_event = {
                            'id': l['id'],
                            'name': l['name'],
                            'vendor': l.get('vendor') or '',
                            'date': format_date(cand),
                            'day': cand.day,
                            'month': cand.month,
                            'year': cand.year,
                            'type': 'cancellation_deadline',
                            'title': f'Kündigungsfrist: {l["name"]}',
                            'cost': lic_cost,
                            'currency': l.get('currency', 'EUR'),
                            'notice_days': notice_days,
                            'badge_color': 'red'
                        }
                        months_data[cand.month]['cancellations'].append(cand_event)
                        events.append(cand_event)

            if not auto_ren or cycle_m <= 0:
                break

            y = curr_exp.year + (curr_exp.month + cycle_m - 1) // 12
            m = (curr_exp.month + cycle_m - 1) % 12 + 1
            max_d = calendar.monthrange(y, m)[1]
            curr_exp = date(y, m, min(curr_exp.day, max_d))

    for m in range(1, 13):
        months_data[m]['total_renewal_cost'] = round(months_data[m]['total_renewal_cost'], 2)

    return {
        'year': year,
        'months': months_data,
        'events': events
    }

def sanitize_csv_cell(val):
    """Verhindert CSV Formula Injection (DDE) in Tabellenkalkulationen (Excel, LibreOffice)."""
    if val is None:
        return ''
    s = str(val)
    if s.startswith(('=', '+', '-', '@', '\t', '\r')):
        return f"'{s}"
    return s

def export_csv_data():
    """Erzeugt CSV-String mit UTF-8-BOM für Excel-Kompatibilität."""
    licenses = get_all_licenses()
    output = io.StringIO()
    # UTF-8 BOM
    output.write('\ufeff')

    fieldnames = [
        'ID', 'Software', 'Hersteller', 'Kategorie', 'Lizenztyp',
        'Lizenzschluessel', 'Plaetze_Gesamt', 'Plaetze_Genutzt',
        'Kaufdatum', 'Gueltig_Bis', 'Kuendigungsfrist_Tage', 'Kuendigungsstichtag',
        'Auto_Verlaengerung', 'Kosten', 'Abrechnungsintervall', 'Abrechnungsmonate', 'Waehrung',
        'Jaehrliche_Kosten_EUR', 'Rechnungsnummer', 'Zugewiesen_An',
        'Status', 'Portal_URL', 'Notizen'
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames, delimiter=';')
    writer.writeheader()

    for l in licenses:
        writer.writerow({
            'ID': l.get('id'),
            'Software': sanitize_csv_cell(l.get('name', '')),
            'Hersteller': sanitize_csv_cell(l.get('vendor', '')),
            'Kategorie': sanitize_csv_cell(l.get('category', '')),
            'Lizenztyp': sanitize_csv_cell(l.get('license_type', '')),
            'Lizenzschluessel': sanitize_csv_cell(l.get('license_key', '')),
            'Plaetze_Gesamt': l.get('seats_total') if l.get('seats_total') is not None else 1,
            'Plaetze_Genutzt': l.get('seats_used') if l.get('seats_used') is not None else 0,
            'Kaufdatum': l.get('purchase_date', '') or '',
            'Gueltig_Bis': l.get('expiration_date', '') or '',
            'Kuendigungsfrist_Tage': l.get('notice_period_days') if l.get('notice_period_days') is not None else 30,
            'Kuendigungsstichtag': l.get('cancellation_deadline', '') or '',
            'Auto_Verlaengerung': 'Ja' if l.get('auto_renewal') else 'Nein',
            'Kosten': str(l.get('cost', 0)).replace('.', ','),
            'Abrechnungsintervall': sanitize_csv_cell(l.get('billing_cycle', '')),
            'Abrechnungsmonate': l.get('billing_cycle_months', 12),
            'Waehrung': sanitize_csv_cell(l.get('currency', 'EUR')),
            'Jaehrliche_Kosten_EUR': str(l.get('yearly_equivalent', 0)).replace('.', ','),
            'Rechnungsnummer': sanitize_csv_cell(l.get('invoice_number', '')),
            'Zugewiesen_An': sanitize_csv_cell(l.get('assigned_to', '')),
            'Status': sanitize_csv_cell(l.get('status', 'active')),
            'Portal_URL': sanitize_csv_cell(l.get('login_portal_url', '')),
            'Notizen': sanitize_csv_cell(l.get('notes', ''))
        })

    return output.getvalue()

def import_csv_data(csv_text):
    """Importiert Lizenzen aus einer hochgeladenen CSV-Datei in einer einzigen atomaren Transaktion."""
    delimiter = ';' if ';' in csv_text else ','
    reader = csv.DictReader(io.StringIO(csv_text), delimiter=delimiter)

    conn = get_db()
    cursor = conn.cursor()
    count = 0
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        cursor.execute("BEGIN TRANSACTION;")
        for row in reader:
            name = row.get('Software') or row.get('name') or row.get('Name')
            if not name or not str(name).strip():
                continue

            cost_val = row.get('Kosten') or row.get('cost') or '0'
            cost = _safe_float(cost_val, 0.0)

            auto_ren_val = row.get('Auto_Verlaengerung') or row.get('auto_renewal') or '1'
            auto_ren = 1 if str(auto_ren_val).lower().strip() in ('ja', '1', 'true', 'yes') else 0

            months_val = row.get('Abrechnungsmonate') or row.get('billing_cycle_months')
            cycle_months = _safe_int(months_val, default=12)

            tot_seats_val = row.get('Plaetze_Gesamt') or row.get('seats_total')
            seats_total = _safe_int(tot_seats_val, default=1)
            if seats_total < 1:
                seats_total = 1

            used_seats_val = row.get('Plaetze_Genutzt') if 'Plaetze_Genutzt' in row else row.get('seats_used')
            seats_used = _safe_int(used_seats_val, default=0) if used_seats_val is not None and str(used_seats_val).strip() != '' else 0

            notice_val = row.get('Kuendigungsfrist_Tage') or row.get('notice_period_days')
            notice_days = _safe_int(notice_val, default=30) if notice_val is not None and str(notice_val).strip() != '' else 30

            cursor.execute('''
                INSERT INTO licenses (
                    name, vendor, category, license_type, license_key,
                    seats_total, seats_used, purchase_date, expiration_date,
                    notice_period_days, auto_renewal, cost, billing_cycle,
                    billing_cycle_months, currency, invoice_number, assigned_to,
                    login_portal_url, status, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                _safe_str(name),
                _safe_str(row.get('Hersteller') or row.get('vendor')),
                _safe_str(row.get('Kategorie') or row.get('category'), 'Sonstiges') or 'Sonstiges',
                _safe_str(row.get('Lizenztyp') or row.get('license_type'), 'subscription') or 'subscription',
                _safe_str(row.get('Lizenzschluessel') or row.get('license_key')),
                seats_total,
                seats_used,
                normalize_date_str(row.get('Kaufdatum') or row.get('purchase_date')),
                normalize_date_str(row.get('Gueltig_Bis') or row.get('expiration_date')),
                notice_days,
                auto_ren,
                cost,
                _safe_str(row.get('Abrechnungsintervall') or row.get('billing_cycle'), 'yearly') or 'yearly',
                cycle_months,
                _safe_str(row.get('Waehrung') or row.get('currency'), 'EUR') or 'EUR',
                _safe_str(row.get('Rechnungsnummer') or row.get('invoice_number')),
                _safe_str(row.get('Zugewiesen_An') or row.get('assigned_to')),
                _safe_str(row.get('Portal_URL') or row.get('login_portal_url')),
                _safe_str(row.get('Status') or row.get('status'), 'active') or 'active',
                _safe_str(row.get('Notizen') or row.get('notes')),
                now_str,
                now_str
            ))
            count += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return count

def seed_sample_data():
    """Fügt realistische Beispieldaten relativ zum heutigen Datum ein."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM licenses')
        conn.commit()
    finally:
        conn.close()

    today = date.today()

    samples = [
        {
            'name': 'Microsoft 365 Business Standard',
            'vendor': 'Microsoft',
            'category': 'Office & Produktivität',
            'license_type': 'subscription',
            'license_key': 'M365-ENT-8842-XPL9',
            'seats_total': 5,
            'seats_used': 5,
            'purchase_date': format_date(today - timedelta(days=340)),
            'expiration_date': format_date(today + timedelta(days=25)), # Kündigungsfrist/Ablauf bald!
            'notice_period_days': 30, # Frist bereits heute fällig!
            'auto_renewal': 1,
            'cost': 62.50,
            'billing_cycle': 'monthly',
            'currency': 'EUR',
            'invoice_number': 'INV-2026-MS-019',
            'assigned_to': 'Team Gesamt (GF, Buchhaltung, Vertrieb)',
            'login_portal_url': 'https://admin.microsoft.com',
            'status': 'active',
            'notes': '5 Benutzerkonten inkl. Exchange, Teams und Desktop-Office-Apps.'
        },
        {
            'name': 'Adobe Creative Cloud Alle Applikationen',
            'vendor': 'Adobe Inc.',
            'category': 'Design & Kreativität',
            'license_type': 'subscription',
            'license_key': 'ADOBE-CC-PRO-9921',
            'seats_total': 2,
            'seats_used': 2,
            'purchase_date': format_date(today - timedelta(days=350)),
            'expiration_date': format_date(today + timedelta(days=15)), # Sehr dringend!
            'notice_period_days': 14,
            'auto_renewal': 1,
            'cost': 142.78,
            'billing_cycle': 'monthly',
            'currency': 'EUR',
            'invoice_number': 'ADB-8823101',
            'assigned_to': 'Marketing & Mediendesign',
            'login_portal_url': 'https://adminconsole.adobe.com',
            'status': 'active',
            'notes': 'Photoshop, Illustrator, InDesign, Premiere Pro etc.'
        },
        {
            'name': 'JetBrains All Products Pack',
            'vendor': 'JetBrains s.r.o.',
            'category': 'Entwicklung & Tools',
            'license_type': 'subscription',
            'license_key': 'JB-ALL-4421-998A',
            'seats_total': 1,
            'seats_used': 1,
            'purchase_date': format_date(today - timedelta(days=300)),
            'expiration_date': format_date(today + timedelta(days=65)), # Demnächst in 65 Tagen
            'notice_period_days': 30,
            'auto_renewal': 1,
            'cost': 289.00,
            'billing_cycle': 'yearly',
            'currency': 'EUR',
            'invoice_number': 'JB-INV-7729',
            'assigned_to': 'Entwickler-Arbeitsplatz',
            'login_portal_url': 'https://account.jetbrains.com',
            'status': 'active',
            'notes': 'PyCharm, WebStorm, IntelliJ IDEA, DataGrip.'
        },
        {
            'name': '1Password Business',
            'vendor': 'AgileBits / 1Password',
            'category': 'Sicherheit & Antivirus',
            'license_type': 'subscription',
            'license_key': '1PASS-BIZ-TEAM-10',
            'seats_total': 10,
            'seats_used': 8,
            'purchase_date': format_date(today - timedelta(days=180)),
            'expiration_date': format_date(today + timedelta(days=185)), # Grün, noch 6 Monate
            'notice_period_days': 30,
            'auto_renewal': 1,
            'cost': 79.90,
            'billing_cycle': 'monthly',
            'currency': 'EUR',
            'invoice_number': '1P-2026-081',
            'assigned_to': 'Alle Mitarbeiter',
            'login_portal_url': 'https://my.1password.com',
            'status': 'active',
            'notes': 'Zentraler Passworttresor für Firmenzugänge.'
        },
        {
            'name': 'Bitdefender GravityZone Security',
            'vendor': 'Bitdefender',
            'category': 'Sicherheit & Antivirus',
            'license_type': 'subscription',
            'license_key': 'BD-GZ-25-SEATS-991',
            'seats_total': 15,
            'seats_used': 12,
            'purchase_date': format_date(today - timedelta(days=280)),
            'expiration_date': format_date(today + timedelta(days=85)), # In 85 Tagen
            'notice_period_days': 45,
            'auto_renewal': 1,
            'cost': 389.00,
            'billing_cycle': 'yearly',
            'currency': 'EUR',
            'invoice_number': 'BD-INV-2025-44',
            'assigned_to': 'Alle Firmen-Laptops & Server',
            'login_portal_url': 'https://cloud.gravityzone.bitdefender.com',
            'status': 'active',
            'notes': 'Endpoint Protection für Windows und macOS.'
        },
        {
            'name': 'Domain & Cloud Webhosting (Hetzner)',
            'vendor': 'Hetzner Online GmbH',
            'category': 'Cloud & Hosting',
            'license_type': 'subscription',
            'license_key': 'HTZ-SRV-CX31-884',
            'seats_total': 1,
            'seats_used': 1,
            'purchase_date': format_date(today - timedelta(days=320)),
            'expiration_date': format_date(today + timedelta(days=45)), # In 45 Tagen
            'notice_period_days': 30,
            'auto_renewal': 1,
            'cost': 118.80,
            'billing_cycle': 'yearly',
            'currency': 'EUR',
            'invoice_number': 'HTZ-R-2025-9921',
            'assigned_to': 'Webserver & Unternehmens-Domains',
            'login_portal_url': 'https://konsoleh.hetzner.com',
            'status': 'active',
            'notes': 'Cloud vServer und 3 Firmen-Domains (.de / .com).'
        },
        {
            'name': 'Windows Server 2022 Standard (16 Cores)',
            'vendor': 'Microsoft',
            'category': 'Betriebssysteme',
            'license_type': 'perpetual',
            'license_key': 'WNSVR-2022-XXXX-YYYY-ZZZZ',
            'seats_total': 1,
            'seats_used': 1,
            'purchase_date': format_date(today - timedelta(days=600)),
            'expiration_date': None, # Unbegrenzte Dauerlizenz
            'notice_period_days': 0,
            'auto_renewal': 0,
            'cost': 890.00,
            'billing_cycle': 'once',
            'currency': 'EUR',
            'invoice_number': 'BECHTLE-RE-44120',
            'assigned_to': 'Hauptserver SRV-01',
            'login_portal_url': '',
            'status': 'active',
            'notes': 'Einmalkauf Dauerlizenz, keine monatlichen oder jährlichen Folgekosten.'
        },
        {
            'name': 'Lexware Buchhaltung Pro',
            'vendor': 'Haufe-Lexware',
            'category': 'Finanzen & ERP',
            'license_type': 'subscription',
            'license_key': 'LXW-PRO-2026-8812',
            'seats_total': 3,
            'seats_used': 2,
            'purchase_date': format_date(today - timedelta(days=200)),
            'expiration_date': format_date(today + timedelta(days=165)),
            'notice_period_days': 60,
            'auto_renewal': 1,
            'cost': 459.00,
            'billing_cycle': 'yearly',
            'currency': 'EUR',
            'invoice_number': 'LX-991208',
            'assigned_to': 'Buchhaltung / Finanzen',
            'login_portal_url': 'https://lexware.de',
            'status': 'active',
            'notes': 'Jahreslizenz mit automatischen gesetzlichen Updates.'
        }
    ]

    for s in samples:
        add_license(s)

    return len(samples)

def clear_all_data():
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM licenses')
        conn.commit()
    finally:
        conn.close()
    return True
