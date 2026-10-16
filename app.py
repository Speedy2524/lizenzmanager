import os
import sys
import threading
import time
import webbrowser
from urllib.parse import urlsplit
from functools import wraps
from flask import Flask, render_template, request, jsonify, Response, session, redirect, url_for, send_file
import database
import config
import auth_ldap
import ai_service
import update_service
import notification_service
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1')
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 10 * 1024 * 1024)) # 10 MB

# Reverse-Proxy-Unterstützung (z. B. Nginx Proxy Manager, Traefik)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Initialisiere Datenbank beim Start
database.init_db()

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'Übermittelte Datei ist zu groß (maximal 10 MB erlaubt).'}), 413

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ==============================================================================
# ERSTEINRICHTUNG & CSRF SCHUTZ
# ==============================================================================
@app.before_request
def enforce_setup_and_csrf():
    # 1. Ersteinrichtung erzwingen, falls noch kein lokaler Administrator angelegt wurde
    if not database.has_local_admin():
        allowed = ('/setup', '/static/')
        if not any(request.path.startswith(p) for p in allowed):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Ersteinrichtung erforderlich', 'setup_required': True, 'redirect': '/setup'}), 403
            return redirect(url_for('setup'))

    # 2. CSRF-Schutz für mutierende API-Requests
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        if request.path.startswith('/api/'):
            req_with = request.headers.get('X-Requested-With')
            csrf_token = request.headers.get('X-CSRF-Token')
            if req_with != 'XMLHttpRequest' and not csrf_token:
                return jsonify({'error': 'Fehlender CSRF-Schutz-Header (X-Requested-With erforderlich)'}), 403

_login_attempts = {}

def is_login_rate_limited(ip, max_attempts=5, window_seconds=60):
    """Verhindert AD-Account-Lockouts durch Brute-Force Rate-Limiting pro IP."""
    now = time.time()
    # Speicherbereinigung bei anwachsender Cache-Größe
    if len(_login_attempts) > 500:
        stale_ips = [k for k, v in _login_attempts.items() if not v or (now - v[-1] > window_seconds)]
        for k in stale_ips:
            _login_attempts.pop(k, None)

    attempts = [t for t in _login_attempts.get(ip, []) if now - t < window_seconds]
    if len(attempts) >= max_attempts:
        return True
    attempts.append(now)
    _login_attempts[ip] = attempts
    return False

def is_safe_url(target):
    """Prüft, ob eine Weiterleitungs-URL sicher und intern ist (Open-Redirect-Schutz)."""
    if not target or '\r' in target or '\n' in target:
        return False
    test_url = urlsplit(target)
    return (
        test_url.scheme == ''
        and test_url.netloc == ''
        and target.startswith('/')
        and not target.startswith('//')
        and not target.startswith('\\')
        and '/\\' not in target
        and '\\\\' not in target
    )

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not config.AUTH_ENABLED:
            return f(*args, **kwargs)
        if 'user' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Nicht authentifiziert. Bitte anmelden.', 'auth_required': True}), 401
            next_url = request.full_path if request.query_string else request.path
            return redirect(url_for('login', next=next_url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not config.AUTH_ENABLED:
            return f(*args, **kwargs)
        if 'user' not in session:
            return jsonify({'error': 'Nicht authentifiziert.', 'auth_required': True}), 401
        if not session.get('user', {}).get('is_admin'):
            return jsonify({'error': 'Administrator-Berechtigung erforderlich.'}), 403
        return f(*args, **kwargs)
    return decorated_function

def editor_required(f):
    """Erfordert mindestens Bearbeiter- oder Administrator-Rechte (kann Lizenzen verwalten)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not config.AUTH_ENABLED:
            return f(*args, **kwargs)
        if 'user' not in session:
            return jsonify({'error': 'Nicht authentifiziert.', 'auth_required': True}), 401
        u = session.get('user', {})
        can_edit = u.get('can_edit') or u.get('is_admin') or (u.get('role') in ('admin', 'editor'))
        if not can_edit:
            return jsonify({'error': 'Bearbeiter- oder Administrator-Berechtigung erforderlich.'}), 403
        return f(*args, **kwargs)
    return decorated_function

def record_audit(action, category, target_name='', target_id=None, details=None, status='success'):
    """Hilfsfunktion zum revisionssicheren Protokollieren von Aktionen im Audit-Log."""
    try:
        user = session.get('user', {})
        username = user.get('username') or 'anonym'
        display_name = user.get('display_name') or username
        client_ip = request.headers.get('X-Forwarded-For') or request.remote_addr or '127.0.0.1'
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        database.log_audit_event(
            action=action,
            category=category,
            target_name=target_name,
            target_id=target_id,
            details=details,
            username=username,
            display_name=display_name,
            ip_address=client_ip,
            status=status
        )
    except Exception as e:
        app.logger.warning(f"Fehler beim Protokollieren ins Audit-Log: {e}")

# ==============================================================================
# AUTHENTIFIZIERUNGS-ROUTEN & ERSTEINRICHTUNG
# ==============================================================================
@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if database.has_local_admin():
        # Ersteinrichtung bereits erfolgt -> Weiterleitung
        return redirect(url_for('index') if 'user' in session else url_for('login'))

    error = None
    username = 'admin'
    display_name = 'Administrator'

    if request.method == 'POST':
        if request.is_json:
            data = request.get_json() or {}
            username = data.get('username', '').strip()
            display_name = data.get('display_name', '').strip()
            password = data.get('password', '')
            password_confirm = data.get('password_confirm', '')
        else:
            username = request.form.get('username', '').strip()
            display_name = request.form.get('display_name', '').strip()
            password = request.form.get('password', '')
            password_confirm = request.form.get('password_confirm', '')

        if not username:
            error = "Bitte geben Sie einen Administrator-Benutzernamen ein."
        elif not password or len(password) < 8:
            error = "Das Kennwort muss mindestens 8 Zeichen lang sein."
        elif password != password_confirm:
            error = "Die eingegebenen Kennwörter stimmen nicht überein."
        else:
            try:
                admin_user = database.create_local_admin(
                    username=username,
                    password=password,
                    display_name=display_name
                )
                # Sofort als neuer Administrator anmelden
                session['user'] = {
                    'username': admin_user['username'],
                    'display_name': admin_user['display_name'],
                    'email': admin_user['email'],
                    'role': 'admin',
                    'is_admin': True,
                    'can_edit': True,
                    'groups': ['Lizenz-Admins'],
                    'auth_method': 'local_database'
                }
                record_audit('SETUP_ADMIN', 'user', target_name=admin_user['username'], details='Ersteinrichtung des lokalen Administrator-Kontos', status='success')
                if request.is_json:
                    return jsonify({'success': True, 'redirect': url_for('index')})
                return redirect(url_for('index'))
            except Exception as e:
                error = f"Fehler beim Erstellen des Administrator-Kontos: {str(e)}"

    return render_template(
        'setup.html',
        error=error,
        username=username,
        display_name=display_name
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not config.AUTH_ENABLED:
        return redirect(url_for('index'))

    # Bereits angemeldet?
    if 'user' in session:
        return redirect(url_for('index'))

    error = None
    username = ''

    if request.method == 'POST':
        # Rate Limiting prüfen (Schutz gegen Brute Force & AD-Kontosperrung)
        client_ip = request.remote_addr or '127.0.0.1'
        if is_login_rate_limited(client_ip):
            error = "Zu viele Anmeldeversuche. Bitte warten Sie 60 Sekunden."
            if request.is_json:
                return jsonify({'error': error}), 429
            return render_template(
                'login.html',
                error=error,
                username=username,
                domain=config.LDAP_DOMAIN
            ), 429

        # Unterstützt sowohl HTML-Formulare als auch JSON-Requests
        if request.is_json:
            data = request.get_json() or {}
            username = data.get('username', '').strip()
            password = data.get('password', '')
        else:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

        next_url = request.args.get('next') or request.form.get('next') or url_for('index')
        # Open-Redirect-Schutz via is_safe_url
        if not is_safe_url(next_url):
            next_url = url_for('index')

        success, user_info, error_msg = auth_ldap.authenticate_user(username, password)

        if success:
            session['user'] = user_info
            role_label = user_info.get('role', 'user')
            record_audit('LOGIN', 'auth', target_name=username, details=f"Erfolgreich angemeldet ({role_label})", status='success')
            if request.is_json:
                return jsonify({'success': True, 'redirect': next_url, 'user': user_info})
            return redirect(next_url)
        else:
            error = error_msg
            record_audit('LOGIN_FAILED', 'auth', target_name=username, details=error_msg, status='warning')
            if request.is_json:
                return jsonify({'error': error_msg}), 401

    return render_template(
        'login.html',
        error=error,
        username=username,
        domain=config.LDAP_DOMAIN
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/auth/me', methods=['GET'])
def get_current_user():
    if not config.AUTH_ENABLED:
        return jsonify({
            'auth_enabled': False,
            'authenticated': True,
            'user': {
                'username': 'local',
                'display_name': 'Lokaler Administrator',
                'role': 'admin',
                'is_admin': True,
                'can_edit': True,
                'groups': ['Lizenz-Admins']
            }
        })

    is_logged_in = 'user' in session
    return jsonify({
        'auth_enabled': True,
        'authenticated': is_logged_in,
        'user': session.get('user')
    })

@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    user = session.get('user', {})
    username = user.get('username')
    auth_method = user.get('auth_method')

    if auth_method != 'local_database':
        return jsonify({'error': 'Das Kennwort von Windows/AD-Benutzerkonten muss im Active Directory geändert werden.'}), 400

    data = request.get_json(silent=True) or {}
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    new_password_confirm = data.get('new_password_confirm', '')

    if not old_password or not new_password:
        return jsonify({'error': 'Bitte aktuelles und neues Kennwort angeben.'}), 400

    if len(new_password) < 8:
        return jsonify({'error': 'Das neue Kennwort muss mindestens 8 Zeichen lang sein.'}), 400

    if new_password != new_password_confirm:
        return jsonify({'error': 'Die neuen Kennwörter stimmen nicht überein.'}), 400

    if not database.verify_local_user(username, old_password):
        return jsonify({'error': 'Das aktuelle Kennwort ist nicht korrekt.'}), 400

    database.update_local_user_password(username, new_password)
    record_audit('CHANGE_PASSWORD', 'user', target_name=username, details='Eigenes Kennwort geändert', status='success')
    return jsonify({'success': True, 'message': 'Kennwort erfolgreich aktualisiert.'})

# ==============================================================================
# BENUTZERVERWALTUNG (LOKALE BENUTZER & ROLLENVERWALTUNG)
# ==============================================================================
@app.route('/api/users', methods=['GET'])
@login_required
@admin_required
def get_users():
    users = database.get_all_local_users()
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
@login_required
@admin_required
def create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    display_name = (data.get('display_name') or '').strip()
    email = (data.get('email') or '').strip()
    role = data.get('role')
    is_admin = bool(data.get('is_admin', False)) if 'is_admin' in data else None

    if not username:
        return jsonify({'error': 'Benutzername ist erforderlich.'}), 400
    if not password or len(password) < 8:
        return jsonify({'error': 'Das Kennwort muss mindestens 8 Zeichen lang sein.'}), 400

    try:
        user = database.add_local_user(
            username=username,
            password=password,
            display_name=display_name,
            email=email,
            role=role or ('admin' if is_admin else 'viewer'),
            is_admin=is_admin
        )
        record_audit('CREATE_USER', 'user', target_name=user['username'], target_id=user.get('id'), details=f"Benutzer '{user['username']}' mit Rolle '{user.get('role')}' angelegt", status='success')
        return jsonify({'success': True, 'user': user}), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Fehler beim Erstellen des Benutzers: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def update_user(user_id):
    data = request.get_json(silent=True) or {}
    display_name = data.get('display_name')
    email = data.get('email')
    role = data.get('role')
    is_admin = data.get('is_admin')
    new_password = data.get('password')

    try:
        updated = database.update_local_user(
            user_id=user_id,
            display_name=display_name,
            email=email,
            role=role,
            is_admin=is_admin,
            new_password=new_password
        )
        if not updated:
            return jsonify({'error': 'Benutzer nicht gefunden.'}), 404

        # Falls der aktuell angemeldete Benutzer sein eigenes Profil geändert hat, Session synchronisieren
        curr_user = session.get('user', {})
        if curr_user.get('username', '').lower() == updated.get('username', '').lower():
            curr_user['display_name'] = updated['display_name']
            curr_user['email'] = updated['email']
            curr_user['role'] = updated['role']
            curr_user['is_admin'] = updated['is_admin']
            curr_user['can_edit'] = updated['can_edit']
            session['user'] = curr_user

        record_audit('UPDATE_USER', 'user', target_name=updated['username'], target_id=user_id, details=f"Benutzerdaten aktualisiert (Rolle: {updated.get('role')})", status='warning')
        return jsonify({'success': True, 'user': updated})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Fehler beim Aktualisieren: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    current_username = session.get('user', {}).get('username')
    try:
        target_user = database.get_local_user_by_id(user_id)
        if not target_user:
            return jsonify({'error': 'Benutzer nicht gefunden.'}), 404

        success = database.delete_local_user(user_id, current_username=current_username)
        if not success:
            return jsonify({'error': 'Benutzer nicht gefunden.'}), 404

        record_audit('DELETE_USER', 'user', target_name=target_user['username'], target_id=user_id, details=f"Benutzerkonto '{target_user['username']}' (Rolle: {target_user.get('role')}) wurde gelöscht", status='danger')
        return jsonify({'success': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Fehler beim Löschen: {str(e)}'}), 500

@app.route('/')
@login_required
def index():
    user = session.get('user')
    if not user and not config.AUTH_ENABLED:
        user = {
            'username': 'local',
            'display_name': 'Lokaler Administrator',
            'role': 'admin',
            'is_admin': True,
            'can_edit': True,
            'groups': ['Lizenz-Admins']
        }
    return render_template('index.html', user=user)


@app.route('/api/licenses', methods=['GET'])
@login_required
def get_licenses():
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    status_filter = request.args.get('status', '')
    sort_by = request.args.get('sort_by', 'expiration_date')
    sort_order = request.args.get('sort_order', 'asc')

    licenses = database.get_all_licenses(
        search=search,
        category=category,
        status_filter=status_filter,
        sort_by=sort_by,
        sort_order=sort_order
    )
    return jsonify(licenses)

@app.route('/api/licenses/<int:license_id>', methods=['GET'])
@login_required
def get_license(license_id):
    lic = database.get_license(license_id)
    if not lic:
        return jsonify({'error': 'Lizenz nicht gefunden'}), 404
    return jsonify(lic)

@app.route('/api/licenses', methods=['POST'])
@login_required
@editor_required
def add_license():
    data = request.get_json(silent=True) or {}
    if not data.get('name'):
        return jsonify({'error': 'Software-Name ist erforderlich'}), 400

    current_user = session.get('user', {}).get('username', 'Admin')
    new_lic = database.add_license(data, recorded_by=current_user)
    record_audit(
        'CREATE_LICENSE',
        'license',
        target_name=new_lic.get('name', ''),
        target_id=new_lic.get('id'),
        details={
            'name': new_lic.get('name'),
            'vendor': new_lic.get('vendor'),
            'category': new_lic.get('category'),
            'cost': new_lic.get('cost'),
            'expiration_date': new_lic.get('expiration_date'),
            'assigned_to': new_lic.get('assigned_to')
        },
        status='success'
    )
    return jsonify(new_lic), 201

@app.route('/api/licenses/<int:license_id>', methods=['PUT'])
@login_required
@editor_required
def update_license(license_id):
    data = request.get_json(silent=True) or {}
    if not data.get('name'):
        return jsonify({'error': 'Software-Name ist erforderlich'}), 400

    existing_lic = database.get_license(license_id)
    if not existing_lic:
        return jsonify({'error': 'Lizenz nicht gefunden'}), 404

    current_user = session.get('user', {}).get('username', 'Admin')
    updated_lic = database.update_license(license_id, data, recorded_by=current_user)
    if not updated_lic:
        return jsonify({'error': 'Lizenz nicht gefunden'}), 404

    record_audit(
        'UPDATE_LICENSE',
        'license',
        target_name=updated_lic.get('name', ''),
        target_id=license_id,
        details={
            'name': updated_lic.get('name'),
            'cost': updated_lic.get('cost'),
            'expiration_date': updated_lic.get('expiration_date'),
            'status': updated_lic.get('status')
        },
        status='warning'
    )
    return jsonify(updated_lic)

@app.route('/api/licenses/<int:license_id>', methods=['DELETE'])
@login_required
@editor_required
def delete_license(license_id):
    lic = database.get_license(license_id)
    if not lic:
        return jsonify({'error': 'Lizenz nicht gefunden'}), 404

    lic_name = lic.get('name', 'Unbekannt')
    # Ausführliche Lizenzdaten im Audit-Log festhalten für Nachvollziehbarkeit & Wiederherstellung
    record_audit(
        'DELETE_LICENSE',
        'license',
        target_name=lic_name,
        target_id=license_id,
        details={
            'name': lic_name,
            'vendor': lic.get('vendor'),
            'category': lic.get('category'),
            'cost': lic.get('cost'),
            'license_key': lic.get('license_key'),
            'assigned_to': lic.get('assigned_to'),
            'expiration_date': lic.get('expiration_date'),
            'billing_cycle': lic.get('billing_cycle'),
            'notes': lic.get('notes'),
            'status': lic.get('status')
        },
        status='danger'
    )

    database.delete_license(license_id)
    return jsonify({'success': True})

@app.route('/api/licenses/<int:license_id>/renew', methods=['POST'])
@login_required
@editor_required
def renew_license(license_id):
    data = request.get_json(silent=True) or {}
    months = data.get('months')
    if months is not None:
        try:
            months = int(months)
        except ValueError:
            months = None

    new_cost = data.get('new_cost')
    invoice_number = data.get('invoice_number')
    notes = data.get('notes')
    current_user = session.get('user', {}).get('username', 'Admin')

    renewed = database.renew_license(
        license_id,
        months=months,
        new_cost=new_cost,
        invoice_number=invoice_number,
        notes=notes,
        recorded_by=current_user
    )
    if not renewed:
        return jsonify({'error': 'Lizenz konnte nicht verlängert werden'}), 400

    record_audit(
        'RENEW_LICENSE',
        'license',
        target_name=renewed.get('name', ''),
        target_id=license_id,
        details=f"Verlängert um {months or 'reguläres Intervall'} Monat(e) bis {renewed.get('expiration_date')} (Preis: {renewed.get('cost')} {renewed.get('currency', 'EUR')})",
        status='success'
    )
    return jsonify(renewed)

@app.route('/api/licenses/<int:license_id>/history', methods=['GET'])
@login_required
def get_license_history_route(license_id):
    return jsonify(database.get_license_history(license_id))

@app.route('/api/licenses/<int:license_id>/history', methods=['POST'])
@login_required
@editor_required
def add_license_history_route(license_id):
    lic = database.get_license(license_id)
    if not lic:
        return jsonify({'error': 'Lizenz nicht gefunden'}), 404

    data = request.get_json(silent=True) or {}
    if data.get('new_cost') is None or str(data.get('new_cost')).strip() == '':
        return jsonify({'error': 'Bitte einen Preis angeben.'}), 400

    current_user = session.get('user', {}).get('username', 'Admin')
    entry_id = database.add_license_history(
        license_id=license_id,
        event_type=data.get('event_type') or 'manual',
        new_cost=data.get('new_cost'),
        old_cost=data.get('old_cost'),
        event_date=data.get('event_date'),
        billing_cycle=data.get('billing_cycle') or lic.get('billing_cycle', 'yearly'),
        currency=data.get('currency') or lic.get('currency', 'EUR'),
        old_expiration_date=data.get('old_expiration_date'),
        new_expiration_date=data.get('new_expiration_date'),
        seats_total=data.get('seats_total') or lic.get('seats_total', 1),
        invoice_number=data.get('invoice_number'),
        notes=data.get('notes') or 'Manuell nachgetragener Historieneintrag',
        recorded_by=current_user
    )
    return jsonify({'success': True, 'id': entry_id, 'data': database.get_license_history(license_id)})

@app.route('/api/licenses/history/<int:history_id>', methods=['DELETE'])
@login_required
@editor_required
def delete_license_history_route(history_id):
    ok = database.delete_license_history_entry(history_id)
    if not ok:
        return jsonify({'error': 'Eintrag nicht gefunden.'}), 404
    return jsonify({'success': True})

@app.route('/api/spend-tracking', methods=['GET'])
@login_required
def get_spend_tracking_route():
    return jsonify(database.get_spend_tracking_overview())

@app.route('/api/licenses/<int:license_id>/status', methods=['POST'])
@login_required
@editor_required
def change_status(license_id):
    data = request.get_json(silent=True) or {}
    new_status = data.get('status')
    if new_status not in ('active', 'cancelled', 'archived'):
        return jsonify({'error': 'Ungültiger Status'}), 400

    lic = database.get_license(license_id)
    if not lic:
        return jsonify({'error': 'Lizenz nicht gefunden'}), 404

    old_status = lic.get('status')
    lic['status'] = new_status
    updated = database.update_license(license_id, lic, _skip_history=True)

    record_audit(
        'STATUS_CHANGE',
        'license',
        target_name=lic.get('name', ''),
        target_id=license_id,
        details=f"Status geändert von '{old_status}' auf '{new_status}'",
        status='warning'
    )
    return jsonify(updated)

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    stats = database.get_dashboard_stats()
    return jsonify(stats)

@app.route('/api/calendar', methods=['GET'])
@login_required
def get_calendar():
    year = request.args.get('year')
    if year:
        try:
            year = int(year)
        except ValueError:
            year = None
    cal_data = database.get_calendar_data(year=year)
    return jsonify(cal_data)

@app.route('/api/export/csv', methods=['GET'])
@login_required
def export_csv():
    csv_content = database.export_csv_data()
    filename = f"lizenzen_export_{database.date.today().strftime('%Y%m%d')}.csv"
    return Response(
        csv_content,
        mimetype='text/csv; charset=utf-8-sig',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )

@app.route('/api/export/db', methods=['GET'])
@login_required
@admin_required
def export_db():
    if not os.path.exists(database.DB_PATH):
        return jsonify({'error': 'Datenbankdatei nicht gefunden.'}), 404
    # WAL-Checkpoint ausführen, um sicherzustellen, dass alle Transaktionen im Backup enthalten sind
    try:
        conn = database.get_db()
        try:
            conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
        finally:
            conn.close()
    except Exception:
        pass
    filename = f"licenses_backup_{database.date.today().strftime('%Y%m%d')}.db"
    return send_file(
        database.DB_PATH,
        as_attachment=True,
        download_name=filename,
        mimetype='application/x-sqlite3'
    )

@app.route('/api/import/csv', methods=['POST'])
@login_required
@editor_required
def import_csv():
    if 'file' not in request.files:
        return jsonify({'error': 'Keine Datei übermittelt'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'Keine Datei ausgewählt'}), 400

    raw_bytes = file.read()
    content = None
    for enc in ('utf-8-sig', 'utf-8', 'cp1252', 'iso-8859-1'):
        try:
            content = raw_bytes.decode(enc)
            break
        except UnicodeDecodeError:
            continue

    if content is None:
        content = raw_bytes.decode('utf-8-sig', errors='replace')

    try:
        imported_count = database.import_csv_data(content)
        record_audit(
            'IMPORT_CSV',
            'license',
            target_name=file.filename,
            details=f"{imported_count} Lizenzen aus CSV importiert",
            status='success'
        )
        return jsonify({'success': True, 'imported_count': imported_count})
    except Exception as e:
        return jsonify({'error': f'Fehler beim CSV-Import: {str(e)}'}), 400

@app.route('/api/seed', methods=['POST'])
@login_required
@admin_required
def seed_data():
    count = database.seed_sample_data()
    record_audit(
        'SEED_DATA',
        'system',
        target_name='Beispieldaten',
        details=f"{count} Beispiellizenzen generiert",
        status='warning'
    )
    return jsonify({'success': True, 'count': count})

@app.route('/api/clear', methods=['POST'])
@login_required
@admin_required
def clear_data():
    database.clear_all_data()
    record_audit(
        'CLEAR_DATA',
        'system',
        target_name='Alle Lizenzen',
        details='Alle Lizenzen wurden unwiderruflich aus der Datenbank gelöscht',
        status='danger'
    )
    return jsonify({'success': True})

# ==============================================================================
# AUDIT-LOG ROUTEN (REVISIONSSICHERHEIT & ÄNDERUNGSPROTOKOLL FÜR ADMINISTRATOREN)
# ==============================================================================
@app.route('/api/audit-logs', methods=['GET'])
@login_required
@admin_required
def get_audit_logs():
    limit = request.args.get('limit', 50)
    offset = request.args.get('offset', 0)
    category = request.args.get('category') or None
    action = request.args.get('action') or None
    search = request.args.get('search') or None
    deletions_only = request.args.get('deletions_only', 'false').lower() in ('true', '1')

    try:
        limit = int(limit)
        offset = int(offset)
    except ValueError:
        limit = 50
        offset = 0

    result = database.get_audit_logs(
        limit=limit,
        offset=offset,
        category=category,
        action=action,
        search=search,
        deletions_only=deletions_only
    )
    stats = database.get_audit_log_stats()
    return jsonify({
        'success': True,
        'logs': result['logs'],
        'total': result['total'],
        'stats': stats,
        'limit': limit,
        'offset': offset
    })

@app.route('/api/audit-logs/export', methods=['GET'])
@login_required
@admin_required
def export_audit_logs():
    csv_content = database.export_audit_logs_csv()
    filename = f"audit_log_{database.date.today().strftime('%Y%m%d')}.csv"
    return Response(
        csv_content,
        mimetype='text/csv; charset=utf-8-sig',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )

@app.route('/api/audit-logs/clear', methods=['POST'])
@login_required
@admin_required
def clear_audit_logs():
    data = request.get_json(silent=True) or {}
    keep_days = data.get('keep_days')
    if keep_days is not None:
        try:
            keep_days = int(keep_days)
        except ValueError:
            keep_days = None

    deleted_count = database.clear_audit_logs(keep_days=keep_days)
    record_audit(
        'CLEAR_AUDIT_LOGS',
        'system',
        target_name='Audit-Log',
        details=f"{deleted_count} Log-Einträge bereinigt (Behalten: {keep_days if keep_days is not None else 'Keine'} Tage)",
        status='danger'
    )
    return jsonify({'success': True, 'deleted_count': deleted_count})

# ==============================================================================
# SYSTEM & HEALTHCHECK ROUTEN
# ==============================================================================
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok'}), 200

@app.route('/api/system/update-check', methods=['GET'])
@login_required
def check_system_updates():
    force = request.args.get('force', 'false').lower() in ('true', '1')
    simulate = request.args.get('simulate', 'false').lower() in ('true', '1')

    user = session.get('user', {})
    is_admin = not config.AUTH_ENABLED or bool(user.get('is_admin'))

    # Simulation ist nur für Administratoren zulässig
    if simulate and not is_admin:
        return jsonify({'error': 'Administrator-Berechtigung für Update-Simulation erforderlich.'}), 403

    info = update_service.check_for_updates(force=force, simulate=simulate)
    return jsonify(info)

# ==============================================================================
# KI-ROUTEN (vLLM Rechnungsanalyse)
# ==============================================================================
@app.route('/api/ai/status', methods=['GET'])
@login_required
def get_ai_status():
    status = ai_service.check_ai_status()
    return jsonify(status)

@app.route('/api/ai/parse-invoice', methods=['POST'])
@login_required
@editor_required
def parse_invoice():
    data = request.get_json(silent=True) or {}
    text = data.get('text') or data.get('invoice_text') or ''
    if not text.strip():
        return jsonify({'error': 'Bitte füge einen Rechnungstext oder Bestelldaten ein.'}), 400

    try:
        draft = ai_service.parse_invoice_text(text)
        return jsonify({
            'success': True,
            'draft': draft,
            'message': 'Lizenz-Entwurf erfolgreich generiert'
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Fehler bei der KI-Analyse: {str(e)}'}), 500

# ==============================================================================
# BENACHRICHTIGUNGEN (E-MAIL SMTP & MICROSOFT TEAMS WEBHOOK)
# ==============================================================================
@app.route('/api/notifications/settings', methods=['GET'])
@login_required
@admin_required
def get_notification_settings_route():
    return jsonify(database.get_notification_settings(mask_password=True))

@app.route('/api/notifications/settings', methods=['POST'])
@login_required
@admin_required
def save_notification_settings_route():
    data = request.get_json(silent=True) or {}
    saved = database.save_notification_settings(data)
    record_audit(
        'UPDATE_NOTIFICATION_SETTINGS',
        'system',
        target_name='Benachrichtigungen',
        details=f"Teams: {'Aktiv' if saved.get('teams_enabled') else 'Inaktiv'}, E-Mail: {'Aktiv' if saved.get('email_enabled') else 'Inaktiv'}, Intervalle: {saved.get('notify_days')}",
        status='success'
    )
    return jsonify({'success': True, 'settings': saved})

@app.route('/api/notifications/test-teams', methods=['POST'])
@login_required
@admin_required
def test_teams_notification_route():
    data = request.get_json(silent=True) or {}
    stored = database.get_notification_settings(mask_password=False)
    webhook_url = (data.get('teams_webhook_url') or stored.get('teams_webhook_url') or '').strip()
    try:
        ok, msg = notification_service.send_teams_notification(webhook_url, [], is_test=True)
        record_audit('TEST_TEAMS_NOTIFICATION', 'system', target_name='Microsoft Teams Webhook', details=msg, status='success' if ok else 'warning')
        return jsonify({'success': ok, 'message': msg}), (200 if ok else 400)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/notifications/test-email', methods=['POST'])
@login_required
@admin_required
def test_email_notification_route():
    data = request.get_json(silent=True) or {}
    stored = database.get_notification_settings(mask_password=False)

    # Erlaube Test mit ungespeicherten Formulardaten + gespeichertem Passwort-Fallback
    merged = dict(stored)
    for k in ('smtp_host', 'smtp_port', 'smtp_security', 'smtp_user', 'smtp_from', 'smtp_to'):
        if k in data and data[k] is not None and str(data[k]).strip() != '':
            merged[k] = data[k]
    if data.get('smtp_password') and data.get('smtp_password') != '••••••••':
        merged['smtp_password'] = data.get('smtp_password')

    try:
        ok, msg = notification_service.send_email_notification(merged, [], is_test=True)
        record_audit('TEST_EMAIL_NOTIFICATION', 'system', target_name='SMTP E-Mail', details=msg, status='success' if ok else 'warning')
        return jsonify({'success': ok, 'message': msg}), (200 if ok else 400)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/notifications/run-check', methods=['POST'])
@login_required
@admin_required
def run_notification_check_route():
    try:
        res = notification_service.check_and_send_due_notifications(manual_trigger=True)
        record_audit('MANUAL_NOTIFICATION_CHECK', 'system', target_name='Fristenwarnung', details=res.get('message', ''), status='success')
        return jsonify(res)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

def _background_notification_worker():
    """Prüft im Hintergrund regelmäßig auf fällige Lizenzen und versendet konfigurierte Warnungen."""
    time.sleep(15)
    while True:
        try:
            settings = database.get_notification_settings(mask_password=False)
            if settings.get('auto_check_enabled') and (settings.get('teams_enabled') or settings.get('email_enabled')):
                notification_service.check_and_send_due_notifications(manual_trigger=False)
        except Exception as e:
            app.logger.warning(f"Hintergrund-Benachrichtigungsprüfung fehlgeschlagen: {e}")
        time.sleep(6 * 3600) # Alle 6 Stunden prüfen

if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
    threading.Thread(target=_background_notification_worker, daemon=True).start()

def open_browser(port):
    time.sleep(1.2)
    path = '/setup' if not database.has_local_admin() else ''
    url = f'http://localhost:{port}{path}'
    print(f'[Lizenzmanager] Öffne Browser: {url}')
    try:
        webbrowser.open_new_tab(url)
    except Exception as e:
        print(f'[Lizenzmanager] Konnte Browser nicht automatisch öffnen: {e}')

if __name__ == '__main__':
    port = 5000
    import socket
    while port < 5050:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        is_busy = (sock.connect_ex(('127.0.0.1', port)) == 0)
        sock.close()
        if not is_busy:
            break
        port += 1

    needs_setup = not database.has_local_admin()

    print('=' * 65)
    if needs_setup:
        print('  ERSTEINRICHTUNG ERFORDERLICH!')
        print(f'  Öffnen Sie http://localhost:{port}/setup im Browser,')
        print('  um das lokale Administrator-Konto einzurichten.')
    else:
        print('  LIZENZMANAGEMENT TOOL GESTARTET')
        print(f'  Web-Oberfläche verfügbar unter: http://localhost:{port}')
    print('  Drücke STRG + C zum Beenden.')
    print('=' * 65)

    host = os.environ.get('HOST', '127.0.0.1')
    auto_browser = os.environ.get('AUTO_OPEN_BROWSER', 'true').lower() in ('true', '1') and host != '0.0.0.0'

    # Browser nur im Hauptprozess und auf lokalem Host öffnen
    if auto_browser and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        threading.Thread(target=open_browser, args=(port,), daemon=True).start()

    app.run(host=host, port=port, debug=False)
