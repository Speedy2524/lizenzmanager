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

# ==============================================================================
# CSRF & RATE LIMITING SCHUTZ
# ==============================================================================
@app.before_request
def check_csrf():
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        # API-Routen gegen CSRF absichern: Erfordert Custom Request Header
        if request.path.startswith('/api/'):
            req_with = request.headers.get('X-Requested-With')
            csrf_token = request.headers.get('X-CSRF-Token')
            if req_with != 'XMLHttpRequest' and not csrf_token:
                return jsonify({'error': 'Fehlender CSRF-Schutz-Header (X-Requested-With erforderlich)'}), 403

_login_attempts = {}

def is_login_rate_limited(ip, max_attempts=5, window_seconds=60):
    """Verhindert AD-Account-Lockouts durch Brute-Force Rate-Limiting pro IP."""
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < window_seconds]
    if len(attempts) >= max_attempts:
        return True
    attempts.append(now)
    _login_attempts[ip] = attempts
    return False

def is_safe_url(target):
    """Prüft, ob eine Weiterleitungs-URL sicher und intern ist (Open-Redirect-Schutz)."""
    if not target:
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

# ==============================================================================
# AUTHENTIFIZIERUNGS-ROUTEN
# ==============================================================================
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
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1').split(',')[0].strip()
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
            if request.is_json:
                return jsonify({'success': True, 'redirect': next_url, 'user': user_info})
            return redirect(next_url)
        else:
            error = error_msg
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
                'display_name': 'Lokaler Benutzer',
                'is_admin': True,
                'groups': []
            }
        })

    is_logged_in = 'user' in session
    return jsonify({
        'auth_enabled': True,
        'authenticated': is_logged_in,
        'user': session.get('user')
    })

@app.route('/')
@login_required
def index():
    user = session.get('user')
    if not user and not config.AUTH_ENABLED:
        user = {
            'username': 'local',
            'display_name': 'Lokaler Administrator',
            'is_admin': True,
            'groups': []
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
@admin_required
def add_license():
    data = request.get_json(silent=True) or {}
    if not data.get('name'):
        return jsonify({'error': 'Software-Name ist erforderlich'}), 400

    new_lic = database.add_license(data)
    return jsonify(new_lic), 201

@app.route('/api/licenses/<int:license_id>', methods=['PUT'])
@login_required
@admin_required
def update_license(license_id):
    data = request.get_json(silent=True) or {}
    if not data.get('name'):
        return jsonify({'error': 'Software-Name ist erforderlich'}), 400

    updated_lic = database.update_license(license_id, data)
    if not updated_lic:
        return jsonify({'error': 'Lizenz nicht gefunden'}), 404
    return jsonify(updated_lic)

@app.route('/api/licenses/<int:license_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_license(license_id):
    database.delete_license(license_id)
    return jsonify({'success': True})

@app.route('/api/licenses/<int:license_id>/renew', methods=['POST'])
@login_required
@admin_required
def renew_license(license_id):
    data = request.get_json(silent=True) or {}
    months = data.get('months')
    if months is not None:
        try:
            months = int(months)
        except ValueError:
            months = None

    renewed = database.renew_license(license_id, months=months)
    if not renewed:
        return jsonify({'error': 'Lizenz konnte nicht verlängert werden'}), 400
    return jsonify(renewed)

@app.route('/api/licenses/<int:license_id>/status', methods=['POST'])
@login_required
@admin_required
def change_status(license_id):
    data = request.get_json(silent=True) or {}
    new_status = data.get('status')
    if new_status not in ('active', 'cancelled', 'archived'):
        return jsonify({'error': 'Ungültiger Status'}), 400

    lic = database.get_license(license_id)
    if not lic:
        return jsonify({'error': 'Lizenz nicht gefunden'}), 404

    lic['status'] = new_status
    updated = database.update_license(license_id, lic)
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
    filename = f"licenses_backup_{database.date.today().strftime('%Y%m%d')}.db"
    return send_file(
        database.DB_PATH,
        as_attachment=True,
        download_name=filename,
        mimetype='application/x-sqlite3'
    )

@app.route('/api/import/csv', methods=['POST'])
@login_required
@admin_required
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

    imported_count = database.import_csv_data(content)
    return jsonify({'success': True, 'imported_count': imported_count})

@app.route('/api/seed', methods=['POST'])
@login_required
@admin_required
def seed_data():
    count = database.seed_sample_data()
    return jsonify({'success': True, 'count': count})

@app.route('/api/clear', methods=['POST'])
@login_required
@admin_required
def clear_data():
    database.clear_all_data()
    return jsonify({'success': True})

# ==============================================================================
# SYSTEM & HEALTHCHECK ROUTEN
# ==============================================================================
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok'}), 200

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

def open_browser(port):
    time.sleep(1.2)
    url = f'http://localhost:{port}'
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

    print('=' * 60)
    print(f'  LIZENZMANAGEMENT TOOL GESTARTET')
    print(f'  Web-Oberfläche verfügbar unter: http://localhost:{port}')
    print(f'  Drücke STRG + C zum Beenden.')
    print('=' * 60)

    host = os.environ.get('HOST', '127.0.0.1')
    auto_browser = os.environ.get('AUTO_OPEN_BROWSER', 'true').lower() in ('true', '1') and host != '0.0.0.0'

    # Browser nur im Hauptprozess und auf lokalem Host öffnen
    if auto_browser and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        threading.Thread(target=open_browser, args=(port,), daemon=True).start()

    app.run(host=host, port=port, debug=False)
