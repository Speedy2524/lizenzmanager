import json
import smtplib
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlparse
from email.message import EmailMessage
from datetime import datetime
import database


def _validate_webhook_url(url):
    """Prüft, ob die Webhook-URL gültig und sicher (HTTPS) ist."""
    url = (url or '').strip()
    if not url:
        raise ValueError("Keine Microsoft Teams Webhook-URL hinterlegt.")
    parsed = urlparse(url)
    if parsed.scheme not in ('https', 'http') or not parsed.netloc:
        raise ValueError("Ungültige Webhook-URL. Bitte eine vollständige URL (https://...) eingeben.")
    if parsed.hostname in ('localhost', '127.0.0.1', '0.0.0.0', '::1'):
        raise ValueError("Lokale Loopback-Adressen sind als Webhook-Ziel nicht zulässig.")
    return url


def _format_currency_de(val, currency='EUR'):
    try:
        num = float(val or 0.0)
    except (ValueError, TypeError):
        num = 0.0
    formatted = f"{num:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    symbol = "€" if (currency or "EUR").upper() == "EUR" else currency
    return f"{formatted} {symbol}"


def _format_date_de(date_str):
    if not date_str:
        return "-"
    try:
        parts = str(date_str)[:10].split("-")
        if len(parts) == 3:
            return f"{parts[2]}.{parts[1]}.{parts[0]}"
    except Exception:
        pass
    return str(date_str)


def send_teams_notification(webhook_url, licenses_list, title=None, subtitle=None, is_test=False):
    """
    Sendet eine formatierte Adaptive Card / Teams-Benachrichtigung an Microsoft Teams
    (kompatibel mit klassischen Office 365 Connectors & modernen Teams Workflows).
    """
    url = _validate_webhook_url(webhook_url)
    now_str = datetime.now().strftime('%d.%m.%Y %H:%M')

    if is_test:
        title = title or "🔔 Lizenzmanager – Testbenachrichtigung"
        subtitle = subtitle or f"Verbindungstest erfolgreich durchgeführt am {now_str} Uhr."
    else:
        title = title or f"⚠️ Lizenzmanager: {len(licenses_list)} fällige Lizenz(en)"
        subtitle = subtitle or f"Automatische Fristenwarnung vom {now_str} Uhr"

    body_elements = [
        {
            "type": "TextBlock",
            "size": "Large",
            "weight": "Bolder",
            "text": title,
            "wrap": True,
            "color": "Attention" if not is_test else "Accent"
        },
        {
            "type": "TextBlock",
            "text": subtitle,
            "isSubtle": True,
            "wrap": True,
            "spacing": "None"
        }
    ]

    if is_test and not licenses_list:
        body_elements.append({
            "type": "TextBlock",
            "text": "✅ Ihr Microsoft Teams Webhook ist korrekt eingerichtet. Zukünftige Kündigungsfristen und ablaufende Lizenzen werden automatisch in diesem Kanal gemeldet.",
            "wrap": True,
            "spacing": "Medium"
        })
    else:
        for lic in licenses_list[:15]:
            name = lic.get('name', 'Unbekannt')
            vendor = lic.get('vendor') or '-'
            cost_str = _format_currency_de(lic.get('cost'), lic.get('currency', 'EUR'))
            exp_str = _format_date_de(lic.get('expiration_date'))
            canc_str = _format_date_de(lic.get('cancellation_deadline'))
            badge = lic.get('badge_label') or 'Fällig'

            body_elements.append({
                "type": "Container",
                "separator": True,
                "spacing": "Medium",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": f"**{name}** ({vendor})",
                        "wrap": True,
                        "weight": "Bolder"
                    },
                    {
                        "type": "FactSet",
                        "spacing": "Small",
                        "facts": [
                            {"title": "Status:", "value": badge},
                            {"title": "Kündigungsfrist:", "value": canc_str},
                            {"title": "Ablaufdatum:", "value": exp_str},
                            {"title": "Kosten:", "value": cost_str}
                        ]
                    }
                ]
            })

    payload = {
        "type": "message",
        "summary": title,
        "text": f"**{title}**\n\n{subtitle}",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body_elements
                }
            }
        ]
    }

    data_bytes = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        url,
        data=data_bytes,
        headers={
            'Content-Type': 'application/json; charset=utf-8',
            'User-Agent': 'Lizenzmanager-Notifier/1.2'
        },
        method='POST'
    )

    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            status_code = resp.getcode()
            if 200 <= status_code < 300:
                return True, f"Teams-Nachricht erfolgreich gesendet (HTTP {status_code})."
            return False, f"Teams antwortete mit HTTP-Status {status_code}."
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode('utf-8', errors='replace')[:200]
        except Exception:
            pass
        raise RuntimeError(f"Teams Webhook HTTP-Fehler {e.code}: {err_body or e.reason}")
    except Exception as e:
        raise RuntimeError(f"Verbindungsfehler zum Teams Webhook: {str(e)}")


def send_email_notification(settings, licenses_list, subject=None, is_test=False):
    """Sendet eine HTML- & Text-Benachrichtigungs-E-Mail über den konfigurierten SMTP-Server."""
    host = (settings.get('smtp_host') or '').strip()
    port = int(settings.get('smtp_port') or 587)
    security = (settings.get('smtp_security') or 'starttls').strip().lower()
    user = (settings.get('smtp_user') or '').strip()
    password = settings.get('smtp_password') or ''
    sender = (settings.get('smtp_from') or user or '').strip()
    recipients_raw = (settings.get('smtp_to') or '').strip()

    if not host:
        raise ValueError("Kein SMTP-Server (Host) konfiguriert.")
    if not sender:
        raise ValueError("Keine Absender-E-Mail-Adresse konfiguriert.")
    if not recipients_raw:
        raise ValueError("Keine Empfänger-E-Mail-Adresse konfiguriert.")

    recipients = [r.strip() for r in recipients_raw.replace(';', ',').split(',') if r.strip()]
    if not recipients:
        raise ValueError("Keine gültige Empfänger-E-Mail-Adresse gefunden.")

    now_str = datetime.now().strftime('%d.%m.%Y %H:%M')
    if is_test:
        subject = subject or "🔔 Lizenzmanager – Test-E-Mail"
    else:
        subject = subject or f"⚠️ Lizenzmanager: {len(licenses_list)} anstehende Lizenzfrist(en)"

    # Plain-Text Aufbau
    text_lines = [
        subject,
        f"Zeitpunkt: {now_str} Uhr",
        "-" * 60
    ]
    if is_test and not licenses_list:
        text_lines.append("Ihre SMTP-E-Mail-Konfiguration im Lizenzmanager funktioniert einwandfrei.")
        text_lines.append("Künftige Fristenwarnungen werden automatisch an diese Adresse zugestellt.")
    else:
        for lic in licenses_list:
            text_lines.append(
                f"• {lic.get('name')} ({lic.get('vendor') or '-'}) | "
                f"Status: {lic.get('badge_label')} | "
                f"Kündigungsfrist: {_format_date_de(lic.get('cancellation_deadline'))} | "
                f"Ablauf: {_format_date_de(lic.get('expiration_date'))} | "
                f"Kosten: {_format_currency_de(lic.get('cost'), lic.get('currency', 'EUR'))}"
            )

    # HTML Aufbau
    rows_html = ""
    for lic in licenses_list:
        rows_html += f"""
        <tr>
          <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; font-weight:600; color:#0f172a;">{lic.get('name', '-')}</td>
          <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; color:#475569;">{lic.get('vendor') or '-'}</td>
          <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; color:#b91c1c; font-weight:600;">{lic.get('badge_label') or '-'}</td>
          <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; color:#0f172a;">{_format_date_de(lic.get('cancellation_deadline'))}</td>
          <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; color:#0f172a;">{_format_date_de(lic.get('expiration_date'))}</td>
          <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; text-align:right; font-weight:600;">{_format_currency_de(lic.get('cost'), lic.get('currency', 'EUR'))}</td>
        </tr>
        """

    if is_test and not licenses_list:
        body_content_html = """
        <div style="padding:16px; background:#f0fdf4; border:1px solid #bbf7d0; border-radius:6px; color:#166534; font-size:14px;">
          <strong>✅ Verbindungstest erfolgreich!</strong><br>
          Ihre SMTP-Einstellungen im Lizenzmanager wurden erfolgreich getestet. Künftige Kündigungsfristen und Lizenzverlängerungen werden automatisch per E-Mail gemeldet.
        </div>
        """
    else:
        body_content_html = f"""
        <p style="font-size:14px; color:#475569; margin-bottom:16px;">
          Folgende Lizenzen erfordern Ihre Aufmerksamkeit (anstehende Kündigungsfrist oder Ablaufdatum):
        </p>
        <table style="width:100%; border-collapse:collapse; font-size:13px; text-align:left;">
          <thead>
            <tr style="background:#f1f5f9; color:#334155;">
              <th style="padding:10px 12px; border-bottom:2px solid #cbd5e1;">Lizenz</th>
              <th style="padding:10px 12px; border-bottom:2px solid #cbd5e1;">Hersteller</th>
              <th style="padding:10px 12px; border-bottom:2px solid #cbd5e1;">Status / Frist</th>
              <th style="padding:10px 12px; border-bottom:2px solid #cbd5e1;">Kündigungsstichtag</th>
              <th style="padding:10px 12px; border-bottom:2px solid #cbd5e1;">Ablaufdatum</th>
              <th style="padding:10px 12px; border-bottom:2px solid #cbd5e1; text-align:right;">Kosten</th>
            </tr>
          </thead>
          <tbody>
            {rows_html}
          </tbody>
        </table>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="de">
    <body style="font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background:#f8fafc; padding:24px; margin:0;">
      <div style="max-width:780px; margin:0 auto; background:#ffffff; border:1px solid #e2e8f0; border-radius:8px; overflow:hidden;">
        <div style="background:#0f172a; color:#ffffff; padding:16px 24px;">
          <h2 style="margin:0; font-size:18px;">{subject}</h2>
          <div style="font-size:12px; color:#94a3b8; margin-top:4px;">Lizenzmanager Benachrichtigungsdienst • {now_str} Uhr</div>
        </div>
        <div style="padding:24px;">
          {body_content_html}
        </div>
      </div>
    </body>
    </html>
    """

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ", ".join(recipients)
    msg.set_content("\n".join(text_lines))
    msg.add_alternative(html_content, subtype='html')

    try:
        context = ssl.create_default_context()
        if security == 'ssl':
            with smtplib.SMTP_SSL(host, port, timeout=12, context=context) as server:
                if user and password:
                    server.login(user, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=12) as server:
                server.ehlo()
                if security == 'starttls':
                    server.starttls(context=context)
                    server.ehlo()
                if user and password:
                    server.login(user, password)
                server.send_message(msg)
        return True, f"E-Mail erfolgreich an {', '.join(recipients)} gesendet."
    except Exception as e:
        raise RuntimeError(f"SMTP-Fehler beim E-Mail-Versand: {str(e)}")


def _parse_thresholds(notify_days_str):
    thresholds = []
    for part in str(notify_days_str or '30,14,7,3,1').split(','):
        part = part.strip()
        if part.isdigit():
            val = int(part)
            if 0 <= val <= 365:
                thresholds.append(val)
    if not thresholds:
        thresholds = [30, 14, 7, 3, 1]
    return sorted(set(thresholds), reverse=True)


def check_and_send_due_notifications(manual_trigger=False):
    """
    Prüft alle aktiven Lizenzen auf anstehende Kündigungsfristen / Ablauftermine
    und versendet Benachrichtigungen über aktivierte Kanäle (Teams & E-Mail).
    """
    settings = database.get_notification_settings(mask_password=False)
    teams_on = settings.get('teams_enabled') and bool(settings.get('teams_webhook_url'))
    email_on = settings.get('email_enabled') and bool(settings.get('smtp_host'))

    if not teams_on and not email_on:
        return {
            'success': False,
            'sent': False,
            'message': 'Weder Microsoft Teams noch E-Mail-Benachrichtigungen sind aktuell aktiviert.'
        }

    thresholds = _parse_thresholds(settings.get('notify_days'))
    max_days = max(thresholds) if thresholds else 30

    licenses = database.get_all_licenses(status_filter='active')
    due_licenses = []

    for lic in licenses:
        if lic.get('billing_cycle') == 'once' or not lic.get('expiration_date'):
            continue

        days_canc = lic.get('days_until_cancellation')
        days_exp = lic.get('days_until_expiration')
        auto_ren = bool(lic.get('auto_renewal'))

        effective_days = days_canc if (auto_ren and days_canc is not None) else days_exp
        if effective_days is None:
            continue

        if effective_days <= max_days:
            # Passenden Schwellenwert-Bucket bestimmen (z. B. <= 3, <= 7, <= 14, <= 30)
            matched_bucket = max_days
            for t in sorted(thresholds):
                if effective_days <= t:
                    matched_bucket = t
                    break
            if effective_days < 0:
                matched_bucket = -1

            lic_copy = dict(lic)
            lic_copy['_alert_bucket'] = matched_bucket
            due_licenses.append(lic_copy)

    if not due_licenses:
        return {
            'success': True,
            'sent': False,
            'due_count': 0,
            'message': f'Aktuell stehen keine Lizenzen innerhalb des {max_days}-Tage-Warnfensters zur Verlängerung/Kündigung an.'
        }

    results = []
    sent_any = False

    if teams_on:
        to_send_teams = []
        for lic in due_licenses:
            alert_key = f"lic_{lic['id']}_exp_{lic.get('expiration_date')}_b_{lic['_alert_bucket']}_teams"
            if manual_trigger or not database.has_notification_been_sent(alert_key):
                to_send_teams.append((lic, alert_key))

        if to_send_teams:
            lic_objs = [item[0] for item in to_send_teams]
            ok, msg = send_teams_notification(settings['teams_webhook_url'], lic_objs, is_test=False)
            if ok:
                sent_any = True
                for lic, a_key in to_send_teams:
                    database.mark_notification_sent(lic['id'], a_key, 'teams')
            results.append(msg)

    if email_on:
        to_send_email = []
        for lic in due_licenses:
            alert_key = f"lic_{lic['id']}_exp_{lic.get('expiration_date')}_b_{lic['_alert_bucket']}_email"
            if manual_trigger or not database.has_notification_been_sent(alert_key):
                to_send_email.append((lic, alert_key))

        if to_send_email:
            lic_objs = [item[0] for item in to_send_email]
            ok, msg = send_email_notification(settings, lic_objs, is_test=False)
            if ok:
                sent_any = True
                for lic, a_key in to_send_email:
                    database.mark_notification_sent(lic['id'], a_key, 'email')
            results.append(msg)

    if not results:
        return {
            'success': True,
            'sent': False,
            'due_count': len(due_licenses),
            'message': 'Alle fälligen Lizenzen für den aktuellen Schwellenwert wurden bereits benachrichtigt.'
        }

    return {
        'success': True,
        'sent': sent_any,
        'due_count': len(due_licenses),
        'message': " | ".join(results)
    }
