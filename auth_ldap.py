"""
Active Directory (LDAP) Authentifizierungsmodul für den Lizenzmanager.
Prüft Anmeldedaten gegen einen Windows Server Domain Controller und ermittelt
Benutzerattribute sowie AD-Gruppenmitgliedschaften.
"""

import re
import logging
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError, LDAPBindError
from ldap3.utils.conv import escape_filter_chars
import config

logger = logging.getLogger('auth_ldap')

def clean_username(raw_username: str):
    """
    Bereinigt den Benutzernamen und extrahiert den reinen Accountnamen (sAMAccountName).
    Gibt (bind_username, plain_username) zurück.
    """
    raw = raw_username.strip()
    
    if '\\' in raw:
        domain_part, user_part = raw.split('\\', 1)
        return raw, user_part
    elif '@' in raw:
        user_part, domain_part = raw.split('@', 1)
        return raw, user_part
    else:
        # Standard: Domäne voranstellen
        domain = config.LDAP_DOMAIN
        if '.' in domain:
            # UPN-Format (user@domain.local)
            bind_user = f"{raw}@{domain}"
        else:
            # NetBIOS-Format (DOMÄNE\\user)
            bind_user = f"{domain}\\{raw}"
        return bind_user, raw


def _extract_cn(dn_string: str) -> str:
    """Extrahiert den Common Name (CN) aus einem Distinguished Name (DN)."""
    match = re.search(r'CN=([^,]+)', dn_string, re.IGNORECASE)
    return match.group(1) if match else dn_string


def authenticate_user(username: str, password: str):
    """
    Authentifiziert einen Benutzer gegen das Active Directory.
    
    Rückgabe: (success: bool, user_info: dict, error_message: str)
    """
    if not username or not password:
        return False, None, "Bitte geben Sie Benutzername und Kennwort ein."

    bind_user, plain_username = clean_username(username)

    # -------------------------------------------------------------------------
    # NOTFALL-FALLBACK (NUR WENN EXPLIZIT IN .ENV AKTIVIERT)
    # -------------------------------------------------------------------------
    if config.ALLOW_DEMO_FALLBACK:
        expected_user = (getattr(config, 'LOCAL_ADMIN_USER', 'admin') or 'admin').lower()
        expected_pwd = getattr(config, 'LOCAL_ADMIN_PASSWORD', '')
        # Falls kein Kennwort via .env definiert ist, Standard 'admin' nur bei explizitem Fallback
        if not expected_pwd:
            expected_pwd = 'admin'
        if plain_username.lower() == expected_user and password == expected_pwd:
            logger.warning(f"Lokaler Notfall-Login für Benutzer '{plain_username}' verwendet.")
            return True, {
                'username': plain_username,
                'display_name': f'Administrator ({plain_username} - Notfall-Login)',
                'email': f'{plain_username}@localhost',
                'is_admin': True,
                'groups': ['Lizenz-Admins'],
                'auth_method': 'demo_fallback'
            }, None

    # -------------------------------------------------------------------------
    # ACTIVE DIRECTORY LDAP VERBINDUNG
    # -------------------------------------------------------------------------
    try:
        server = Server(
            host=config.LDAP_HOST,
            port=config.LDAP_PORT,
            use_ssl=config.LDAP_USE_SSL,
            get_info=ALL,
            connect_timeout=4
        )
        
        conn = Connection(
            server=server,
            user=bind_user,
            password=password,
            auto_bind=False,
            raise_exceptions=False
        )

        bound = conn.bind()
        
        if not bound:
            error_desc = conn.result.get('description', '')
            error_msg = conn.result.get('message', '')
            logger.warning(f"AD Bind fehlgeschlagen für {bind_user}: {error_desc} / {error_msg}")
            
            # Einheitliche Meldung verhindert Benutzer-Enumeration im Active Directory
            return False, None, "Benutzername oder Kennwort ist ungültig."

        # ---------------------------------------------------------------------
        # BENUTZERDETAILS & GRUPPEN ERMITTELN
        # ---------------------------------------------------------------------
        display_name = plain_username
        email = f"{plain_username}@{config.LDAP_DOMAIN.lower()}"
        groups = []

        try:
            # LDAP Injection Schutz: Filter-Zeichen maskieren
            escaped_username = escape_filter_chars(plain_username)
            search_filter = f"(&(objectClass=user)(sAMAccountName={escaped_username}))"
            search_base = config.LDAP_SEARCH_BASE

            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['displayName', 'mail', 'memberOf', 'sAMAccountName', 'givenName', 'sn']
            )

            if conn.entries:
                entry = conn.entries[0]
                if hasattr(entry, 'displayName') and entry.displayName.value:
                    display_name = str(entry.displayName.value)
                elif hasattr(entry, 'givenName') and hasattr(entry, 'sn'):
                    display_name = f"{entry.givenName.value or ''} {entry.sn.value or ''}".strip() or plain_username

                if hasattr(entry, 'mail') and entry.mail.value:
                    email = str(entry.mail.value)

                if hasattr(entry, 'memberOf') and entry.memberOf.values:
                    # Gruppen-DNs auslesen und lesbare CNs extrahieren
                    raw_groups = list(entry.memberOf.values)
                    groups = [_extract_cn(g) for g in raw_groups]
        except Exception as search_err:
            logger.warning(f"AD-Benutzersuche für Details fehlgeschlagen: {search_err}")

        # Verbindung ordnungsgemäß trennen
        try:
            conn.unbind()
        except Exception:
            pass

        # ---------------------------------------------------------------------
        # ZUGRIFFS- & ROLLENPRÜFUNG
        # ---------------------------------------------------------------------
        # 1. Muss der Benutzer in einer bestimmten Gruppe sein?
        if config.LDAP_REQUIRED_GROUP:
            req_group = config.LDAP_REQUIRED_GROUP.strip().lower()
            user_group_names = [g.lower() for g in groups]
            if req_group not in user_group_names:
                return False, None, f"Zugriff verweigert: Sie müssen Mitglied der AD-Gruppe '{config.LDAP_REQUIRED_GROUP}' sein."

        # 2. Ist der Benutzer Administrator? (Fail-Closed: Standard ist False!)
        is_admin = False
        if config.LDAP_ADMIN_GROUP:
            admin_group = config.LDAP_ADMIN_GROUP.strip().lower()
            user_group_names = [g.lower() for g in groups]
            is_admin = (admin_group in user_group_names)

        user_info = {
            'username': plain_username,
            'display_name': display_name,
            'email': email,
            'is_admin': is_admin,
            'groups': groups,
            'auth_method': 'ldap'
        }

        return True, user_info, None

    except LDAPSocketOpenError as socket_err:
        logger.error(f"Domain Controller nicht erreichbar ({config.LDAP_HOST}:{config.LDAP_PORT}): {socket_err}")
        return False, None, (
            f"Active Directory Server ({config.LDAP_HOST}:{config.LDAP_PORT}) ist nicht erreichbar. "
            "Bitte prüfen Sie die Netzwerkverbindung (LAN/VPN) oder die Einstellungen in config.py."
        )
    except LDAPException as ldap_err:
        logger.error(f"LDAP-Fehler: {ldap_err}")
        return False, None, f"LDAP-Kommunikationsfehler: {str(ldap_err)}"
    except Exception as general_err:
        logger.exception(f"Unerwarteter Fehler bei AD-Authentifizierung: {general_err}")
        return False, None, f"Fehler bei der Authentifizierung: {str(general_err)}"
