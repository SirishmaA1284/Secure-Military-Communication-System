# core.py
"""Shared application objects: Flask app, Socket.IO, keys, audit trail, error pages.
Feature modules (auth.py, chat.py, admin.py) import from here."""
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from datetime import timezone

import mysql.connector
from flask import Flask, has_request_context, render_template
from flask_socketio import SocketIO
from werkzeug.exceptions import HTTPException

import db
import security
from encryption_utils import (b64d, b64e, is_sealed, load_or_create_rsa_key, public_key_fingerprint,
                              public_key_spki_b64, seal, unseal, write_private_file)
from permissions import ROLE_INFO, can_manage, home_endpoint
from security import client_ip

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
log = logging.getLogger('securecomm')

app = Flask(__name__, instance_relative_config=True)
app.config.from_pyfile('config.py')
os.makedirs(app.instance_path, exist_ok=True)


def load_secrets():
    """Use secrets from the environment, or generate strong ones once and keep them in
    instance/secrets.json (owner-only file) so they survive restarts."""
    path = os.path.join(app.instance_path, 'secrets.json')
    stored = {}
    if os.path.exists(path):
        with open(path, encoding='utf-8') as f:
            stored = json.load(f)
    generators = {
        'SECRET_KEY': lambda: secrets.token_hex(32),
        'DATA_ENCRYPTION_KEY': lambda: b64e(secrets.token_bytes(32)),
        'RSA_KEY_PASSPHRASE': lambda: secrets.token_urlsafe(32),
    }
    changed = False
    for name, generate in generators.items():
        if app.config.get(name):
            continue
        if name not in stored:
            stored[name] = generate()
            changed = True
        app.config[name] = stored[name]
    if changed:
        write_private_file(path, json.dumps(stored, indent=2).encode('utf-8'))
        log.info('Generated new secrets in %s - keep this file private and backed up', path)


load_secrets()
DATA_KEY = b64d(app.config['DATA_ENCRYPTION_KEY'])
if len(DATA_KEY) != 32:
    raise RuntimeError('DATA_ENCRYPTION_KEY must be 32 bytes (base64-encoded)')

SERVER_KEY = load_or_create_rsa_key(os.path.join(app.instance_path, 'server_rsa.pem'),
                                    app.config['RSA_KEY_PASSPHRASE'])
SERVER_PUBLIC_SPKI = public_key_spki_b64(SERVER_KEY)
SERVER_FINGERPRINT = public_key_fingerprint(SERVER_KEY)

if app.config['USE_TLS']:
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_NAME'] = '__Host-session'

db.init_app(app)
security.init_app(app)
app.jinja_env.globals.update(ROLE_INFO=ROLE_INFO, can_manage=can_manage, home_endpoint=home_endpoint)

# cors_allowed_origins left at its default: only same-origin pages may open a socket.
socketio = SocketIO(app, async_mode='threading', max_http_buffer_size=64 * 1024)


def utc_iso(dt):
    return dt.replace(tzinfo=timezone.utc).isoformat()


# ---------------------------------------------------------------- encrypted, hash-chained audit trail

# Each entry stores HMAC(prev_hash | fields). Editing, deleting or reordering any stored
# entry breaks the chain, so the log can be trusted later as evidence.
AUDIT_CHAIN_KEY = hmac.new(DATA_KEY, b'audit-chain-v1', hashlib.sha256).digest()
_audit_lock = threading.Lock()


def _audit_hash(prev, event, username, ip, detail, created_at):
    fields = [prev or '', event, username or '', ip or '', detail or '',
              created_at.strftime('%Y-%m-%d %H:%M:%S')]
    return hmac.new(AUDIT_CHAIN_KEY, ''.join(fields).encode('utf-8'), hashlib.sha256).hexdigest()


def audit(event, username=None, detail=None):
    """Record a security event. The free-text detail is encrypted at rest; event, user,
    IP and time stay queryable for the login history and suspicious-activity monitor."""
    ip = client_ip() if has_request_context() else None
    username = (username or '')[:64] or None
    log.info('AUDIT %s user=%s ip=%s %s', event, username, ip, detail or '')
    sealed = seal(DATA_KEY, detail[:200], f'audit:{event}') if detail else None
    try:
        with _audit_lock, db.cursor() as cur:
            cur.execute('SELECT NOW() AS now')
            now = cur.fetchone()['now']
            cur.execute('SELECT row_hash FROM audit_log WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1')
            last = cur.fetchone()
            prev = last['row_hash'] if last else None
            cur.execute('INSERT INTO audit_log (event, username, ip, detail, created_at, prev_hash, row_hash) '
                        'VALUES (%s, %s, %s, %s, %s, %s, %s)',
                        (event, username, ip, sealed, now, prev,
                         _audit_hash(prev, event, username, ip, sealed, now)))
    except mysql.connector.Error:
        log.exception('Could not write audit log')


def verify_audit_chain():
    """Recompute the whole chain. Returns {'ok', 'checked', 'legacy', 'head', 'broken_id', 'reason'}."""
    with db.cursor() as cur:
        cur.execute('SELECT id, event, username, ip, detail, created_at, prev_hash, row_hash '
                    'FROM audit_log ORDER BY id')
        rows = cur.fetchall()
    prev, checked, legacy = None, 0, 0
    for row in rows:
        if row['row_hash'] is None:
            if prev is None:          # entries written before the chain existed
                legacy += 1
                continue
            return {'ok': False, 'checked': checked, 'legacy': legacy, 'broken_id': row['id'],
                    'reason': 'entry is missing its hash'}
        if row['prev_hash'] != prev:
            return {'ok': False, 'checked': checked, 'legacy': legacy, 'broken_id': row['id'],
                    'reason': 'an earlier entry was deleted or reordered'}
        expected = _audit_hash(prev, row['event'], row['username'], row['ip'], row['detail'],
                               row['created_at'])
        if not hmac.compare_digest(expected, row['row_hash']):
            return {'ok': False, 'checked': checked, 'legacy': legacy, 'broken_id': row['id'],
                    'reason': 'entry was modified'}
        prev = row['row_hash']
        checked += 1
    return {'ok': True, 'checked': checked, 'legacy': legacy, 'head': prev}


def audit_detail(row):
    """Decrypt an audit row's detail for display."""
    value = row.get('detail')
    if not value or not is_sealed(value):
        return value or ''
    try:
        return unseal(DATA_KEY, value, f"audit:{row['event']}")
    except ValueError:
        return '[integrity check failed]'


# ---------------------------------------------------------------- error pages

@app.errorhandler(mysql.connector.Error)
def database_error(e):
    log.error('Database error: %s', e)
    return render_template('error.html', code=503,
                           message='The database is unavailable. Please try again later.'), 503


@app.errorhandler(HTTPException)
def http_error(e):
    return render_template('error.html', code=e.code, message=e.description), e.code


@app.errorhandler(Exception)
def unhandled_error(e):
    log.exception('Unhandled error')   # details stay in the server log, not the browser
    return render_template('error.html', code=500, message='Something went wrong.'), 500
