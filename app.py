# app.py
"""Secure military communication chat - entry point.

Modules
  core.py         Flask app, Socket.IO, keys, encrypted audit trail, error pages
  auth.py         role-separated login portals, two-step login, first-login activation
  accounts.py     account creation (admin: any role, officer: soldiers), deletion
  chat.py         encrypted real-time chat: channels, direct messages, presence
  admin.py        accounts, login dashboard, suspicious activity, audit trail,
                  message vault
  permissions.py  role-based access control rules
  security.py     CSRF, headers, rate limiting, validation, revocable sessions
  encryption_utils.py  RSA-OAEP, AES-GCM, sealing at rest, TLS certificate
"""
import os

from core import SERVER_FINGERPRINT, app, log, socketio
from encryption_utils import ensure_self_signed_cert

import auth      # noqa: F401,E402  (registers routes)
import accounts  # noqa: F401,E402
import chat      # noqa: F401,E402
import admin     # noqa: F401,E402

if __name__ == '__main__':
    ssl_context = None
    if app.config['USE_TLS']:
        cert = app.config['TLS_CERT_FILE'] or os.path.join(app.instance_path, 'tls', 'cert.pem')
        key = app.config['TLS_KEY_FILE'] or os.path.join(app.instance_path, 'tls', 'key.pem')
        if not app.config['TLS_CERT_FILE']:
            ensure_self_signed_cert(cert, key)
        ssl_context = (cert, key)
    else:
        log.warning('USE_TLS=0: traffic is only protected by the app-level message encryption')

    scheme = 'https' if ssl_context else 'http'
    log.info('Server key fingerprint: %s', SERVER_FINGERPRINT)
    log.info('Open %s://%s:%s', scheme, 'localhost' if app.config['APP_HOST'] in ('127.0.0.1', '0.0.0.0')
             else app.config['APP_HOST'], app.config['APP_PORT'])
    socketio.run(app, host=app.config['APP_HOST'], port=app.config['APP_PORT'],
                 debug=app.config['DEBUG'], use_reloader=app.config['DEBUG'],
                 ssl_context=ssl_context, allow_unsafe_werkzeug=True)
