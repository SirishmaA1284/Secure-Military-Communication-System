# security.py
"""Web security layers: CSRF, security headers, rate limiting, input validation,
server-side (revocable) sessions with idle timeout, and access-control decorators."""
import hmac
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, current_app, flash, g, redirect, request, session, url_for

from permissions import ROLES, has_permission  # noqa: F401  (ROLES re-exported)
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,32}$')
OTP_RE = re.compile(r'^\d{6}$')
CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]')


# ---------------------------------------------------------------- input validation

def valid_username(username: str) -> bool:
    return bool(USERNAME_RE.fullmatch(username or ''))


def password_problems(password: str, username: str) -> list:
    """Return a list of policy violations (empty list = acceptable)."""
    problems = []
    if len(password) < 12:
        problems.append('at least 12 characters')
    if len(password.encode('utf-8')) > 72:
        problems.append('at most 72 bytes (bcrypt limit)')
    if not re.search(r'[a-z]', password) or not re.search(r'[A-Z]', password):
        problems.append('upper- and lower-case letters')
    if not re.search(r'\d', password):
        problems.append('a digit')
    if not re.search(r'[^A-Za-z0-9]', password):
        problems.append('a symbol')
    if username and username.lower() in password.lower():
        problems.append('must not contain the username')
    return problems


def clean_message(text) -> str:
    """Normalise a chat message: strip control / bidi-override characters and whitespace."""
    if not isinstance(text, str):
        return ''
    return CONTROL_CHARS_RE.sub('', text).strip()


# ---------------------------------------------------------------- rate limiting

class RateLimiter:
    """In-memory sliding-window limiter: at most `limit` hits per `window` seconds per key."""

    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


login_limiter = RateLimiter(limit=10, window=300)      # per IP
register_limiter = RateLimiter(limit=5, window=3600)   # per IP
otp_setup_limiter = RateLimiter(limit=10, window=300)  # per IP
message_limiter = RateLimiter(limit=10, window=10)     # per user
history_limiter = RateLimiter(limit=30, window=10)     # per user (opening chats)


def client_ip() -> str:
    # Deliberately ignores X-Forwarded-For, which a client can forge.
    return request.remote_addr or 'unknown'


# ---------------------------------------------------------------- server-side sessions

class SessionStore:
    """Tracks live logins server-side so they can be revoked (logout, role change,
    restart) and expire after inactivity, even though Flask's cookie is client-side."""

    def __init__(self):
        self._sessions = {}
        self._lock = threading.Lock()

    def create(self, user_id, username, role) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[token] = {'user_id': user_id, 'username': username,
                                     'role': role, 'last_seen': time.time()}
        return token

    def get(self, token, touch=True):
        if not token:
            return None
        idle = current_app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()
        with self._lock:
            data = self._sessions.get(token)
            if data is None:
                return None
            if time.time() - data['last_seen'] > idle:
                del self._sessions[token]
                return None
            if touch:
                data['last_seen'] = time.time()
            return dict(data)

    def revoke(self, token):
        with self._lock:
            self._sessions.pop(token, None)

    def revoke_user(self, user_id) -> list:
        with self._lock:
            tokens = [t for t, d in self._sessions.items() if d['user_id'] == user_id]
            for t in tokens:
                del self._sessions[t]
        return tokens


sessions = SessionStore()


def login_user(user) -> str:
    """Start a fresh session (prevents session fixation) for a verified user row."""
    session.clear()
    session.permanent = True
    token = sessions.create(user['id'], user['username'], user['role'])
    session['auth'] = token
    return token


def current_user():
    if 'user' not in g:
        g.user = sessions.get(session.get('auth'))
    return g.user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            session.pop('auth', None)
            flash('Please log in.', 'warning')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user()['role'] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def permission_required(permission):
    """Allow the view only for roles holding `permission` (see permissions.py)."""
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if not has_permission(current_user()['role'], permission):
                abort(403, description='Your role does not have access to this page.')
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------- CSRF

def csrf_token() -> str:
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(32)
    return session['csrf']


def check_csrf():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        sent = request.form.get('csrf_token', '')
        expected = session.get('csrf', '')
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, description='Invalid or missing CSRF token. Reload the page and try again.')


# ---------------------------------------------------------------- headers

def set_security_headers(response):
    host = request.host
    ws = f"wss://{host}" if request.is_secure else f"ws://{host}"
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        f"connect-src 'self' {ws}; font-src 'self'; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    if request.is_secure and request.host.split(':')[0] not in ('localhost', '127.0.0.1'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    if response.mimetype == 'text/html':
        # Authenticated pages (and the OTP setup QR code) must not be cached.
        response.headers['Cache-Control'] = 'no-store'
    return response


def init_app(app):
    app.before_request(check_csrf)
    app.after_request(set_security_headers)
    app.jinja_env.globals['csrf_token'] = csrf_token
    app.jinja_env.globals['current_user'] = current_user
    app.jinja_env.globals['has_permission'] = has_permission
