# auth.py
"""Role-separated login portals (soldier / officer / admin), two-step login
(password -> OTP), first-login activation, first-admin setup and logout.

Every attempt - successful or not, and why it failed - goes to the audit trail."""
import hmac
import io
import time

import bcrypt
import pyotp
import qrcode
import qrcode.image.svg
from flask import abort, flash, redirect, render_template, request, session, url_for

import db
import security
from accounts import hash_password, otp_context
from chat import disconnect_sockets
from core import DATA_KEY, app, audit
from encryption_utils import b64e, is_sealed, seal, unseal
from permissions import ROLE_INFO, ROLES, home_endpoint
from security import OTP_RE, client_ip, current_user, login_user, sessions

# Used to keep login timing the same whether or not the username exists.
DUMMY_HASH = bcrypt.hashpw(b'timing-equaliser-not-a-real-password', bcrypt.gensalt())
PENDING_SECONDS = 5 * 60
ACTIVATION_SECONDS = 15 * 60
MAX_OTP_TRIES = 3

USER_COLUMNS = ('id, username, password, role, otp_secret, totp_confirmed, last_otp_step, '
                'failed_attempts, must_change_password, '
                '(locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked, '
                '(password_expires IS NOT NULL AND password_expires < NOW()) AS temp_expired')


# ---------------------------------------------------------------- helpers

def find_user(username=None, user_id=None):
    """Active (not deleted) account by name or id."""
    with db.cursor() as cur:
        if user_id is not None:
            cur.execute(f'SELECT {USER_COLUMNS} FROM users WHERE id = %s AND deleted_at IS NULL', (user_id,))
        else:
            cur.execute(f'SELECT {USER_COLUMNS} FROM users WHERE username = %s AND deleted_at IS NULL',
                        (username,))
        return cur.fetchone()


def active_user_count():
    with db.cursor() as cur:
        cur.execute('SELECT COUNT(*) AS n FROM users WHERE deleted_at IS NULL')
        return cur.fetchone()['n']


def get_otp_secret(user):
    """Decrypt the stored TOTP secret; secrets from the old app are stored in plain text."""
    if is_sealed(user['otp_secret']):
        return unseal(DATA_KEY, user['otp_secret'], otp_context(user['username']))
    return user['otp_secret']


def verify_totp(secret, code, last_step):
    """Return the matched time-step, or None. Accepts +/-1 step of clock drift and
    rejects any step already used (stops replay of an observed code)."""
    if not OTP_RE.fullmatch(code or ''):
        return None
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // totp.interval
    for step in (now_step - 1, now_step, now_step + 1):
        if step > (last_step or 0) and hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def qr_data_uri(text):
    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=8)
    buf = io.BytesIO()
    img.save(buf)
    return 'data:image/svg+xml;base64,' + b64e(buf.getvalue())


def record_failed_login(user, event, detail):
    """Count a failed attempt against the account; lock it after too many."""
    max_fail, minutes = app.config['MAX_FAILED_LOGINS'], app.config['LOCKOUT_MINUTES']
    with db.cursor() as cur:
        # locked_until is assigned first so it sees the old failed_attempts value.
        cur.execute('UPDATE users SET '
                    'locked_until = IF(failed_attempts + 1 >= %s, NOW() + INTERVAL %s MINUTE, locked_until), '
                    'failed_attempts = IF(failed_attempts + 1 >= %s, 0, failed_attempts + 1) '
                    'WHERE id = %s', (max_fail, minutes, max_fail, user['id']))
    audit(event, user['username'], detail)
    if user['failed_attempts'] + 1 >= max_fail:
        audit('account_locked', user['username'], f'{max_fail} failed attempts; locked {minutes} min')
        return True
    return False


def portal_or_404(role):
    if role not in ROLES:
        abort(404)
    return role


def login_failed(portal, username=''):
    # One generic message: never reveal which factor was wrong or whether the user exists.
    flash('Login failed: invalid credentials, wrong login portal, or account temporarily locked.', 'danger')
    return render_template('login_portal.html', portal=portal, info=ROLE_INFO[portal],
                           username=username), 401


# ---------------------------------------------------------------- landing / portals

@app.route('/')
def home():
    user = current_user()
    return redirect(url_for(home_endpoint(user['role']) if user else 'login'))


@app.route('/dashboard')
def dashboard():
    return home()


@app.route('/login')
def login():
    if current_user():
        return home()
    if active_user_count() == 0:
        return redirect(url_for('setup'))
    return render_template('login.html', roles=ROLES)


@app.route('/login/<role>', methods=['GET', 'POST'])
def login_portal(role):
    """Step 1 of 2: username + password, only for accounts of this portal's role."""
    portal = portal_or_404(role)
    if current_user():
        return home()
    if request.method == 'GET':
        return render_template('login_portal.html', portal=portal, info=ROLE_INFO[portal])

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').encode('utf-8')

    if not security.login_limiter.hit(client_ip()):
        audit('login_rate_limited', username[:64], f'portal={portal}')
        flash('Too many login attempts. Wait a few minutes and try again.', 'danger')
        return render_template('login_portal.html', portal=portal, info=ROLE_INFO[portal]), 429

    user = find_user(username) if security.valid_username(username) else None
    # Always run bcrypt so response time does not reveal whether the user exists.
    stored_hash = user['password'].encode('utf-8') if user else DUMMY_HASH
    password_ok = len(password) <= 72 and bcrypt.checkpw(password, stored_hash)

    if user is None:
        audit('login_failed', username[:64], f'unknown user (portal={portal})')
        return login_failed(portal, username)
    if user['is_locked']:
        audit('login_while_locked', user['username'], f'portal={portal}')
        return login_failed(portal, username)
    if not password_ok:
        record_failed_login(user, 'login_failed', f'wrong password (portal={portal})')
        return login_failed(portal, username)
    if user['role'] != portal:
        record_failed_login(user, 'login_failed',
                            f"wrong portal: {user['role']} account tried the {portal} login")
        return login_failed(portal, username)

    session.clear()
    if user['must_change_password'] or not user['totp_confirmed']:
        if user['must_change_password'] and user['temp_expired']:
            audit('login_failed', user['username'], 'temporary password expired')
            flash('Your temporary password has expired. Ask for your account to be reset.', 'warning')
            return render_template('login_portal.html', portal=portal, info=ROLE_INFO[portal]), 401
        session['activation'] = {'user_id': user['id'], 'expires': time.time() + ACTIVATION_SECONDS}
        audit('activation_started', user['username'], f'portal={portal}')
        return redirect(url_for('activate'))

    session['pending_login'] = {'user_id': user['id'], 'portal': portal, 'tries': 0,
                                'expires': time.time() + PENDING_SECONDS}
    return redirect(url_for('login_verify'))


@app.route('/login/verify', methods=['GET', 'POST'])
def login_verify():
    """Step 2 of 2: one-time code from the authenticator app."""
    pending = session.get('pending_login')
    if not pending or pending['expires'] < time.time():
        session.pop('pending_login', None)
        flash('Your login timed out. Please enter your password again.', 'warning')
        return redirect(url_for('login'))
    portal = pending['portal']

    user = find_user(user_id=pending['user_id'])
    if user is None or user['is_locked'] or user['role'] != portal:
        session.pop('pending_login', None)
        return login_failed(portal)

    if request.method == 'POST':
        if not security.login_limiter.hit(client_ip()):
            abort(429)
        step = verify_totp(get_otp_secret(user), request.form.get('otp', '').strip().replace(' ', ''),
                           user['last_otp_step'])
        if step:
            with db.cursor() as cur:
                cur.execute('UPDATE users SET failed_attempts = 0, locked_until = NULL, '
                            'last_otp_step = %s, last_login = NOW() WHERE id = %s', (step, user['id']))
                if not is_sealed(user['otp_secret']):   # upgrade legacy plain-text secret
                    cur.execute('UPDATE users SET otp_secret = %s WHERE id = %s',
                                (seal(DATA_KEY, get_otp_secret(user), otp_context(user['username'])),
                                 user['id']))
            login_user(user)
            audit('login_success', user['username'], f'portal={portal}')
            return redirect(url_for(home_endpoint(user['role'])))

        locked = record_failed_login(user, 'otp_failed', f'wrong one-time code (portal={portal})')
        pending['tries'] += 1
        session['pending_login'] = pending
        if locked or pending['tries'] >= MAX_OTP_TRIES:
            session.pop('pending_login', None)
            return login_failed(portal, user['username'])
        flash('That code is not correct. Wait for a new code and try again.', 'danger')

    return render_template('login_verify.html', username=user['username'], portal=portal,
                           info=ROLE_INFO[portal])


# ---------------------------------------------------------------- first login / first admin

@app.route('/activate', methods=['GET', 'POST'])
def activate():
    """First login: choose a password (if a temporary one was issued) and enrol 2FA."""
    pending = session.get('activation')
    if not pending or pending['expires'] < time.time():
        session.pop('activation', None)
        flash('Activation timed out. Log in again with your temporary password.', 'warning')
        return redirect(url_for('login'))
    user = find_user(user_id=pending['user_id'])
    if user is None:
        session.pop('activation', None)
        return redirect(url_for('login'))
    secret = get_otp_secret(user)
    needs_password = bool(user['must_change_password'])

    if request.method == 'POST':
        if not security.otp_setup_limiter.hit(client_ip()):
            abort(429)
        errors = []
        new_password = request.form.get('password', '')
        if needs_password:
            problems = security.password_problems(new_password, user['username'])
            if problems:
                errors.append('Password needs: ' + ', '.join(problems) + '.')
            elif new_password != request.form.get('confirm_password', ''):
                errors.append('Passwords do not match.')
            elif bcrypt.checkpw(new_password.encode('utf-8'), user['password'].encode('utf-8')):
                errors.append('Choose a new password, not the temporary one.')
        step = None if errors else verify_totp(
            secret, request.form.get('otp', '').strip().replace(' ', ''), 0)
        if not errors and not step:
            errors.append('That code is not correct. Check the time on your phone and try again.')
        if not errors:
            with db.cursor() as cur:
                if needs_password:
                    cur.execute('UPDATE users SET password = %s WHERE id = %s',
                                (hash_password(new_password), user['id']))
                cur.execute('UPDATE users SET totp_confirmed = 1, last_otp_step = %s, must_change_password = 0, '
                            'password_expires = NULL, failed_attempts = 0 WHERE id = %s', (step, user['id']))
            session.pop('activation', None)
            audit('account_activated', user['username'], f"role={user['role']}")
            flash('Your account is active. Log in with your new password and a code from your app.', 'success')
            return redirect(url_for('login_portal', role=user['role']))
        for e in errors:
            flash(e, 'danger')

    uri = pyotp.TOTP(secret).provisioning_uri(name=user['username'], issuer_name='SecureComm')
    return render_template('activate.html', qr=qr_data_uri(uri), secret=secret, username=user['username'],
                           role=user['role'], needs_password=needs_password)


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Create the first admin. Only available while the system has no accounts."""
    if active_user_count() > 0:
        abort(404)
    if request.method == 'POST':
        if not security.register_limiter.hit(client_ip()):
            abort(429)
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        errors = []
        if not security.valid_username(username):
            errors.append('Username must be 3-32 characters: letters, digits, "_", "." or "-".')
        problems = security.password_problems(password, username)
        if problems:
            errors.append('Password needs: ' + ', '.join(problems) + '.')
        if password != request.form.get('confirm_password', ''):
            errors.append('Passwords do not match.')
        if not errors:
            with db.cursor() as cur:
                cur.execute("INSERT INTO users (username, password, role, otp_secret, totp_confirmed, created_by) "
                            "VALUES (%s, %s, 'admin', %s, 0, 'setup')",
                            (username, hash_password(password),
                             seal(DATA_KEY, pyotp.random_base32(), otp_context(username))))
                user_id = cur.lastrowid
            audit('account_created', username, 'role=admin by=initial setup')
            session.clear()
            session['activation'] = {'user_id': user_id, 'expires': time.time() + ACTIVATION_SECONDS}
            return redirect(url_for('activate'))
        for e in errors:
            flash(e, 'danger')
        return render_template('setup.html', username=username), 400
    return render_template('setup.html')


@app.route('/logout', methods=['POST'])
def logout():
    token = session.get('auth')
    user = current_user()
    if token:
        sessions.revoke(token)
        disconnect_sockets(lambda c: c.token == token)
    if user:
        audit('logout', user['username'])
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))
