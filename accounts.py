# accounts.py
"""Account lifecycle. There is no public sign-up: admins create any account, officers
create soldiers. A new account gets a one-time temporary password; at first login the
owner chooses their own password and enrols 2FA. Deleting deactivates the account but
keeps its row, so the username cannot be re-used and the audit trail stays complete."""
import secrets
import string

import bcrypt
import mysql.connector
import pyotp
from flask import abort, flash, redirect, render_template, request, url_for

import db
import security
from chat import force_logout_user
from core import DATA_KEY, app, audit
from encryption_utils import seal
from permissions import can_manage
from security import current_user, permission_required

TEMP_PASSWORD_HOURS = 24


def otp_context(username):
    return f'otp:{username}'


def temp_password():
    """Random one-time password, e.g. 'Kx7m-Qp2r-9TzA-b4Ne' (~95 bits)."""
    alphabet = string.ascii_letters + string.digits
    return '-'.join(''.join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4))


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')


def get_account(user_id):
    with db.cursor() as cur:
        cur.execute('SELECT id, username, role, deleted_at FROM users WHERE id = %s', (user_id,))
        return cur.fetchone()


def create_account(username, role):
    """Create an account as the current user. Returns (temporary_password, error)."""
    actor = current_user()
    if not can_manage(actor['role'], role):
        abort(403, description='Your role cannot create that kind of account.')
    if not security.valid_username(username):
        return None, 'Username must be 3-32 characters: letters, digits, "_", "." or "-".'
    password = temp_password()
    try:
        with db.cursor() as cur:
            cur.execute('INSERT INTO users (username, password, role, otp_secret, totp_confirmed, '
                        'must_change_password, password_expires, created_by) '
                        'VALUES (%s, %s, %s, %s, 0, 1, NOW() + INTERVAL %s HOUR, %s)',
                        (username, hash_password(password), role,
                         seal(DATA_KEY, pyotp.random_base32(), otp_context(username)),
                         TEMP_PASSWORD_HOURS, actor['username']))
    except mysql.connector.IntegrityError:
        return None, 'That username is already taken (deleted accounts keep their username).'
    audit('account_created', username, f"role={role} by={actor['username']}")
    return password, None


def reset_credentials(account):
    """New temporary password and new 2FA secret; the owner must activate again."""
    password = temp_password()
    with db.cursor() as cur:
        cur.execute('UPDATE users SET password = %s, otp_secret = %s, totp_confirmed = 0, '
                    'must_change_password = 1, password_expires = NOW() + INTERVAL %s HOUR, '
                    'failed_attempts = 0, locked_until = NULL, last_otp_step = 0 WHERE id = %s',
                    (hash_password(password),
                     seal(DATA_KEY, pyotp.random_base32(), otp_context(account['username'])),
                     TEMP_PASSWORD_HOURS, account['id']))
    force_logout_user(account['id'])
    audit('credentials_reset', account['username'], f"by={current_user()['username']}")
    return password


def deactivate(account):
    with db.cursor() as cur:
        # Replace the password hash with one for a random secret nobody knows.
        cur.execute('UPDATE users SET deleted_at = NOW(), password = %s WHERE id = %s AND deleted_at IS NULL',
                    (bcrypt.hashpw(secrets.token_bytes(32), bcrypt.gensalt(rounds=4)).decode(), account['id']))
    force_logout_user(account['id'])
    audit('account_deleted', account['username'],
          f"role={account['role']} by={current_user()['username']}")


def show_credentials(username, role, password, back):
    return render_template('credentials.html', username=username, role=role, password=password,
                           hours=TEMP_PASSWORD_HOURS, back=back)


# ---------------------------------------------------------------- officer: manage soldiers

@app.route('/soldiers', methods=['GET', 'POST'])
@permission_required('manage_soldiers')
def soldiers():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password, error = create_account(username, 'soldier')
        if password:
            return show_credentials(username, 'soldier', password, url_for('soldiers'))
        flash(error, 'danger')
    with db.cursor() as cur:
        cur.execute("SELECT id, username, created_by, created_at, last_login, totp_confirmed, "
                    "(locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked "
                    "FROM users WHERE role = 'soldier' AND deleted_at IS NULL ORDER BY username")
        rows = cur.fetchall()
    return render_template('officer/soldiers.html', soldiers=rows)


@app.route('/soldiers/<int:user_id>/delete', methods=['POST'])
@permission_required('manage_soldiers')
def soldier_delete(user_id):
    account = get_account(user_id)
    if account is None or account['deleted_at'] or not can_manage(current_user()['role'], account['role']):
        abort(403, description='You can only remove active soldier accounts.')
    deactivate(account)
    flash(f"{account['username']} has been removed and signed out.", 'success')
    return redirect(url_for('soldiers'))

