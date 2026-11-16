# admin.py
"""Admin interface: accounts for every role, login dashboard (full history of logins and
failed attempts, CSV export), suspicious-activity monitor, tamper-evident audit trail and the
encrypted message log (ciphertext only)."""
import csv
import io

from flask import Response, abort, flash, redirect, render_template, request, url_for

import db
from accounts import create_account, deactivate, get_account, reset_credentials, show_credentials
from chat import force_logout_user
from core import app, audit, audit_detail, verify_audit_chain
from permissions import CHANNELS, ROLES
from security import current_user, permission_required

FAILED_LOGIN_EVENTS = ('login_failed', 'otp_failed', 'account_locked', 'login_while_locked')
LOGIN_EVENTS = ('login_success', 'logout', 'activation_started', 'account_activated',
                'login_rate_limited') + FAILED_LOGIN_EVENTS
INTEGRITY_EVENTS = ('tampered_message', 'replay_rejected', 'handshake_failed', 'access_denied',
                    'login_rate_limited', 'register_rate_limited')
OUTCOMES = {
    'login_success': ('Success', 'success'),
    'logout': ('Signed out', 'secondary'),
    'activation_started': ('First login', 'info'),
    'account_activated': ('Activated', 'success'),
    'login_failed': ('Failed', 'danger'),
    'otp_failed': ('Wrong code', 'danger'),
    'account_locked': ('Locked', 'danger'),
    'login_while_locked': ('Blocked (locked)', 'warning'),
    'login_rate_limited': ('Blocked (rate limit)', 'warning'),
}


def _in(values):
    return ', '.join(['%s'] * len(values))


def conversation_label(key):
    if key.startswith('ch:'):
        meta = CHANNELS.get(key[3:])
        return '# ' + (meta['title'] if meta else key[3:])
    return 'DM ' + key[3:].replace('|', ' ↔ ')


# ---------------------------------------------------------------- accounts

def editable_account(user_id):
    """An account the current admin may modify, or None (with a flash message)."""
    account = get_account(user_id)
    if account is None:
        abort(404)
    if account['id'] == current_user()['user_id']:
        flash('You cannot change your own account.', 'warning')
        return None
    if account['deleted_at']:
        flash('That account has been deleted.', 'warning')
        return None
    return account


@app.route('/admin', methods=['GET', 'POST'])
@permission_required('manage_accounts')
def admin():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        role = request.form.get('role')
        if role not in ROLES:
            abort(400)
        password, error = create_account(username, role)
        if password:
            return show_credentials(username, role, password, url_for('admin'))
        flash(error, 'danger')
    with db.cursor() as cur:
        cur.execute("SELECT id, username, role, totp_confirmed, must_change_password, last_login, "
                    "created_at, created_by, deleted_at, "
                    "(locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked "
                    "FROM users ORDER BY deleted_at IS NOT NULL, FIELD(role, 'admin', 'officer', 'soldier'), username")
        users = cur.fetchall()
    return render_template('admin/accounts.html', users=users, roles=ROLES, tab='accounts')


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@permission_required('manage_accounts')
def admin_set_role(user_id):
    role = request.form.get('role')
    if role not in ROLES:
        abort(400)
    account = editable_account(user_id)
    if account and account['role'] != role:
        with db.cursor() as cur:
            cur.execute('UPDATE users SET role = %s WHERE id = %s', (role, user_id))
        force_logout_user(user_id)   # the new role applies at the next login, via the new portal
        audit('role_changed', account['username'],
              f"{account['role']} -> {role} by={current_user()['username']}")
        flash(f"{account['username']} is now {role} and has been signed out.", 'success')
    return redirect(url_for('admin'))


@app.route('/admin/users/<int:user_id>/unlock', methods=['POST'])
@permission_required('manage_accounts')
def admin_unlock(user_id):
    account = editable_account(user_id)
    if account:
        with db.cursor() as cur:
            cur.execute('UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = %s', (user_id,))
        audit('account_unlocked', account['username'], f"by={current_user()['username']}")
        flash(f"{account['username']} unlocked.", 'success')
    return redirect(url_for('admin'))


@app.route('/admin/users/<int:user_id>/reset', methods=['POST'])
@permission_required('manage_accounts')
def admin_reset(user_id):
    account = editable_account(user_id)
    if account is None:
        return redirect(url_for('admin'))
    password = reset_credentials(account)
    return show_credentials(account['username'], account['role'], password, url_for('admin'))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@permission_required('manage_accounts')
def admin_delete(user_id):
    account = editable_account(user_id)
    if account:
        deactivate(account)
        flash(f"{account['username']} has been deleted and signed out.", 'success')
    return redirect(url_for('admin'))


# ---------------------------------------------------------------- login dashboard

def login_events(username, outcome, limit=None):
    events = {'success': ('login_success',),
              'failure': FAILED_LOGIN_EVENTS + ('login_rate_limited',)}.get(outcome, LOGIN_EVENTS)
    sql = (f'SELECT id, event, username, ip, detail, created_at, row_hash FROM audit_log '
           f'WHERE event IN ({_in(events)})')
    params = list(events)
    if username:
        sql += ' AND username = %s'
        params.append(username)
    sql += ' ORDER BY id DESC'
    if limit:
        sql += ' LIMIT %s'
        params.append(limit)
    with db.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    for row in rows:
        row['detail'] = audit_detail(row)
        row['outcome'], row['style'] = OUTCOMES.get(row['event'], (row['event'], 'secondary'))
    return rows


@app.route('/admin/logins')
@permission_required('login_history')
def admin_logins():
    username = (request.args.get('user') or '').strip()[:64]
    outcome = request.args.get('outcome', 'all')
    with db.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n, COUNT(DISTINCT username) AS users FROM audit_log "
                    "WHERE event = 'login_success' AND created_at > NOW() - INTERVAL 1 DAY")
        ok_row = cur.fetchone()
        cur.execute(f'SELECT COUNT(*) AS n FROM audit_log WHERE event IN ({_in(FAILED_LOGIN_EVENTS)}) '
                    'AND created_at > NOW() - INTERVAL 1 DAY', FAILED_LOGIN_EVENTS)
        failed = cur.fetchone()['n']
        cur.execute('SELECT COUNT(*) AS n FROM users WHERE locked_until > NOW() AND deleted_at IS NULL')
        locked = cur.fetchone()['n']
    return render_template('admin/logins.html', tab='logins', rows=login_events(username, outcome, 300),
                           user=username, outcome=outcome, ok_24h=ok_row['n'], users_24h=ok_row['users'],
                           failed_24h=failed, locked_now=locked, chain=verify_audit_chain())


def _csv_safe(value):
    # Stop spreadsheet formula injection from attacker-chosen usernames.
    text = '' if value is None else str(value)
    return "'" + text if text[:1] in ('=', '+', '-', '@', '\t', '\r') else text


@app.route('/admin/logins.csv')
@permission_required('login_history')
def admin_logins_csv():
    username = (request.args.get('user') or '').strip()[:64]
    outcome = request.args.get('outcome', 'all')
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['id', 'time', 'event', 'outcome', 'username', 'ip', 'detail', 'row_hash'])
    for r in login_events(username, outcome):
        writer.writerow([_csv_safe(v) for v in (r['id'], r['created_at'], r['event'], r['outcome'],
                                                r['username'], r['ip'], r['detail'], r['row_hash'])])
    audit('login_history_exported', current_user()['username'], f'user={username or "*"} outcome={outcome}')
    return Response(buf.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=login_history.csv'})


# ---------------------------------------------------------------- suspicious activity

@app.route('/admin/security')
@permission_required('security_monitor')
def admin_security():
    with db.cursor() as cur:
        cur.execute(f'SELECT COUNT(*) AS n FROM audit_log WHERE event IN ({_in(FAILED_LOGIN_EVENTS)}) '
                    'AND created_at > NOW() - INTERVAL 1 DAY', FAILED_LOGIN_EVENTS)
        failed_24h = cur.fetchone()['n']
        cur.execute('SELECT COUNT(*) AS n FROM users WHERE locked_until > NOW()')
        locked_now = cur.fetchone()['n']
        cur.execute(f'SELECT COUNT(*) AS n FROM audit_log WHERE event IN ({_in(INTEGRITY_EVENTS)}) '
                    'AND created_at > NOW() - INTERVAL 7 DAY', INTEGRITY_EVENTS)
        integrity_7d = cur.fetchone()['n']

        # Behaviour rule 1: repeated failures against one account (brute force).
        cur.execute(f'SELECT username, COUNT(*) AS n, COUNT(DISTINCT ip) AS ips, MAX(created_at) AS last '
                    f'FROM audit_log WHERE event IN ({_in(FAILED_LOGIN_EVENTS)}) '
                    'AND created_at > NOW() - INTERVAL 1 DAY AND username IS NOT NULL '
                    'GROUP BY username HAVING n >= 3 ORDER BY last DESC', FAILED_LOGIN_EVENTS)
        brute_force = cur.fetchall()

        # Behaviour rule 2: one address trying many accounts (credential stuffing).
        cur.execute(f'SELECT ip, COUNT(*) AS n, COUNT(DISTINCT username) AS users, MAX(created_at) AS last '
                    f'FROM audit_log WHERE event IN ({_in(FAILED_LOGIN_EVENTS)}) '
                    'AND created_at > NOW() - INTERVAL 1 DAY GROUP BY ip HAVING users >= 3 '
                    'ORDER BY last DESC', FAILED_LOGIN_EVENTS)
        stuffing = cur.fetchall()

        # Behaviour rule 3: successful login from an address this user never used before.
        cur.execute("SELECT a.username, a.ip, a.created_at FROM audit_log a "
                    "WHERE a.event = 'login_success' AND a.created_at > NOW() - INTERVAL 7 DAY "
                    "AND EXISTS (SELECT 1 FROM audit_log p WHERE p.event = 'login_success' "
                    "            AND p.username = a.username AND p.id < a.id) "
                    "AND NOT EXISTS (SELECT 1 FROM audit_log p WHERE p.event = 'login_success' "
                    "            AND p.username = a.username AND p.ip = a.ip AND p.id < a.id) "
                    "ORDER BY a.id DESC LIMIT 50")
        new_ip = cur.fetchall()

        # Rule 4: tampering, replay, access violations, rate limiting.
        cur.execute(f'SELECT event, username, ip, detail, created_at FROM audit_log '
                    f'WHERE event IN ({_in(INTEGRITY_EVENTS)}) AND created_at > NOW() - INTERVAL 7 DAY '
                    'ORDER BY id DESC LIMIT 50', INTEGRITY_EVENTS)
        integrity = cur.fetchall()

        cur.execute(f'SELECT event, username, ip, detail, created_at FROM audit_log '
                    f'WHERE event IN ({_in(FAILED_LOGIN_EVENTS)}) ORDER BY id DESC LIMIT 100',
                    FAILED_LOGIN_EVENTS)
        failures = cur.fetchall()
    for row in integrity + failures:
        row['detail'] = audit_detail(row)
    return render_template('admin/security.html', tab='security', failed_24h=failed_24h,
                           locked_now=locked_now, integrity_7d=integrity_7d,
                           brute_force=brute_force, stuffing=stuffing, new_ip=new_ip,
                           integrity=integrity, failures=failures)


# ---------------------------------------------------------------- message vault

@app.route('/admin/vault')
@permission_required('message_vault')
def admin_vault():
    """Encrypted message log: metadata and ciphertext only - admins cannot read message content."""
    query = (request.args.get('q') or '').strip()[:32]
    with db.cursor() as cur:
        if query:
            like = '%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
            cur.execute('SELECT id, conversation, sender, sender_role, recipient, body, created_at '
                        'FROM messages WHERE sender LIKE %s OR recipient LIKE %s OR conversation LIKE %s '
                        'ORDER BY id DESC LIMIT 100', (like, like, like))
        else:
            cur.execute('SELECT id, conversation, sender, sender_role, recipient, body, created_at '
                        'FROM messages ORDER BY id DESC LIMIT 100')
        rows = cur.fetchall()
    for row in rows:
        row['label'] = conversation_label(row['conversation'])
    return render_template('admin/vault.html', tab='vault', rows=rows, q=query)


# ---------------------------------------------------------------- audit trail

@app.route('/admin/audit')
@permission_required('audit_log')
def admin_audit():
    with db.cursor() as cur:
        cur.execute('SELECT event, username, ip, detail, created_at FROM audit_log '
                    'ORDER BY id DESC LIMIT 200')
        events = cur.fetchall()
    for row in events:
        row['sealed'] = row['detail']
        row['detail'] = audit_detail(row)
    return render_template('admin/audit.html', tab='audit', events=events, chain=verify_audit_chain())
