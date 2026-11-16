# db.py
"""MySQL access: pooled connections, schema creation and migration of the old users table."""
import logging
import os
import threading
from contextlib import contextmanager

import mysql.connector
from mysql.connector import pooling

log = logging.getLogger(__name__)

_pool = None
_pool_lock = threading.Lock()
_config = {}

SCHEMA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')

# Columns added to tables created by older versions of the app: {table: {column: ddl}}.
COLUMN_MIGRATIONS = {
    'users': {
        'totp_confirmed': 'TINYINT(1) NOT NULL DEFAULT 0',
        'last_otp_step': 'BIGINT NOT NULL DEFAULT 0',
        'failed_attempts': 'INT NOT NULL DEFAULT 0',
        'locked_until': 'DATETIME NULL',
        'created_at': 'DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP',
        'last_login': 'DATETIME NULL',
        'must_change_password': 'TINYINT(1) NOT NULL DEFAULT 0',
        'password_expires': 'DATETIME NULL',
        'created_by': 'VARCHAR(32) NULL',
        'deleted_at': 'DATETIME NULL',
    },
    'messages': {
        'conversation': "VARCHAR(80) NOT NULL DEFAULT 'ch:general'",
        'recipient': 'VARCHAR(32) NULL',
    },
    'audit_log': {
        'prev_hash': 'CHAR(64) NULL',
        'row_hash': 'CHAR(64) NULL',
    },
}
INDEX_MIGRATIONS = {
    'messages': {
        'idx_messages_conversation': '(conversation, id)',
        'idx_messages_recipient': '(recipient)',
    },
    'audit_log': {
        'idx_audit_event': '(event, created_at)',   # suspicious-activity queries
        'idx_audit_user': '(username, event)',
    },
}


def init_app(app):
    _config.update(
        host=app.config['MYSQL_HOST'],
        port=app.config['MYSQL_PORT'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB'],
    )


def _get_pool():
    """Create the pool lazily so the app can start (and show a 503) while MySQL is down."""
    global _pool
    with _pool_lock:
        if _pool is None:
            ensure_schema()
            _pool = pooling.MySQLConnectionPool(pool_name='chat', pool_size=8, **_config)
        return _pool


@contextmanager
def cursor(dictionary=True):
    """Yield a cursor; commits on success, rolls back on error, always returns the connection."""
    conn = _get_pool().get_connection()
    cur = conn.cursor(dictionary=dictionary)
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def ensure_schema():
    """Create missing tables and upgrade tables from older versions of the app in place."""
    conn = mysql.connector.connect(**_config)
    cur = conn.cursor()
    try:
        with open(SCHEMA_FILE, encoding='utf-8') as f:
            statements = [s.strip() for s in _strip_comments(f.read()).split(';') if s.strip()]
        for stmt in statements:
            cur.execute(stmt)

        existing = {table: _columns(cur, table) for table in COLUMN_MIGRATIONS}
        for table, columns in COLUMN_MIGRATIONS.items():
            for column, ddl in columns.items():
                if column not in existing[table]:
                    log.warning('Migrating %s table: adding column %s', table, column)
                    cur.execute(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}')
                    if table == 'users' and column == 'totp_confirmed':
                        # Accounts created by the old app already received their OTP secret.
                        cur.execute('UPDATE users SET totp_confirmed = 1')
        for table, indexes in INDEX_MIGRATIONS.items():
            cur.execute('SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS '
                        'WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s', (_config['database'], table))
            present = {row[0] for row in cur.fetchall()}
            for name, cols in indexes.items():
                if name not in present:
                    cur.execute(f'ALTER TABLE {table} ADD INDEX {name} {cols}')
        if (_columns(cur, 'audit_log').get('detail') or 512) < 512:
            cur.execute('ALTER TABLE audit_log MODIFY detail VARCHAR(512) NULL')

        existing = existing['users']
        # Sealed OTP secrets are longer than a raw base32 secret.
        if (existing.get('otp_secret') or 255) < 255:
            cur.execute('ALTER TABLE users MODIFY otp_secret VARCHAR(255) NOT NULL')
        if (existing.get('password') or 255) < 60:
            cur.execute('ALTER TABLE users MODIFY password VARCHAR(255) NOT NULL')

        cur.execute(
            "SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = %s "
            "AND TABLE_NAME = 'users' AND COLUMN_NAME = 'username' AND NON_UNIQUE = 0",
            (_config['database'],))
        if cur.fetchone()[0] == 0:
            try:
                cur.execute('ALTER TABLE users ADD UNIQUE INDEX uq_users_username (username)')
            except mysql.connector.Error as e:
                log.error('Could not add unique index on users.username (duplicates exist?): %s', e)
        conn.commit()
    finally:
        cur.close()
        conn.close()


def _columns(cur, table):
    """{column_name: max_length} for a table in the configured database."""
    cur.execute('SELECT COLUMN_NAME, CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS '
                'WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s', (_config['database'], table))
    return {name.lower(): length for name, length in cur.fetchall()}


def _strip_comments(sql):
    lines = []
    for line in sql.splitlines():
        idx = line.find('--')
        lines.append(line if idx == -1 else line[:idx])
    return '\n'.join(lines)
