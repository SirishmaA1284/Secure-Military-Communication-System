# scripts/check_db.py
"""Used by start.bat: wait for MySQL, verify the credentials in instance/.env and
create the database if it does not exist yet. Exit code 0 = ready."""
import os
import socket
import sys
import time

from dotenv import load_dotenv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT, 'instance', '.env'))

HOST = os.environ.get('MYSQL_HOST', '127.0.0.1')
PORT = int(os.environ.get('MYSQL_PORT', '3306'))
USER = os.environ.get('MYSQL_USER', '')
PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
DB = os.environ.get('MYSQL_DB', 'secureee')


def port_open(timeout=1.0):
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout):
            return True
    except OSError:
        return False


def prepare():
    """For setup_db.bat on a fresh clone: create instance/.env if missing, generate a strong
    password for the app's MySQL user if none is set, and write the one-time setup SQL."""
    import re
    import secrets
    import shutil

    env_path = os.path.join(ROOT, 'instance', '.env')
    if not os.path.exists(env_path):
        shutil.copy(os.path.join(ROOT, '.env.example'), env_path)
        print('  Created instance\\.env from .env.example')
    with open(env_path, encoding='utf-8') as f:
        env = f.read()

    user = re.search(r'(?m)^MYSQL_USER=(.*)$', env)
    user = user.group(1).strip() if user else 'chat_app'
    password = re.search(r'(?m)^MYSQL_PASSWORD=(.*)$', env)
    password = password.group(1).strip() if password else ''
    if not re.fullmatch(r'[A-Za-z0-9_]{1,32}', user) or not DB.replace('_', '').isalnum():
        print('  MYSQL_USER / MYSQL_DB in instance\\.env may only contain letters, digits and _')
        sys.exit(1)
    if password in ('', 'change-me'):
        while True:
            password = secrets.token_urlsafe(18)
            if all(re.search(p, password) for p in (r'[a-z]', r'[A-Z]', r'\d', r'[-_]')):
                break
        env = (re.sub(r'(?m)^MYSQL_PASSWORD=.*$', 'MYSQL_PASSWORD=' + password, env)
               if re.search(r'(?m)^MYSQL_PASSWORD=', env) else env + f'\nMYSQL_PASSWORD={password}\n')
        with open(env_path, 'w', encoding='utf-8') as f:
            f.write(env)
        print('  Generated a strong password for the app database user (saved in instance\\.env)')
    if "'" in password or '\\' in password:
        print("  MYSQL_PASSWORD must not contain ' or \\ characters")
        sys.exit(1)

    with open(os.path.join(ROOT, 'instance', 'create_app_user.sql'), 'w', encoding='utf-8') as f:
        f.write(f"CREATE DATABASE IF NOT EXISTS `{DB}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
                f"CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{password}';\n"
                f"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX ON `{DB}`.* TO '{user}'@'localhost';\n")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'check'
    if mode == 'prepare':
        prepare()
        return
    if mode == 'port':                       # quick probe: is anything listening?
        sys.exit(0 if port_open() else 1)
    if mode == 'wait':                       # wait up to N seconds for the port
        deadline = time.time() + int(sys.argv[2] if len(sys.argv) > 2 else 30)
        while time.time() < deadline:
            if port_open():
                sys.exit(0)
            time.sleep(1)
        sys.exit(1)

    import mysql.connector
    from mysql.connector import errorcode

    if not USER:
        print('  MYSQL_USER is not set in instance\\.env')
        sys.exit(1)
    if not DB.replace('_', '').isalnum():
        print(f'  MYSQL_DB "{DB}" contains invalid characters')
        sys.exit(1)
    try:
        conn = mysql.connector.connect(host=HOST, port=PORT, user=USER, password=PASSWORD,
                                       connection_timeout=5)
    except mysql.connector.Error as e:
        if e.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print(f'  MySQL rejected user "{USER}" - check MYSQL_USER / MYSQL_PASSWORD in instance\\.env')
        else:
            print(f'  Cannot connect to MySQL at {HOST}:{PORT}: {e.msg}')
        sys.exit(1)

    cur = conn.cursor()
    try:
        cur.execute(f'CREATE DATABASE IF NOT EXISTS `{DB}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
    except mysql.connector.Error as e:
        cur.execute('SHOW DATABASES LIKE %s', (DB,))
        if not cur.fetchone():
            print(f'  Database "{DB}" does not exist and user "{USER}" cannot create it: {e.msg}')
            sys.exit(1)
    finally:
        cur.close()
        conn.close()
    print(f'  MySQL OK - {USER}@{HOST}:{PORT}, database "{DB}"')


if __name__ == '__main__':
    main()
