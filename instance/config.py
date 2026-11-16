# instance/config.py
# All secrets come from environment variables or instance/.env (never commit that file).
# SECRET_KEY, DATA_ENCRYPTION_KEY and RSA_KEY_PASSPHRASE are generated automatically
# into instance/secrets.json on first run if they are not set here.
import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

SECRET_KEY = os.environ.get('SECRET_KEY')
DATA_ENCRYPTION_KEY = os.environ.get('DATA_ENCRYPTION_KEY')   # base64, 32 bytes
RSA_KEY_PASSPHRASE = os.environ.get('RSA_KEY_PASSPHRASE')

MYSQL_HOST = os.environ.get('MYSQL_HOST', '127.0.0.1')
MYSQL_PORT = int(os.environ.get('MYSQL_PORT', '3306'))
MYSQL_USER = os.environ.get('MYSQL_USER', '')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
MYSQL_DB = os.environ.get('MYSQL_DB', 'secureee')

# Server
APP_HOST = os.environ.get('APP_HOST', '127.0.0.1')   # use 0.0.0.0 only on a trusted LAN
APP_PORT = int(os.environ.get('APP_PORT', '5000'))
DEBUG = os.environ.get('FLASK_DEBUG') == '1'          # never enable on a shared network
USE_TLS = os.environ.get('USE_TLS', '1') == '1'
TLS_CERT_FILE = os.environ.get('TLS_CERT_FILE', '')   # empty -> self-signed cert in instance/tls/
TLS_KEY_FILE = os.environ.get('TLS_KEY_FILE', '')

# Sessions
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get('SESSION_IDLE_MINUTES', '30')))

# Limits
MAX_CONTENT_LENGTH = 16 * 1024         # form posts are tiny
MAX_MESSAGE_LENGTH = 1000              # characters per chat message
CHAT_HISTORY_SIZE = 50
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
