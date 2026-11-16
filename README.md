# SecureComm - Secure Military Communication Chat

A Flask + Socket.IO chat room with layered security: TLS, application-layer message encryption, encryption at rest, password + TOTP two-factor login, and role-based access.

## Running it

**Windows quick start** (needs Python 3.10+ and MySQL Server 8.0 running as a service):

1. Double-click **`setup_db.bat`** once. It creates `instance\.env` with a generated password for a least-privilege `chat_app` database user, then asks for your MySQL **root** password to create that user and the `secureee` database.
2. Double-click **`start.bat`**. It installs missing packages, checks MySQL, and starts the server.
3. On first run, the browser opens `/setup` to create the first **admin** account.

**Manually, on any OS:**

```bash
pip install -r requirements.txt
cp .env.example instance/.env      # then put your MySQL credentials in it
python app.py
```

Open **https://localhost:5000**. The certificate is self-signed, so your browser shows a warning the first time. Accept it, or set `TLS_CERT_FILE`/`TLS_KEY_FILE` to a real certificate.

MySQL must be running. On startup the app creates the tables in `schema.sql` and upgrades tables from older versions. There is no public sign-up. On an empty database, `/setup` creates the first admin once, and every other account is created from inside the app.

On first run these files are generated in `instance/`. All of them are git-ignored, so keep them private and backed up:

| File | Contents |
|---|---|
| `secrets.json` | Flask secret key, at-rest data key, RSA key passphrase |
| `server_rsa.pem` | Server RSA-3072 key, encrypted with the passphrase |
| `tls/` | Self-signed TLS certificate and key |

Losing `secrets.json` makes stored messages and OTP secrets unreadable.

## Roles and logins

The login page has three portals: **Soldier**, **Officer** and **Admin**. An account can only sign in through the portal for its own role. A correct password at the wrong portal is refused and logged. Login is two steps: password, then a 6-digit code from an authenticator app. The rules live in `permissions.py`.

| Role | Can do |
|---|---|
| **Soldier** | Chat (General channel, read Announcements, direct messages). Sees only officers and soldiers |
| **Officer** | Chat (plus post Announcements and the Command channel). **Add and delete soldiers** |
| **Admin** | Create, reset, unlock and delete accounts of any clearance. Login dashboard (every login and failure, CSV export). Suspicious-activity monitor. Hash-chained audit log. Encrypted message log (metadata and ciphertext only; admins cannot read messages). Admins do not appear in chat |

**New accounts:**
1. An admin or officer creates the account and chooses its clearance.
2. A one-time temporary password, valid 24 hours, is shown once to the creator.
3. At first login through their portal, the user chooses their own password and scans a 2FA QR code.

**Deleting** deactivates an account. It is signed out at once and can never log in again. The username stays reserved, so nobody can take it over and read old messages, and its audit history is kept.

**Audit log:**
- Every login attempt is recorded with its reason, such as wrong password, wrong code, wrong portal, locked, or expired temporary password.
- Account changes and access denials are recorded too.
- Each entry is HMAC hash-chained to the previous one, so the admin pages show an alert if any entry is later edited or deleted in the database.

## Code layout

| File | Purpose |
|---|---|
| `app.py` | Entry point |
| `core.py` | App, Socket.IO, keys, encrypted hash-chained audit log, error pages |
| `auth.py` | Role login portals, two-step login, first-login activation, first-admin setup |
| `accounts.py` | Account creation, reset and deletion; officer's Manage soldiers page |
| `chat.py` | Encrypted chat: channels, DMs, presence, history |
| `admin.py` | Admin pages |
| `permissions.py` | Role rules |
| `security.py` | Web security layers |
| `encryption_utils.py` | Crypto |
| `db.py` + `schema.sql` | Database and automatic migrations |

## Security layers

| Layer | What it does |
|---|---|
| Transport | HTTPS/WSS (TLS). `Secure`, `HttpOnly`, `SameSite=Strict` `__Host-` session cookie |
| Message encryption | Each browser makes a fresh AES-256-GCM key per connection and wraps it with the server's RSA-3072-OAEP key. Each message gets a random IV and a sequence number, bound as associated data, so tampered or replayed frames are rejected in both directions. The server key fingerprint is shown in the chat page so users can check it |
| At rest | Messages and TOTP secrets are AES-256-GCM encrypted in MySQL. Each value is bound to its owner, so copying a ciphertext into another user's row doesn't decrypt |
| Passwords | bcrypt (cost 12). Minimum 12 characters with mixed case, a digit and a symbol, and the password can't contain the username |
| 2FA | TOTP is required. Setup shows a QR code once and must be confirmed with a valid code. Used codes can't be replayed |
| Brute force | Per-IP rate limits on login, registration and 2FA setup. Account lockout after 5 failures for 15 minutes. One generic error message, and the same bcrypt timing whether or not the username exists |
| Sessions | Server-side session registry: logout, role change or restart revokes sessions and closes open sockets. 30-minute idle timeout. Session ID regenerated at login |
| Web | CSRF tokens on every form (logout is POST). Strict Content-Security-Policy with no inline script and no CDNs (vendored assets). Clickjacking, MIME-sniffing and referrer headers. `no-store` on pages. Output escaping, with chat messages rendered via `textContent` |
| Socket | Unauthenticated sockets are refused, same-origin only. Per-user message rate limit. Size limits. Control and bidi-override characters stripped |
| Access control | Separate login portal per role. No self-registration. Accounts are issued by admins (any role) or officers (soldiers) |
| Accountability | Tamper-evident (hash-chained) audit log of every login attempt and reason, account change and access denial. CSV export |
| Ops | Debug mode off and bind to `127.0.0.1` by default. Secrets come from env/`instance/.env`. Parameterized SQL everywhere. Use a least-privilege DB user (see `schema.sql`) |

## Limitations

- **Encryption is end-to-server, not end-to-end.** The server decrypts messages to store and relay them, so a compromised server can read them. True E2E would need per-user key pairs and client-side group key management.
- **One process only.** Rate limits and sessions are kept in memory, so they reset on restart and won't work across multiple workers. Use Redis for a multi-worker deployment.
- **Development server.** The Werkzeug server is fine for a demo. For real deployment, put the app behind a production server or reverse proxy.
