# encryption_utils.py
"""Cryptographic building blocks for the secure chat.

* RSA-3072 / OAEP-SHA256 - each browser generates a fresh AES session key and
  wraps it with the server's public key (hybrid key exchange).
* AES-256-GCM - authenticated encryption of every chat message in transit
  (per-connection session key) and of sensitive columns at rest (server data key).
* Self-signed TLS certificate generation for running over HTTPS locally.
"""
import base64
import datetime
import hashlib
import ipaddress
import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

RSA_BITS = 3072
AES_KEY_SIZE = 32       # AES-256
NONCE_SIZE = 12         # 96-bit GCM nonce (NIST recommended)
TAG_SIZE = 16           # 128-bit GCM tag
SEALED_PREFIX = 'v1:'   # version marker for values encrypted at rest


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def b64d(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def write_private_file(path: str, data: bytes) -> None:
    """Create a file readable only by the owner (best effort on Windows)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)


# ---------------------------------------------------------------- RSA (key exchange)

def generate_keys(bits: int = RSA_BITS):
    """Return a new (private_key, public_key) RSA pair."""
    key = RSA.generate(bits)
    return key, key.publickey()


def load_or_create_rsa_key(path: str, passphrase: str):
    """Load the server's RSA key, creating it on first run.

    The private key is stored PKCS#8-encrypted (scrypt + AES-256) so the PEM
    file alone is useless without the passphrase.
    """
    if os.path.exists(path):
        with open(path, 'rb') as f:
            return RSA.import_key(f.read(), passphrase=passphrase)
    key, _ = generate_keys()
    pem = key.export_key(format='PEM', pkcs=8, passphrase=passphrase,
                         protection='scryptAndAES256-CBC')
    write_private_file(path, pem)
    return key


def public_key_spki_b64(key) -> str:
    """Public key as base64 SubjectPublicKeyInfo DER (what WebCrypto imports as 'spki')."""
    return b64e(key.publickey().export_key(format='DER'))


def public_key_fingerprint(key) -> str:
    """SHA-256 fingerprint of the public key so users can verify it out of band."""
    digest = hashlib.sha256(key.publickey().export_key(format='DER')).hexdigest().upper()
    return ':'.join(digest[i:i + 4] for i in range(0, 32, 4))


def rsa_wrap(public_key, data: bytes) -> str:
    return b64e(PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(data))


def rsa_unwrap(private_key, wrapped_b64: str) -> bytes:
    """Decrypt an RSA-OAEP(SHA-256) blob. Raises ValueError on any failure."""
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(b64d(wrapped_b64))


# ---------------------------------------------------------------- AES-GCM (messages)

def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b'') -> dict:
    """Encrypt with AES-256-GCM. Output matches WebCrypto: ct = ciphertext || tag."""
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {'iv': b64e(nonce), 'ct': b64e(ciphertext + tag)}


def aes_decrypt(key: bytes, iv_b64: str, ct_b64: str, aad: bytes = b'') -> bytes:
    """Decrypt and authenticate AES-256-GCM. Raises ValueError if tampered with."""
    nonce, blob = b64d(iv_b64), b64d(ct_b64)
    if len(nonce) != NONCE_SIZE or len(blob) < TAG_SIZE:
        raise ValueError('malformed ciphertext')
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
    cipher.update(aad)
    return cipher.decrypt_and_verify(blob[:-TAG_SIZE], blob[-TAG_SIZE:])


def encrypt_message(key: bytes, text: str, aad: bytes = b'') -> dict:
    return aes_encrypt(key, text.encode('utf-8'), aad)


def decrypt_message(key: bytes, iv_b64: str, ct_b64: str, aad: bytes = b'') -> str:
    return aes_decrypt(key, iv_b64, ct_b64, aad).decode('utf-8')


# ---------------------------------------------------------------- encryption at rest

def seal(key: bytes, text: str, context: str) -> str:
    """Encrypt a value for storage in the DB.

    `context` is bound as associated data, so a ciphertext copied into another
    row/column (e.g. someone else's OTP secret) fails to decrypt.
    """
    out = aes_encrypt(key, text.encode('utf-8'), context.encode('utf-8'))
    return SEALED_PREFIX + b64e(b64d(out['iv']) + b64d(out['ct']))


def unseal(key: bytes, token: str, context: str) -> str:
    if not is_sealed(token):
        raise ValueError('value is not sealed')
    raw = b64d(token[len(SEALED_PREFIX):])
    return aes_decrypt(key, b64e(raw[:NONCE_SIZE]), b64e(raw[NONCE_SIZE:]),
                       context.encode('utf-8')).decode('utf-8')


def is_sealed(token: str) -> bool:
    return isinstance(token, str) and token.startswith(SEALED_PREFIX)


# ---------------------------------------------------------------- TLS

def ensure_self_signed_cert(cert_path: str, key_path: str) -> None:
    """Create a self-signed ECDSA P-256 certificate for localhost if none exists."""
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName('localhost'),
            x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    write_private_file(key_path, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
