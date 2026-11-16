# chat.py
"""Encrypted real-time chat over Socket.IO: role-restricted channels, direct messages,
presence and per-conversation history.

Wire protocol (all application data travels inside AES-256-GCM frames):
  client -> server  'handshake'      {wrapped_key}                RSA-OAEP wrapped session key
  client -> server  'secure_message' {iv, ct, seq}                encrypted JSON request:
        {"action": "send",    "conv": "ch:general" | "dm:<user>", "text": "..."}
        {"action": "history", "conv": "..."}
  server -> client  'secure_message' {iv, ct, seq}                encrypted JSON event:
        {"type": "init" | "history" | "message" | "presence", ...}
Conversation ids: 'ch:<channel>' for channels, 'dm:<other user>' for direct messages.
"""
import json
import threading
from datetime import datetime, timezone

import mysql.connector
from flask import render_template, request, session

import db
import security
from core import (DATA_KEY, SERVER_FINGERPRINT, SERVER_KEY, SERVER_PUBLIC_SPKI, app, audit, log,
                  socketio, utc_iso)
from encryption_utils import decrypt_message, encrypt_message, rsa_unwrap, seal, unseal
from permissions import CHANNELS, CHAT_ROLES, can_post_channel, can_read_channel, has_permission
from security import permission_required, sessions


class Client:
    def __init__(self, sid, token, user):
        self.sid, self.token = sid, token
        self.user_id, self.username, self.role = user['user_id'], user['username'], user['role']
        self.key = None        # AES-256 session key, set by the handshake
        self.recv_seq = 0      # highest client->server sequence number accepted
        self.send_seq = 0      # last server->client sequence number used
        self.lock = threading.Lock()


clients = {}
clients_lock = threading.Lock()


def connected_clients():
    with clients_lock:
        return [c for c in clients.values() if c.key is not None]


def is_online(username):
    return any(c.username.lower() == username.lower() for c in connected_clients())


def disconnect_sockets(predicate):
    with clients_lock:
        sids = [sid for sid, c in clients.items() if predicate(c)]
    for sid in sids:
        socketio.emit('session_expired', to=sid)
        socketio.server.disconnect(sid, namespace='/')


def force_logout_user(user_id):
    sessions.revoke_user(user_id)
    disconnect_sockets(lambda c: c.user_id == user_id)


def send_encrypted(client, payload):
    with client.lock:
        if client.key is None:
            return
        client.send_seq += 1
        seq = client.send_seq
        box = encrypt_message(client.key, json.dumps(payload), f's2c|{seq}'.encode())
        socketio.emit('secure_message', {**box, 'seq': seq}, to=client.sid)


# ---------------------------------------------------------------- conversations

def channel_list(role):
    return [{'id': f'ch:{key}', 'title': meta['title'], 'description': meta['description'],
             'can_post': can_post_channel(role, key)}
            for key, meta in CHANNELS.items() if can_read_channel(role, key)]


# Accounts that appear in chat: active, activated, and of a chat role (admins never appear).
CHAT_MEMBER_SQL = ('totp_confirmed = 1 AND deleted_at IS NULL AND role IN (%s)'
                   % ', '.join(['%s'] * len(CHAT_ROLES)))


def lookup_user(username):
    if not isinstance(username, str) or not security.valid_username(username):
        return None
    with db.cursor() as cur:
        cur.execute(f'SELECT username, role FROM users WHERE username = %s AND {CHAT_MEMBER_SQL}',
                    (username, *CHAT_ROLES))
        return cur.fetchone()


def resolve(client, conv):
    """Map a client's conversation id to its storage key, or None if this user may not access it."""
    if not isinstance(conv, str):
        return None
    if conv.startswith('ch:'):
        channel = conv[3:]
        if can_read_channel(client.role, channel):
            return {'id': conv, 'key': conv, 'channel': channel, 'peer': None}
        return None
    if conv.startswith('dm:'):
        peer = lookup_user(conv[3:])
        if peer is None or peer['username'].lower() == client.username.lower():
            return None
        a, b = sorted([client.username, peer['username']], key=str.lower)
        return {'id': 'dm:' + peer['username'], 'key': f'dm:{a}|{b}', 'channel': None,
                'peer': peer['username']}
    return None


def message_context(conversation, sender):
    # Bound as associated data: a stored message cannot be moved to another chat or sender.
    return f'msg:{conversation}:{sender}'


def open_message(row):
    for context in (message_context(row['conversation'], row['sender']), f"msg:{row['sender']}"):
        try:
            return unseal(DATA_KEY, row['body'], context)
        except ValueError:
            continue
    log.warning('Stored message %s failed integrity check', row['id'])
    return None


def to_payload(row, text, viewer):
    if row['recipient'] is None:
        conv = row['conversation']
    else:
        conv = 'dm:' + (row['recipient'] if row['sender'].lower() == viewer.lower() else row['sender'])
    return {'id': row['id'], 'conv': conv, 'from': row['sender'], 'role': row['sender_role'],
            'text': text, 'ts': utc_iso(row['created_at'])}


def load_history(conversation_key, viewer):
    with db.cursor() as cur:
        cur.execute('SELECT id, conversation, sender, sender_role, recipient, body, created_at '
                    'FROM messages WHERE conversation = %s ORDER BY id DESC LIMIT %s',
                    (conversation_key, app.config['CHAT_HISTORY_SIZE']))
        rows = cur.fetchall()
    out = []
    for row in reversed(rows):
        text = open_message(row)
        if text is not None:
            out.append(to_payload(row, text, viewer))
    return out


def member_list():
    online = {c.username.lower() for c in connected_clients()}
    with db.cursor() as cur:
        cur.execute(f'SELECT username, role FROM users WHERE {CHAT_MEMBER_SQL} ORDER BY username', CHAT_ROLES)
        return [{'username': r['username'], 'role': r['role'], 'online': r['username'].lower() in online}
                for r in cur.fetchall()]


def recent_dm_peers(username):
    """Direct-message partners with the time of the latest message, newest first."""
    with db.cursor() as cur:
        cur.execute('SELECT IF(sender = %s, recipient, sender) AS peer, MAX(created_at) AS last_at '
                    'FROM messages WHERE recipient IS NOT NULL AND (sender = %s OR recipient = %s) '
                    'GROUP BY peer ORDER BY last_at DESC', (username, username, username))
        return [{'peer': r['peer'], 'last': utc_iso(r['last_at'])} for r in cur.fetchall()]


def deliver(row, text):
    for c in connected_clients():
        if row['recipient'] is None:
            if not can_read_channel(c.role, row['conversation'][3:]):
                continue
        elif c.username.lower() not in (row['sender'].lower(), row['recipient'].lower()):
            continue
        send_encrypted(c, {'type': 'message', **to_payload(row, text, c.username)})


def broadcast_presence(client, online):
    payload = {'type': 'presence', 'username': client.username, 'role': client.role, 'online': online}
    for c in connected_clients():
        if c.sid != client.sid:
            send_encrypted(c, payload)


def deny(client, conv, what):
    audit('access_denied', client.username, f'{what} {str(conv)[:60]}')
    emit_error('Access denied: your role cannot ' + what + ' that conversation.')


def emit_error(text):
    socketio.emit('chat_error', text, to=request.sid)


# ---------------------------------------------------------------- page

@app.route('/chat')
@permission_required('chat')
def chat():
    return render_template('chat.html', server_key=SERVER_PUBLIC_SPKI,
                           fingerprint=SERVER_FINGERPRINT,
                           max_len=app.config['MAX_MESSAGE_LENGTH'])


# ---------------------------------------------------------------- socket events

def get_client():
    with clients_lock:
        return clients.get(request.sid)


@socketio.on('connect')
def on_connect(auth=None):
    token = session.get('auth')
    user = sessions.get(token)
    if user is None or not has_permission(user['role'], 'chat'):
        return False   # refuse unauthenticated sockets and roles without chat access
    with clients_lock:
        clients[request.sid] = Client(request.sid, token, user)


@socketio.on('disconnect')
def on_disconnect(*args):
    with clients_lock:
        client = clients.pop(request.sid, None)
    if client and client.key is not None and not is_online(client.username):
        broadcast_presence(client, False)


@socketio.on('handshake')
def on_handshake(data):
    client = get_client()
    if client is None or not isinstance(data, dict) or not isinstance(data.get('wrapped_key'), str):
        return False
    try:
        key = rsa_unwrap(SERVER_KEY, data['wrapped_key'])
    except (ValueError, TypeError):
        key = None
    if key is None or len(key) != 32:
        audit('handshake_failed', client.username)
        socketio.server.disconnect(request.sid, namespace='/')
        return

    was_online = is_online(client.username)
    with client.lock:
        client.key, client.recv_seq, client.send_seq = key, 0, 0
    socketio.emit('handshake_ok', to=request.sid)
    try:
        send_encrypted(client, {
            'type': 'init',
            'me': {'username': client.username, 'role': client.role},
            'channels': channel_list(client.role),
            'members': member_list(),
            'recent': recent_dm_peers(client.username),
            'max_len': app.config['MAX_MESSAGE_LENGTH'],
        })
    except mysql.connector.Error:
        log.exception('Could not load chat directory')
        emit_error('The member list is unavailable right now.')
    if not was_online:
        broadcast_presence(client, True)


@socketio.on('secure_message')
def on_secure_message(data):
    client = get_client()
    if client is None or client.key is None:
        return
    if sessions.get(client.token) is None:   # logged out elsewhere or idle timeout
        disconnect_sockets(lambda c: c.sid == client.sid)
        return
    if not isinstance(data, dict):
        return
    seq, iv, ct = data.get('seq'), data.get('iv'), data.get('ct')
    if (type(seq) is not int or not isinstance(iv, str) or not isinstance(ct, str)
            or len(ct) > 16384 or len(iv) > 32):
        emit_error('Malformed message rejected.')
        return

    with client.lock:
        if seq <= client.recv_seq:
            audit('replay_rejected', client.username, f'seq={seq}')
            emit_error('Replayed message rejected.')
            return
        try:
            plaintext = decrypt_message(client.key, iv, ct, f'c2s|{seq}'.encode())
        except (ValueError, KeyError, UnicodeDecodeError):
            audit('tampered_message', client.username, f'seq={seq}')
            emit_error('Message failed integrity check and was rejected.')
            return
        client.recv_seq = seq

    try:
        req = json.loads(plaintext)
    except ValueError:
        req = None
    if not isinstance(req, dict):
        emit_error('Malformed request rejected.')
        return

    try:
        if req.get('action') == 'send':
            handle_send(client, req)
        elif req.get('action') == 'history':
            handle_history(client, req)
        else:
            emit_error('Unknown request.')
    except mysql.connector.Error:
        log.exception('Database error in chat')
        emit_error('The server could not complete that request (storage error).')


def handle_history(client, req):
    if not security.history_limiter.hit(client.user_id):
        emit_error('Slow down.')
        return
    conv = resolve(client, req.get('conv'))
    if conv is None:
        deny(client, req.get('conv'), 'open')
        return
    send_encrypted(client, {'type': 'history', 'conv': conv['id'],
                            'messages': load_history(conv['key'], client.username)})


def handle_send(client, req):
    if not security.message_limiter.hit(client.user_id):
        emit_error('You are sending messages too quickly.')
        return
    conv = resolve(client, req.get('conv'))
    if conv is None:
        deny(client, req.get('conv'), 'open')
        return
    if conv['channel'] and not can_post_channel(client.role, conv['channel']):
        deny(client, conv['id'], 'post in')
        return

    text = security.clean_message(req.get('text'))
    if not text:
        return
    if len(text) > app.config['MAX_MESSAGE_LENGTH']:
        emit_error(f"Messages are limited to {app.config['MAX_MESSAGE_LENGTH']} characters.")
        return

    now = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
    with db.cursor() as cur:
        cur.execute('INSERT INTO messages (conversation, sender, sender_role, recipient, body, created_at) '
                    'VALUES (%s, %s, %s, %s, %s, %s)',
                    (conv['key'], client.username, client.role, conv['peer'],
                     seal(DATA_KEY, text, message_context(conv['key'], client.username)), now))
        msg_id = cur.lastrowid
    deliver({'id': msg_id, 'conversation': conv['key'], 'sender': client.username,
             'sender_role': client.role, 'recipient': conv['peer'], 'created_at': now}, text)
