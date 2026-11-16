# permissions.py
"""Role-based access control: one place that defines what each role may do.

Roles are separated at login (each has its own portal) and each holds an explicit
set of permissions - there is no inheritance between roles.
"""

ROLES = ('soldier', 'officer', 'admin')

ROLE_INFO = {
    'soldier': {'title': 'Soldier', 'summary': 'Secure chat with officers and soldiers.'},
    'officer': {'title': 'Officer', 'summary': 'Secure chat, add and remove soldiers.'},
    'admin':   {'title': 'Admin',   'summary': 'Accounts, login history and the audit log.'},
}

ROLE_PERMISSIONS = {
    'soldier': {'chat'},
    'officer': {'chat', 'manage_soldiers'},
    'admin':   {'manage_accounts', 'login_history', 'security_monitor', 'audit_log',
                'message_vault'},
}

# Which account roles each role may create / delete.
MANAGEABLE_ROLES = {
    'soldier': (),
    'officer': ('soldier',),
    'admin':   ROLES,
}

# Roles that take part in chat (and so appear in the chat member list).
CHAT_ROLES = ('soldier', 'officer')

# Chat channels: which roles may read and post.
CHANNELS = {
    'general': {
        'title': 'General',
        'description': 'Open channel for officers and soldiers',
        'read': {'soldier', 'officer'}, 'post': {'soldier', 'officer'},
    },
    'announcements': {
        'title': 'Announcements',
        'description': 'Orders and notices. Officers post; soldiers read.',
        'read': {'soldier', 'officer'}, 'post': {'officer'},
    },
    'command': {
        'title': 'Command',
        'description': 'Restricted channel for officers',
        'read': {'officer'}, 'post': {'officer'},
    },
}


def has_permission(role, permission):
    return permission in ROLE_PERMISSIONS.get(role, ())


def can_manage(actor_role, target_role):
    return target_role in MANAGEABLE_ROLES.get(actor_role, ())


def can_read_channel(role, channel):
    ch = CHANNELS.get(channel)
    return ch is not None and role in ch['read']


def can_post_channel(role, channel):
    ch = CHANNELS.get(channel)
    return ch is not None and role in ch['post']


def home_endpoint(role):
    """Where each role lands after login."""
    return 'admin' if role == 'admin' else 'chat'
