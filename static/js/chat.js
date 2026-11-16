// static/js/chat.js
// Client side of the encrypted chat.
//  1. On every (re)connect, generate a fresh AES-256-GCM session key.
//  2. Wrap it with the server's RSA-3072 public key (RSA-OAEP / SHA-256) and send it.
//  3. Every request and event is AES-GCM encrypted JSON with a random 96-bit IV; the
//     direction and a strictly increasing sequence number are bound as associated data,
//     so tampered, reordered or replayed frames are rejected on both sides.
// Conversation ids: 'ch:<channel>' for channels, 'dm:<username>' for direct messages.
(function () {
    'use strict';

    const $ = (id) => document.getElementById(id);
    const config = $('chat-config').dataset;
    const el = {
        chatBox: $('chat-box'), form: $('chat-form'), input: $('msg'), sendBtn: $('send-btn'),
        status: $('status'), error: $('chat-error'), channels: $('channel-list'),
        members: $('member-list'), search: $('sidebar-search'), noResults: $('no-results'),
        title: $('conv-title'), subtitle: $('conv-subtitle'), find: $('find-in-chat'),
        onlineCount: $('online-count'),
    };
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    let sessionKey = null;
    let sendSeq = 0;
    let recvSeq = 0;
    let sendQueue = Promise.resolve();
    let recvQueue = Promise.resolve();

    const state = {
        me: null,
        maxLen: parseInt(el.input.maxLength, 10) || 1000,
        channels: [],             // [{id, title, description, can_post}]
        members: new Map(),       // username -> {username, role, online, last}
        convs: new Map(),         // conv id -> {loaded, requested, messages: Map(id -> msg)}
        unread: new Map(),        // conv id -> count
        active: null,
        connected: false,
    };

    // ------------------------------------------------------------ small helpers

    function setStatus(text, style) {
        el.status.textContent = text;
        el.status.className = 'badge text-bg-' + style;
    }

    function showError(text) {
        el.error.textContent = text;
        clearTimeout(showError.timer);
        showError.timer = setTimeout(() => { el.error.textContent = ''; }, 6000);
    }

    function b64ToBytes(b64) {
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes;
    }

    function bytesToB64(buf) {
        const bytes = new Uint8Array(buf);
        let bin = '';
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin);
    }

    function make(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;   // never innerHTML: no XSS
        return node;
    }

    function roleBadge(role) {
        return make('span', 'badge role-badge role-' + String(role).replace(/[^a-z]/g, ''), role);
    }

    // ------------------------------------------------------------ crypto

    if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
        setStatus('Insecure context', 'danger');
        showError('Encryption needs HTTPS (or localhost). Open this page over https://.');
        return;
    }

    const serverKeyPromise = crypto.subtle.importKey(
        'spki', b64ToBytes(config.serverKey),
        { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);

    async function newHandshake() {
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        const raw = await crypto.subtle.exportKey('raw', key);
        const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, await serverKeyPromise, raw);
        sessionKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
        sendSeq = 0;
        recvSeq = 0;
        return bytesToB64(wrapped);
    }

    async function encrypt(text, seq) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv, additionalData: encoder.encode('c2s|' + seq) },
            sessionKey, encoder.encode(text));
        return { iv: bytesToB64(iv), ct: bytesToB64(ct), seq: seq };
    }

    async function decrypt(box) {
        const pt = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: b64ToBytes(box.iv), additionalData: encoder.encode('s2c|' + box.seq) },
            sessionKey, b64ToBytes(box.ct));
        return decoder.decode(pt);
    }

    function secureSend(request) {
        // Encrypt and emit one at a time so sequence numbers reach the server in order.
        sendQueue = sendQueue.then(async () => {
            if (!sessionKey) return;
            sendSeq += 1;
            socket.emit('secure_message', await encrypt(JSON.stringify(request), sendSeq));
        }).catch((e) => showError('Could not encrypt request: ' + e.message));
    }

    // ------------------------------------------------------------ conversation state

    function getConv(id) {
        if (!state.convs.has(id)) state.convs.set(id, { loaded: false, requested: false, messages: new Map() });
        return state.convs.get(id);
    }

    function channelById(id) {
        return state.channels.find((c) => c.id === id);
    }

    function peerOf(id) {
        return id.startsWith('dm:') ? state.members.get(id.slice(3)) : null;
    }

    function canPost(id) {
        const ch = channelById(id);
        if (ch) return ch.can_post;
        return Boolean(peerOf(id));
    }

    // ------------------------------------------------------------ sidebar

    function sidebarItem(id, label, opts) {
        const btn = make('button', 'list-group-item list-group-item-action d-flex align-items-center gap-2 py-2');
        btn.type = 'button';
        if (id === state.active) btn.classList.add('active');
        if (opts.online !== undefined) {
            const dot = make('span', 'presence-dot ' + (opts.online ? 'online' : 'offline'));
            dot.title = opts.online ? 'online' : 'offline';
            btn.append(dot);
        }
        btn.append(make('span', 'flex-grow-1 text-truncate', label));
        if (opts.role) btn.append(roleBadge(opts.role));
        if (opts.hint) btn.append(make('span', 'small text-muted', opts.hint));
        const unread = state.unread.get(id);
        if (unread) btn.append(make('span', 'badge rounded-pill text-bg-danger', String(unread)));
        btn.addEventListener('click', () => openConversation(id));
        return btn;
    }

    function renderSidebar() {
        const q = el.search.value.trim().toLowerCase();
        let shown = 0;

        el.channels.replaceChildren();
        for (const ch of state.channels) {
            if (q && !ch.title.toLowerCase().includes(q)) continue;
            el.channels.append(sidebarItem(ch.id, '# ' + ch.title, { hint: ch.can_post ? '' : 'read-only' }));
            shown++;
        }

        const people = [...state.members.values()].filter((m) =>
            state.me && m.username !== state.me.username &&
            (!q || m.username.toLowerCase().includes(q) || m.role.includes(q)));
        // Recent conversations first, then online people, then alphabetical.
        people.sort((a, b) => (b.last || '').localeCompare(a.last || '') ||
            (b.online - a.online) || a.username.localeCompare(b.username));
        el.members.replaceChildren();
        for (const m of people) {
            el.members.append(sidebarItem('dm:' + m.username, m.username, { online: m.online, role: m.role }));
            shown++;
        }
        el.noResults.hidden = shown > 0;

        const online = [...state.members.values()].filter((m) => m.online).length;
        el.onlineCount.textContent = online + ' online';
    }

    // ------------------------------------------------------------ conversation pane

    function messageElement(msg) {
        const li = make('li', 'chat-msg' + (state.me && msg.from === state.me.username ? ' own' : ''));
        li.dataset.search = (msg.from + ' ' + msg.text).toLowerCase();
        const meta = make('div', 'chat-meta');
        const when = make('time');
        const date = new Date(msg.ts);
        when.dateTime = msg.ts;
        when.textContent = isNaN(date) ? '' : date.toLocaleString();
        meta.append(make('strong', null, msg.from), ' ', roleBadge(msg.role), ' ', when);
        li.append(meta, make('div', 'chat-text', msg.text));
        return li;
    }

    function applyFind() {
        const q = el.find.value.trim().toLowerCase();
        for (const li of el.chatBox.querySelectorAll('li.chat-msg')) {
            li.hidden = Boolean(q) && !li.dataset.search.includes(q);
        }
    }

    function renderMessages() {
        el.chatBox.replaceChildren();
        if (!state.active) return;
        const conv = getConv(state.active);
        const messages = [...conv.messages.values()].sort((a, b) => a.id - b.id);
        if (!messages.length) {
            el.chatBox.append(make('li', 'text-muted small text-center mt-4',
                conv.loaded ? 'No messages yet.' : 'Loading encrypted history…'));
            return;
        }
        for (const msg of messages) el.chatBox.append(messageElement(msg));
        applyFind();
        el.chatBox.scrollTop = el.chatBox.scrollHeight;
    }

    function renderHeader() {
        const id = state.active;
        const ch = channelById(id);
        const peer = peerOf(id);
        if (ch) {
            el.title.textContent = '# ' + ch.title;
            el.subtitle.textContent = ch.description;
        } else if (peer) {
            el.title.textContent = '@' + peer.username;
            el.subtitle.replaceChildren(roleBadge(peer.role), ' ',
                peer.online ? 'online' : 'offline', ' · private, encrypted direct message');
        }
        const allowed = state.connected && canPost(id);
        el.input.disabled = !allowed;
        el.sendBtn.disabled = !allowed;
        el.input.placeholder = (ch && !ch.can_post)
            ? 'Read-only: only officers and admins can post here'
            : 'Type your message...';
    }

    function openConversation(id) {
        if (!channelById(id) && !peerOf(id)) id = 'ch:general';
        state.active = id;
        state.unread.delete(id);
        el.find.value = '';
        renderHeader();
        renderSidebar();
        renderMessages();
        const conv = getConv(id);
        if (!conv.loaded && !conv.requested) {
            conv.requested = true;
            secureSend({ action: 'history', conv: id });
        }
        if (!el.input.disabled) el.input.focus();
    }

    // ------------------------------------------------------------ server events

    function handleEvent(evt) {
        switch (evt.type) {
        case 'init': {
            state.me = evt.me;
            state.maxLen = evt.max_len || state.maxLen;
            state.channels = evt.channels;
            state.members = new Map(evt.members.map((m) => [m.username, m]));
            for (const r of evt.recent) {
                const m = state.members.get(r.peer);
                if (m) m.last = r.last;
            }
            state.convs = new Map();   // history is re-fetched after every handshake
            openConversation(state.active || 'ch:general');
            break;
        }
        case 'history': {
            const conv = getConv(evt.conv);
            for (const msg of evt.messages) conv.messages.set(msg.id, msg);
            conv.loaded = true;
            if (evt.conv === state.active) renderMessages();
            break;
        }
        case 'message': {
            const conv = getConv(evt.conv);
            conv.messages.set(evt.id, evt);
            const peer = peerOf(evt.conv);
            if (peer) peer.last = evt.ts;
            if (evt.conv === state.active) {
                el.chatBox.querySelector('li:not(.chat-msg)')?.remove();
                el.chatBox.append(messageElement(evt));
                applyFind();
                el.chatBox.scrollTop = el.chatBox.scrollHeight;
            } else {
                state.unread.set(evt.conv, (state.unread.get(evt.conv) || 0) + 1);
            }
            renderSidebar();
            break;
        }
        case 'presence': {
            const m = state.members.get(evt.username) || { username: evt.username, role: evt.role };
            m.online = evt.online;
            m.role = evt.role;
            state.members.set(evt.username, m);
            renderSidebar();
            if (state.active === 'dm:' + evt.username) renderHeader();
            break;
        }
        }
    }

    // ------------------------------------------------------------ socket

    const socket = io({ transports: ['websocket'], upgrade: false });

    function setConnected(connected) {
        state.connected = connected;
        if (state.active) renderHeader();
        else { el.input.disabled = true; el.sendBtn.disabled = true; }
    }

    socket.on('connect', async () => {
        setConnected(false);
        setStatus('Exchanging keys…', 'warning');
        try {
            socket.emit('handshake', { wrapped_key: await newHandshake() });
        } catch (e) {
            setStatus('Key exchange failed', 'danger');
            showError('Could not set up encryption: ' + e.message);
        }
    });

    socket.on('handshake_ok', () => {
        setStatus('🔒 Encrypted', 'success');
        setConnected(true);
    });

    socket.on('secure_message', (box) => {
        if (!sessionKey || typeof box !== 'object' || !Number.isInteger(box.seq) || box.seq <= recvSeq) {
            showError('Dropped an out-of-order or replayed frame.');
            return;
        }
        recvSeq = box.seq;
        // Decrypt strictly in arrival order so events are applied in sequence.
        recvQueue = recvQueue.then(async () => {
            let evt;
            try {
                evt = JSON.parse(await decrypt(box));
            } catch (e) {
                showError('A frame failed its integrity check and was discarded.');
                return;
            }
            handleEvent(evt);
        });
    });

    socket.on('chat_error', (text) => showError(String(text)));

    socket.on('session_expired', () => {
        setConnected(false);
        setStatus('Session ended', 'secondary');
        window.location.href = '/login';
    });

    socket.on('connect_error', () => {
        setConnected(false);
        setStatus('Disconnected', 'danger');
        if (!socket.active) window.location.href = '/login';   // refused: not logged in
    });

    socket.on('disconnect', (reason) => {
        setConnected(false);
        sessionKey = null;
        setStatus('Disconnected', 'danger');
        if (reason === 'io server disconnect') window.location.href = '/login';
    });

    // ------------------------------------------------------------ UI events

    el.search.addEventListener('input', renderSidebar);
    el.find.addEventListener('input', applyFind);

    el.form.addEventListener('submit', (event) => {
        event.preventDefault();   // Enter key and Send button both land here
        const text = el.input.value.trim();
        if (!text || !state.active || el.input.disabled) return;
        if (text.length > state.maxLen) {
            showError('Messages are limited to ' + state.maxLen + ' characters.');
            return;
        }
        el.input.value = '';
        secureSend({ action: 'send', conv: state.active, text: text });
    });
})();
