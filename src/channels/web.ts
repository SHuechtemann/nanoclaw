import crypto from 'crypto';
import { spawn } from 'child_process';
import http from 'http';

import { ASSISTANT_NAME, WEB_MFA_SECRET, WEB_PORT, WEB_TOKEN } from '../config.js';
import { logger } from '../logger.js';
import { Channel, NewMessage } from '../types.js';
import { ChannelOpts, registerChannel } from './registry.js';

// ── TOTP helpers (RFC 6238, no external deps) ─────────────────────────────────

function base32Decode(s: string): Buffer {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const input = s.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const c of input) {
    const idx = alpha.indexOf(c);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}

function hotp(key: Buffer, counter: number): string {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return String(code % 1_000_000).padStart(6, '0');
}

function verifyTOTP(secret: string, code: string): boolean {
  const key = base32Decode(secret);
  const step = Math.floor(Date.now() / 30_000);
  const normalized = code.replace(/\s/g, '');
  for (let i = -1; i <= 1; i++) {
    if (hotp(key, step + i) === normalized) return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────

const WEB_JID = 'web@nanoclaw';
const WEB_FOLDER = 'web';

// Resolve the claude CLI binary: prefer ~/.local/bin/claude, fall back to PATH
const CLAUDE_BIN = process.env.HOME
  ? `${process.env.HOME}/.local/bin/claude`
  : 'claude';

class WebChannel implements Channel {
  name = 'web';
  private server: http.Server;
  private opts: ChannelOpts;
  private _connected = false;

  // MFA sessions: sessionId → expiry timestamp (ms)
  private sessions = new Map<string, number>();
  private readonly SESSION_TTL = 24 * 60 * 60 * 1000; // 24 h

  // Sia SSE clients
  private sseClients: Set<http.ServerResponse> = new Set();

  // Claude Code state
  private ccSseClients: Set<http.ServerResponse> = new Set();
  private ccSessionId: string | null = null;
  private ccBusy = false;
  private ccLineBuffer = '';
  private ccCurrentText = '';

  constructor(opts: ChannelOpts) {
    this.opts = opts;
    this.server = this.createServer();
  }

  private getBearer(req: http.IncomingMessage): string {
    const authHeader = req.headers['authorization'];
    if (authHeader?.startsWith('Bearer ')) return authHeader.slice(7);
    const url = new URL(req.url ?? '/', `http://localhost:${WEB_PORT}`);
    return url.searchParams.get('token') ?? '';
  }

  private auth(req: http.IncomingMessage): boolean {
    if (!WEB_TOKEN) return true;
    const bearer = this.getBearer(req);
    if (WEB_MFA_SECRET) {
      // MFA mode: bearer must be a valid session UUID
      const expiry = this.sessions.get(bearer);
      if (!expiry || Date.now() > expiry) { this.sessions.delete(bearer); return false; }
      return true;
    }
    // Legacy token mode
    return bearer === WEB_TOKEN;
  }

  private broadcast(data: object): void {
    const payload = `data: ${JSON.stringify(data)}\n\n`;
    for (const client of [...this.sseClients]) {
      try { client.write(payload); }
      catch { this.sseClients.delete(client); }
    }
  }

  private broadcastCC(data: object): void {
    const payload = `data: ${JSON.stringify(data)}\n\n`;
    for (const client of [...this.ccSseClients]) {
      try { client.write(payload); }
      catch { this.ccSseClients.delete(client); }
    }
  }

  private handleCCLine(line: string): void {
    if (!line.trim()) return;
    try {
      const event = JSON.parse(line) as Record<string, unknown>;

      if (event.type === 'system' && event.subtype === 'init') {
        const sid = event.session_id as string;
        this.ccSessionId = sid;
        this.ccCurrentText = '';
        this.broadcastCC({ type: 'cc_session', sessionId: sid.slice(0, 8) });

      } else if (event.type === 'stream_event') {
        // Real-time streaming: extract text deltas from content_block_delta events
        const inner = event.event as Record<string, unknown>;
        if (inner.type === 'content_block_delta') {
          const delta = inner.delta as Record<string, unknown>;
          if (delta.type === 'text_delta' && delta.text) {
            const text = delta.text as string;
            this.ccCurrentText += text;
            this.broadcastCC({ type: 'cc_text_delta', text });
          }
        }

      } else if (event.type === 'assistant') {
        // Fallback: complete message (catches tool_use blocks which don't stream)
        type ContentBlock = { type: string; text?: string; name?: string; input?: unknown };
        const msg = event.message as { content?: ContentBlock[] };
        for (const block of msg.content ?? []) {
          if (block.type === 'tool_use') {
            const input = (block.input ?? {}) as Record<string, unknown>;
            const preview =
              block.name === 'Bash'
                ? String(input.command ?? '').slice(0, 120)
                : JSON.stringify(input).slice(0, 120);
            this.broadcastCC({ type: 'cc_tool', tool: block.name as string, preview });
          }
        }

      } else if (event.type === 'result') {
        this.broadcastCC({ type: 'cc_done', isError: event.is_error ?? false });
        this.ccBusy = false;
        this.ccCurrentText = '';
      }
    } catch {
      // skip malformed NDJSON lines
    }
  }

  private runClaude(prompt: string): void {
    if (this.ccBusy) {
      this.broadcastCC({ type: 'cc_error', message: 'Beschäftigt – bitte warten.' });
      return;
    }
    this.ccBusy = true;
    this.ccCurrentText = '';
    this.ccLineBuffer = '';

    const args = [
      '--print',
      '--verbose',
      '--output-format', 'stream-json',
      '--include-partial-messages',
      '--dangerously-skip-permissions',
    ];
    if (this.ccSessionId) args.push('--resume', this.ccSessionId);
    args.push(prompt);

    logger.info({ bin: CLAUDE_BIN, hasSession: !!this.ccSessionId }, 'Spawning Claude Code');

    const proc = spawn(CLAUDE_BIN, args, {
      cwd: process.cwd(),
      env: { ...process.env },
    });

    proc.stdout.on('data', (chunk: Buffer) => {
      this.ccLineBuffer += chunk.toString();
      const lines = this.ccLineBuffer.split('\n');
      this.ccLineBuffer = lines.pop() ?? '';
      for (const line of lines) this.handleCCLine(line);
    });

    proc.stderr.on('data', (chunk: Buffer) => {
      logger.debug({ stderr: chunk.toString().slice(0, 200) }, 'Claude Code stderr');
    });

    proc.on('close', (code) => {
      if (this.ccLineBuffer.trim()) {
        this.handleCCLine(this.ccLineBuffer);
        this.ccLineBuffer = '';
      }
      if (code !== 0 && this.ccBusy) {
        this.broadcastCC({ type: 'cc_done', isError: true });
      }
      this.ccBusy = false;
    });

    proc.on('error', (err) => {
      logger.error({ err }, 'Failed to spawn Claude Code');
      this.ccBusy = false;
      this.broadcastCC({ type: 'cc_done', isError: true });
    });
  }

  private readBody(req: http.IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', (chunk: Buffer) => { body += chunk; if (body.length > 65_536) reject(new Error('too large')); });
      req.on('end', () => resolve(body));
      req.on('error', reject);
    });
  }

  private createServer(): http.Server {
    return http.createServer(async (req, res) => {
      const url = new URL(req.url ?? '/', `http://localhost:${WEB_PORT}`);
      const { pathname } = url;

      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

      if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

      // ── Public: app info (MFA flag) ──────────────────────────────
      if (pathname === '/api/info' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ mfaRequired: !!WEB_MFA_SECRET }));
        return;
      }

      // ── Public: MFA login (token + TOTP → session) ───────────────
      if (pathname === '/api/auth' && req.method === 'POST') {
        if (!WEB_MFA_SECRET) { res.writeHead(404); res.end('Not found'); return; }
        try {
          const body = await this.readBody(req);
          const { token: t, totp } = JSON.parse(body) as { token?: string; totp?: string };
          if (t !== WEB_TOKEN) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Ungültiger Token.' }));
            return;
          }
          if (!totp || !verifyTOTP(WEB_MFA_SECRET, totp)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Ungültiger MFA-Code.' }));
            return;
          }
          const session = crypto.randomUUID();
          this.sessions.set(session, Date.now() + this.SESSION_TTL);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, session }));
        } catch {
          res.writeHead(400); res.end(JSON.stringify({ error: 'Ungültige Anfrage.' }));
        }
        return;
      }

      // ── Public: serve HTML shell (JS handles token gating) ──────
      if (pathname === '/' || pathname === '/index.html') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(getHtml());
        return;
      }

      // ── Auth guard for all API routes ────────────────────────────
      if (!this.auth(req)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      // ── Status ───────────────────────────────────────────────────
      if (pathname === '/api/status' && req.method === 'GET') {
        const groups = this.opts.registeredGroups();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          ok: true,
          uptime: Math.floor(process.uptime()),
          assistantName: ASSISTANT_NAME,
          registeredGroups: Object.keys(groups).length,
          connected: this._connected,
        }));
        return;
      }

      // ── Sia SSE stream ───────────────────────────────────────────
      if (pathname === '/api/events' && req.method === 'GET') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'X-Accel-Buffering': 'no',   // disable nginx buffering
        });
        res.write(`data: ${JSON.stringify({ type: 'connected', assistantName: ASSISTANT_NAME })}\n\n`);
        this.sseClients.add(res);
        req.on('close', () => this.sseClients.delete(res));
        return;
      }

      // ── Sia message ──────────────────────────────────────────────
      if (pathname === '/api/message' && req.method === 'POST') {
        try {
          const body = await this.readBody(req);
          const { text } = JSON.parse(body) as { text?: string };
          if (!text?.trim()) { res.writeHead(400); res.end(JSON.stringify({ error: 'Missing text' })); return; }
          const timestamp = new Date().toISOString();
          const msg: NewMessage = {
            id: crypto.randomUUID(), chat_jid: WEB_JID,
            sender: 'web-user', sender_name: 'You',
            content: text.trim(), timestamp,
            is_from_me: false, is_bot_message: false,
          };
          this.opts.onChatMetadata(WEB_JID, timestamp, 'Web Chat', 'web', false);
          this.opts.onMessage(WEB_JID, msg);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
        } catch {
          res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
        return;
      }

      // ── Claude Code SSE stream ───────────────────────────────────
      if (pathname === '/api/cc/events' && req.method === 'GET') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'X-Accel-Buffering': 'no',   // disable nginx buffering
        });
        res.write(`data: ${JSON.stringify({ type: 'cc_connected', sessionId: this.ccSessionId?.slice(0, 8) ?? null, busy: this.ccBusy })}\n\n`);
        this.ccSseClients.add(res);
        req.on('close', () => this.ccSseClients.delete(res));
        return;
      }

      // ── Claude Code message ──────────────────────────────────────
      if (pathname === '/api/cc/message' && req.method === 'POST') {
        try {
          const body = await this.readBody(req);
          const { text } = JSON.parse(body) as { text?: string };
          if (!text?.trim()) { res.writeHead(400); res.end(JSON.stringify({ error: 'Missing text' })); return; }
          if (this.ccBusy) { res.writeHead(429); res.end(JSON.stringify({ error: 'Beschäftigt' })); return; }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
          this.runClaude(text.trim());
        } catch {
          res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
        return;
      }

      // ── Claude Code: new session ─────────────────────────────────
      if (pathname === '/api/cc/session/new' && req.method === 'POST') {
        this.ccSessionId = null;
        this.ccCurrentText = '';
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        this.broadcastCC({ type: 'cc_session_reset' });
        return;
      }

      res.writeHead(404); res.end('Not found');
    });
  }

  async connect(): Promise<void> {
    if (!this.opts.registeredGroups()[WEB_JID] && this.opts.registerGroup) {
      this.opts.registerGroup(WEB_JID, {
        name: 'Web Chat', folder: WEB_FOLDER,
        trigger: `@${ASSISTANT_NAME}`, added_at: new Date().toISOString(),
        isMain: false, requiresTrigger: false,
      });
    }
    await new Promise<void>((resolve, reject) => {
      this.server.listen(WEB_PORT, () => { this._connected = true; logger.info({ port: WEB_PORT }, 'Web channel listening'); resolve(); });
      this.server.on('error', reject);
    });
  }

  isConnected(): boolean { return this._connected; }
  ownsJid(jid: string): boolean { return jid === WEB_JID; }

  async sendMessage(_jid: string, text: string): Promise<void> {
    this.broadcast({ type: 'message', sender: 'assistant', text, timestamp: new Date().toISOString() });
  }

  async setTyping(_jid: string, isTyping: boolean): Promise<void> {
    this.broadcast({ type: 'typing', isTyping });
  }

  async disconnect(): Promise<void> {
    this._connected = false;
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }
}

// ── HTML ─────────────────────────────────────────────────────────────────────

function getHtml(): string {
  return `<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NanoClaw</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #f1f5f9; --surface: #ffffff; --border: #e2e8f0;
    --text: #1e293b; --text-muted: #64748b;
    --user-bg: #2563eb; --user-text: #fff;
    --bot-bg: #fff; --bot-border: #e2e8f0;
    --input-bg: #fff;
    --header-bg: #0f172a; --header-text: #f8fafc;
    --status-ok: #22c55e; --status-err: #ef4444;
    --code-bg: #f1f5f9; --pre-bg: #1e293b; --pre-text: #e2e8f0;
    --tab-active-bg: rgba(255,255,255,.2); --tab-inactive: rgba(255,255,255,.08);
    --tool-bg: #f8fafc;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0f172a; --surface: #1e293b; --border: #334155;
      --text: #f1f5f9; --text-muted: #94a3b8;
      --user-bg: #3b82f6; --bot-bg: #1e293b; --bot-border: #334155;
      --input-bg: #1e293b; --code-bg: #0f172a; --tool-bg: #0f172a;
    }
  }
  html, body { height: 100%; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 15px; background: var(--bg); color: var(--text); display: flex; flex-direction: column; height: 100%; }

  /* Header */
  header { background: var(--header-bg); color: var(--header-text); padding: 10px 16px; display: flex; align-items: center; gap: 10px; flex-shrink: 0; user-select: none; }
  header h1 { font-size: 15px; font-weight: 600; }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--status-err); flex-shrink: 0; transition: background .3s; }
  .status-dot.ok { background: var(--status-ok); }
  .status-text { font-size: 11px; color: #64748b; flex: 1; }

  /* Tabs */
  .tabs { display: flex; gap: 3px; }
  .tab-btn { padding: 5px 13px; border: none; border-radius: 6px; background: var(--tab-inactive); color: #94a3b8; font-size: 13px; font-weight: 500; cursor: pointer; transition: background .15s, color .15s; }
  .tab-btn.active { background: var(--tab-active-bg); color: #f8fafc; }
  .tab-btn:hover:not(.active) { background: rgba(255,255,255,.13); color: #cbd5e1; }

  /* Login overlay */
  #login { position: fixed; inset: 0; background: rgba(0,0,0,.55); display: flex; align-items: center; justify-content: center; z-index: 100; }
  #login.hidden { display: none; }
  .login-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 32px 28px; width: min(360px, 90vw); display: flex; flex-direction: column; gap: 14px; }
  .login-card h2 { font-size: 20px; font-weight: 700; }
  .login-card p { font-size: 13px; color: var(--text-muted); }
  .login-card input { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; background: var(--input-bg); color: var(--text); font-size: 14px; font-family: monospace; }
  .login-card input:focus { outline: 2px solid #3b82f6; }
  .login-card button { padding: 10px; background: #2563eb; color: #fff; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; }
  .login-card button:hover { background: #1d4ed8; }
  .login-error { color: #ef4444; font-size: 13px; min-height: 16px; }
  #totp-row { display: none; }
  #totp-row.visible { display: flex; flex-direction: column; gap: 14px; }

  /* Panes */
  .pane { flex: 1; overflow: hidden; display: none; flex-direction: column; min-height: 0; }
  .pane.active { display: flex; }

  /* CC toolbar */
  .cc-toolbar { padding: 7px 16px; background: var(--surface); border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 8px; flex-shrink: 0; font-size: 12px; }
  .cc-toolbar button { padding: 4px 10px; border: 1px solid var(--border); border-radius: 6px; background: transparent; color: var(--text); font-size: 12px; cursor: pointer; }
  .cc-toolbar button:hover { background: var(--border); }
  #cc-session-id { color: var(--text-muted); font-family: monospace; font-size: 11px; }

  /* Messages */
  .messages { flex: 1; overflow-y: auto; padding: 14px 16px; display: flex; flex-direction: column; gap: 9px; }
  .msg { display: flex; flex-direction: column; max-width: 80%; }
  .msg.user { align-self: flex-end; align-items: flex-end; }
  .msg.bot  { align-self: flex-start; align-items: flex-start; }
  .bubble { padding: 9px 13px; border-radius: 14px; line-height: 1.55; word-break: break-word; }
  .msg.user .bubble { background: var(--user-bg); color: var(--user-text); border-bottom-right-radius: 4px; }
  .msg.bot  .bubble { background: var(--bot-bg); border: 1px solid var(--bot-border); border-bottom-left-radius: 4px; color: var(--text); }
  .msg-meta { font-size: 11px; color: var(--text-muted); margin-top: 3px; padding: 0 4px; }

  /* Markdown in bubbles */
  .bubble p   { margin: 0 0 .45em; } .bubble p:last-child { margin: 0; }
  .bubble strong { font-weight: 700; } .bubble em { font-style: italic; }
  .bubble code { font-family: "SFMono-Regular", Consolas, monospace; font-size: .875em; background: var(--code-bg); padding: 1px 5px; border-radius: 4px; }
  .bubble pre { background: var(--pre-bg); color: var(--pre-text); padding: 11px; border-radius: 8px; overflow-x: auto; margin: 5px 0; font-size: .83em; line-height: 1.5; }
  .bubble pre code { background: none; padding: 0; color: inherit; }
  .bubble a { color: #3b82f6; }
  .bubble ul, .bubble ol { padding-left: 1.3em; margin: .25em 0; }

  /* Tool use pill */
  .tool-use { font-size: 11px; color: var(--text-muted); padding: 4px 9px; background: var(--tool-bg); border: 1px solid var(--border); border-radius: 20px; font-family: monospace; max-width: 90%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; align-self: flex-start; }

  /* Typing dots */
  .typing-bubble { background: var(--bot-bg); border: 1px solid var(--bot-border); border-radius: 14px; border-bottom-left-radius: 4px; padding: 11px 14px; display: flex; gap: 5px; align-items: center; align-self: flex-start; }
  .typing-bubble span { width: 7px; height: 7px; background: var(--text-muted); border-radius: 50%; animation: bounce .9s infinite; }
  .typing-bubble span:nth-child(2) { animation-delay: .15s; }
  .typing-bubble span:nth-child(3) { animation-delay: .30s; }
  @keyframes bounce { 0%,60%,100% { transform: translateY(0); } 30% { transform: translateY(-5px); } }

  /* Input bar */
  #inputbar { display: flex; gap: 8px; padding: 11px 16px; background: var(--surface); border-top: 1px solid var(--border); flex-shrink: 0; }
  #inputbar textarea { flex: 1; resize: none; padding: 9px 12px; border: 1px solid var(--border); border-radius: 10px; background: var(--input-bg); color: var(--text); font-family: inherit; font-size: 15px; line-height: 1.4; max-height: 140px; overflow-y: auto; }
  #inputbar textarea:focus { outline: 2px solid #3b82f6; }
  #inputbar button { align-self: flex-end; padding: 9px 17px; background: #2563eb; color: #fff; border: none; border-radius: 10px; font-size: 15px; font-weight: 600; cursor: pointer; white-space: nowrap; }
  #inputbar button:disabled { background: #94a3b8; cursor: default; }
  #inputbar button:not(:disabled):hover { background: #1d4ed8; }
</style>
</head>
<body>

<div id="login">
  <div class="login-card">
    <h2>NanoClaw</h2>
    <p id="loginHint">Gib deinen Zugangs-Token ein.</p>
    <input id="tokenInput" type="password" placeholder="Token" autofocus>
    <div id="totp-row">
      <p style="font-size:13px;color:var(--text-muted)">Gib deinen 6-stelligen Authenticator-Code ein.</p>
      <input id="totpInput" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456">
    </div>
    <button id="loginBtn">Anmelden</button>
    <div class="login-error" id="loginError"></div>
  </div>
</div>

<header>
  <div class="status-dot" id="statusDot"></div>
  <h1 id="headerTitle">NanoClaw</h1>
  <div class="tabs">
    <button class="tab-btn active" id="tab-sia" onclick="switchTab('sia')">Sia</button>
    <button class="tab-btn" id="tab-cc" onclick="switchTab('cc')">Claude Code</button>
  </div>
  <span class="status-text" id="statusText">Verbinde…</span>
</header>

<!-- Sia pane -->
<div id="sia-pane" class="pane active">
  <div id="sia-messages" class="messages"></div>
</div>

<!-- Claude Code pane -->
<div id="cc-pane" class="pane">
  <div class="cc-toolbar">
    <button onclick="newCCSession()">Neue Sitzung</button>
    <span id="cc-session-id"></span>
  </div>
  <div id="cc-messages" class="messages"></div>
</div>

<div id="inputbar">
  <textarea id="msgInput" rows="1" placeholder="Nachricht eingeben…" disabled></textarea>
  <button id="sendBtn" disabled>Senden</button>
</div>

<script>
(function () {
  const TOKEN_KEY = 'nanoclaw_token';
  const SESSION_KEY = 'nanoclaw_session';
  let token = '';      // raw token (no-MFA mode)
  let session = '';    // session UUID (MFA mode)
  let mfaRequired = false;
  let activeTab = 'sia';

  // Sia state
  let siaEvtSource = null;
  let siaTypingEl = null;

  // CC state
  let ccEvtSource = null;
  let ccCurrentBubble = null;
  let ccCurrentText = '';

  const loginEl    = document.getElementById('login');
  const tokenInput = document.getElementById('tokenInput');
  const totpInput  = document.getElementById('totpInput');
  const totpRow    = document.getElementById('totp-row');
  const loginHint  = document.getElementById('loginHint');
  const loginBtn   = document.getElementById('loginBtn');
  const loginError = document.getElementById('loginError');
  const msgInput   = document.getElementById('msgInput');
  const sendBtn    = document.getElementById('sendBtn');
  const statusDot  = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const headerTitle = document.getElementById('headerTitle');

  // ── Tab switching ────────────────────────────────────────────
  window.switchTab = function(tab) {
    activeTab = tab;
    document.getElementById('tab-sia').classList.toggle('active', tab === 'sia');
    document.getElementById('tab-cc').classList.toggle('active', tab === 'cc');
    document.getElementById('sia-pane').classList.toggle('active', tab === 'sia');
    document.getElementById('cc-pane').classList.toggle('active', tab === 'cc');
    if (tab === 'cc' && !ccEvtSource) connectCCSSE();
    msgInput.focus();
  };

  // ── Simple Markdown renderer ─────────────────────────────────
  function renderMarkdown(text) {
    const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const parts = text.split(/(^\`\`\`[\\s\\S]*?\`\`\`$)/m);
    return parts.map((part, i) => {
      if (i % 2 === 1) {
        const lines = part.split('\\n');
        const lang = lines[0].slice(3).trim();
        const code = lines.slice(1, -1).join('\\n');
        return '<pre><code>' + esc(code) + '</code></pre>';
      }
      let s = esc(part);
      s = s.replace(/\`([^\`]+)\`/g, '<code>$1</code>');
      s = s.replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>');
      s = s.replace(/\\*([^*]+)\\*/g, '<em>$1</em>');
      s = s.replace(/\\[([^\\[\\]]+)\\]\\((https?:\\/\\/[^)]+)\\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
      s = s.split(/\\n{2,}/).map(p => '<p>' + p.replace(/\\n/g, '<br>') + '</p>').join('');
      return s;
    }).join('');
  }

  // ── DOM helpers (Sia) ────────────────────────────────────────
  function appendSiaMsg(sender, text, ts) {
    removeSiaTyping();
    const el = makeMsg(sender, text, ts);
    const pane = document.getElementById('sia-messages');
    pane.appendChild(el);
    pane.scrollTop = pane.scrollHeight;
  }
  function showSiaTyping() {
    removeSiaTyping();
    const pane = document.getElementById('sia-messages');
    siaTypingEl = document.createElement('div');
    siaTypingEl.className = 'typing-bubble';
    siaTypingEl.innerHTML = '<span></span><span></span><span></span>';
    pane.appendChild(siaTypingEl);
    pane.scrollTop = pane.scrollHeight;
  }
  function removeSiaTyping() { if (siaTypingEl) { siaTypingEl.remove(); siaTypingEl = null; } }

  // ── DOM helpers (CC) ─────────────────────────────────────────
  function appendCCMsg(sender, text, ts) {
    const el = makeMsg(sender, text, ts);
    const pane = document.getElementById('cc-messages');
    pane.appendChild(el);
    pane.scrollTop = pane.scrollHeight;
  }
  function appendCCTool(tool, preview) {
    const div = document.createElement('div');
    div.className = 'tool-use';
    div.textContent = tool + ': ' + preview;
    const pane = document.getElementById('cc-messages');
    pane.appendChild(div);
    pane.scrollTop = pane.scrollHeight;
  }

  function makeMsg(sender, text, ts) {
    const div = document.createElement('div');
    div.className = 'msg ' + (sender === 'user' ? 'user' : 'bot');
    const bubble = document.createElement('div');
    bubble.className = 'bubble';
    if (sender !== 'user') bubble.innerHTML = renderMarkdown(text);
    else bubble.textContent = text;
    const meta = document.createElement('div');
    meta.className = 'msg-meta';
    meta.textContent = ts ? new Date(ts).toLocaleTimeString() : '';
    div.appendChild(bubble);
    div.appendChild(meta);
    return div;
  }

  // ── API ──────────────────────────────────────────────────────
  function credential() { return mfaRequired ? session : token; }
  function apiFetch(path, opts) {
    return fetch(path, {
      ...(opts || {}),
      headers: { Authorization: 'Bearer ' + credential(), 'Content-Type': 'application/json', ...((opts || {}).headers || {}) },
    });
  }

  // ── Status polling ───────────────────────────────────────────
  async function pollStatus() {
    try {
      const r = await apiFetch('/api/status');
      if (r.ok) {
        const d = await r.json();
        statusText.textContent = fmtUptime(d.uptime) + ' \\u00b7 ' + d.registeredGroups + ' Gruppen';
        statusDot.classList.toggle('ok', d.connected);
        if (d.assistantName) { headerTitle.textContent = 'NanoClaw \\u00b7 ' + d.assistantName; }
      }
    } catch {}
    setTimeout(pollStatus, 30000);
  }
  function fmtUptime(s) {
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'min';
    return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'min';
  }

  // ── Sia SSE ──────────────────────────────────────────────────
  function connectSiaSSE() {
    if (siaEvtSource) siaEvtSource.close();
    siaEvtSource = new EventSource('/api/events?token=' + encodeURIComponent(credential()));
    siaEvtSource.onmessage = (e) => {
      try {
        const d = JSON.parse(e.data);
        if (d.type === 'connected') {
          statusDot.classList.add('ok');
          statusText.textContent = 'Verbunden';
          pollStatus();
        } else if (d.type === 'message') {
          appendSiaMsg(d.sender === 'assistant' ? 'bot' : 'user', d.text, d.timestamp);
        } else if (d.type === 'typing') {
          d.isTyping ? showSiaTyping() : removeSiaTyping();
        }
      } catch {}
    };
    siaEvtSource.onerror = () => {
      statusDot.classList.remove('ok');
      statusText.textContent = 'SSE getrennt – Nachrichten senden weiterhin möglich';
    };
  }

  // ── CC SSE ───────────────────────────────────────────────────
  function connectCCSSE() {
    if (ccEvtSource) ccEvtSource.close();
    ccEvtSource = new EventSource('/api/cc/events?token=' + encodeURIComponent(credential()));
    ccEvtSource.onmessage = (e) => {
      try { handleCCEvent(JSON.parse(e.data)); } catch {}
    };
  }

  function handleCCEvent(d) {
    const pane = document.getElementById('cc-messages');
    const sessionEl = document.getElementById('cc-session-id');

    if (d.type === 'cc_connected' || d.type === 'cc_session') {
      if (sessionEl && d.sessionId) sessionEl.textContent = 'Session ' + d.sessionId + '\\u2026';
      if (d.type === 'cc_connected' && d.busy) {
        // re-attach: a run was already in progress — show indicator
        if (!ccCurrentBubble) createCCStreamBubble();
      }
    } else if (d.type === 'cc_session_reset') {
      if (sessionEl) sessionEl.textContent = 'Neue Sitzung';
      ccCurrentBubble = null; ccCurrentText = '';
    } else if (d.type === 'cc_tool') {
      appendCCTool(d.tool, d.preview);
    } else if (d.type === 'cc_text_delta') {
      if (!ccCurrentBubble) createCCStreamBubble();
      ccCurrentText += d.text;
      ccCurrentBubble.innerHTML = renderMarkdown(ccCurrentText);
      pane.scrollTop = pane.scrollHeight;
    } else if (d.type === 'cc_done') {
      ccCurrentBubble = null;
      ccCurrentText = '';
      sendBtn.disabled = false;
      if (d.isError) appendCCMsg('bot', '(Fehler)', null);
    } else if (d.type === 'cc_error') {
      appendCCMsg('bot', '(Fehler: ' + (d.message || '') + ')', null);
      sendBtn.disabled = false;
    }
  }

  function createCCStreamBubble() {
    const pane = document.getElementById('cc-messages');
    const msgDiv = document.createElement('div');
    msgDiv.className = 'msg bot';
    ccCurrentBubble = document.createElement('div');
    ccCurrentBubble.className = 'bubble';
    const meta = document.createElement('div');
    meta.className = 'msg-meta';
    meta.textContent = new Date().toLocaleTimeString();
    msgDiv.appendChild(ccCurrentBubble);
    msgDiv.appendChild(meta);
    pane.appendChild(msgDiv);
    pane.scrollTop = pane.scrollHeight;
  }

  window.newCCSession = async function() {
    await apiFetch('/api/cc/session/new', { method: 'POST', body: '{}' });
    document.getElementById('cc-messages').innerHTML = '';
    ccCurrentBubble = null; ccCurrentText = '';
  };

  // ── Send message ─────────────────────────────────────────────
  async function sendMessage() {
    const text = msgInput.value.trim();
    if (!text) return;
    msgInput.value = '';
    msgInput.style.height = '';
    sendBtn.disabled = true;

    if (activeTab === 'sia') {
      appendSiaMsg('user', text, new Date().toISOString());
      try {
        const r = await apiFetch('/api/message', { method: 'POST', body: JSON.stringify({ text }) });
        if (!r.ok) appendSiaMsg('bot', '(Fehler)', null);
      } catch { appendSiaMsg('bot', '(Netzwerkfehler)', null); }
      sendBtn.disabled = false;
    } else {
      appendCCMsg('user', text, new Date().toISOString());
      if (!ccEvtSource) connectCCSSE();
      try {
        const r = await apiFetch('/api/cc/message', { method: 'POST', body: JSON.stringify({ text }) });
        if (!r.ok) {
          const d = await r.json().catch(() => ({}));
          appendCCMsg('bot', '(Fehler: ' + (d.error || r.status) + ')', null);
          sendBtn.disabled = false;
        }
        // sendBtn re-enabled by cc_done event
      } catch {
        appendCCMsg('bot', '(Netzwerkfehler)', null);
        sendBtn.disabled = false;
      }
    }
    msgInput.focus();
  }

  // ── Login ────────────────────────────────────────────────────
  function unlockApp() {
    loginEl.classList.add('hidden');
    msgInput.disabled = false;
    sendBtn.disabled = false;
    connectSiaSSE();
    pollStatus();
  }

  async function tryLogin() {
    loginError.textContent = '';
    loginBtn.disabled = true;
    const t = tokenInput.value.trim();
    if (!t) { loginError.textContent = 'Bitte Token eingeben.'; loginBtn.disabled = false; return; }

    try {
      if (mfaRequired) {
        const code = totpInput ? totpInput.value.trim() : '';
        if (!code) {
          // Show TOTP field and ask for code
          totpRow.classList.add('visible');
          loginHint.textContent = 'Token akzeptiert. Bitte Authenticator-Code eingeben.';
          totpInput.focus();
          loginBtn.disabled = false;
          return;
        }
        const r = await fetch('/api/auth', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: t, totp: code }),
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok && d.session) {
          session = d.session;
          localStorage.setItem(SESSION_KEY, session);
          localStorage.setItem(TOKEN_KEY, t);
          unlockApp();
        } else {
          loginError.textContent = d.error || 'Anmeldung fehlgeschlagen.';
          totpInput.value = '';
          totpInput.focus();
        }
      } else {
        const r = await fetch('/api/status', { headers: { Authorization: 'Bearer ' + t } });
        if (r.ok) {
          token = t;
          localStorage.setItem(TOKEN_KEY, token);
          unlockApp();
        } else {
          loginError.textContent = 'Token ungültig.';
        }
      }
    } catch {
      loginError.textContent = 'Verbindungsfehler.';
    } finally {
      loginBtn.disabled = false;
    }
  }

  loginBtn.addEventListener('click', tryLogin);
  tokenInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') tryLogin(); });
  if (totpInput) totpInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') tryLogin(); });

  // ── Input resize + send ──────────────────────────────────────
  msgInput.addEventListener('input', () => {
    msgInput.style.height = 'auto';
    msgInput.style.height = Math.min(msgInput.scrollHeight, 140) + 'px';
  });
  msgInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); if (!sendBtn.disabled) sendMessage(); }
  });
  sendBtn.addEventListener('click', sendMessage);

  // ── Boot ─────────────────────────────────────────────────────
  (async function boot() {
    try {
      const info = await fetch('/api/info').then(r => r.json()).catch(() => ({}));
      mfaRequired = !!info.mfaRequired;
    } catch {}

    if (mfaRequired) {
      session = localStorage.getItem(SESSION_KEY) || '';
      if (session) {
        const r = await fetch('/api/status', { headers: { Authorization: 'Bearer ' + session } }).catch(() => null);
        if (r && r.ok) { unlockApp(); return; }
        localStorage.removeItem(SESSION_KEY);
        session = '';
      }
      // Pre-fill token and show TOTP field if token was saved from a previous login
      const savedToken = localStorage.getItem(TOKEN_KEY) || '';
      if (savedToken) {
        tokenInput.value = savedToken;
        totpRow.classList.add('visible');
        loginHint.textContent = 'Bitte Authenticator-Code eingeben.';
        totpInput.focus();
      }
    } else {
      token = localStorage.getItem(TOKEN_KEY) || '';
      if (token) {
        const r = await fetch('/api/status', { headers: { Authorization: 'Bearer ' + token } }).catch(() => null);
        if (r && r.ok) { unlockApp(); return; }
        localStorage.removeItem(TOKEN_KEY);
        token = '';
      }
    }
  })();

})();
</script>
</body>
</html>`;
}

registerChannel('web', (opts) => {
  if (!WEB_TOKEN) return null;
  return new WebChannel(opts);
});
