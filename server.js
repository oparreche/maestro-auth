'use strict';

// Serviço de autenticação do Maestro.
// - Login via OAuth GitHub (Google fica preparado p/ adicionar depois).
// - Emite um JWT com o papel do usuário (gestor | dev | pending).
// - Papéis e permissões são travados AQUI (no servidor), não no app.
// - Bootstrap do primeiro gestor por allowlist de env (GESTOR_LOGINS).
//
// Fluxo de login (desktop/loopback):
//   app abre o navegador em  /auth/github?cb=http://127.0.0.1:<porta>/done&state=<rnd>
//   -> GitHub -> /auth/github/callback -> redireciona para o cb com #token=<jwt>
//   o app captura o token no loopback e guarda.

const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------- config ----------
const PORT = process.env.PORT ? Number(process.env.PORT) : 8080;
const JWT_SECRET = process.env.JWT_SECRET || '';
const GH_ID = process.env.GITHUB_CLIENT_ID || '';
const GH_SECRET = process.env.GITHUB_CLIENT_SECRET || '';
const BB_ID = process.env.BITBUCKET_CLIENT_ID || '';
const BB_SECRET = process.env.BITBUCKET_CLIENT_SECRET || '';
// URL pública deste serviço (p/ montar o callback do OAuth). Ex.: https://auth.seudominio.com
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const GESTOR_LOGINS = splitList(process.env.GESTOR_LOGINS); // github logins que viram gestor
const DEV_LOGINS = splitList(process.env.DEV_LOGINS); // logins pré-aprovados como dev
const TOKEN_TTL = process.env.TOKEN_TTL || '12h';

if (!JWT_SECRET) console.warn('[auth] ⚠ defina JWT_SECRET (segredo p/ assinar os tokens).');
if (!GH_ID || !GH_SECRET) console.warn('[auth] ⚠ defina GITHUB_CLIENT_ID e GITHUB_CLIENT_SECRET.');

function splitList(s) {
  return String(s || '')
    .split(/[,\s]+/)
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean);
}

// ---------- papéis e permissões (fonte da verdade) ----------
// Dev pode tudo, MENOS estas capacidades — exclusivas do gestor:
const GESTOR_ONLY = ['deploy', 'users.manage', 'pipelines.manage', 'access.manage'];
function permissionsFor(role) {
  if (role === 'gestor') return { role, all: true, denied: [] };
  if (role === 'dev') return { role, all: false, denied: GESTOR_ONLY };
  return { role: 'pending', all: false, denied: ['*'] }; // sem acesso até um gestor aprovar
}

// ---------- armazenamento simples (JSON) ----------
const STORE_FILE = path.join(DATA_DIR, 'store.json');
function loadStore() {
  try {
    return JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
  } catch {
    return { users: {}, pipelines: [], accessRules: [] };
  }
}
function saveStore(s) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = STORE_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(s, null, 2));
  fs.renameSync(tmp, STORE_FILE);
}

// Decide o papel de um usuário que está logando.
function resolveRole(store, key, login) {
  const existing = store.users[key];
  if (existing && existing.role) return existing.role; // já cadastrado: mantém
  const l = String(login || '').toLowerCase();
  if (GESTOR_LOGINS.includes(l)) return 'gestor';
  if (store.invites && store.invites[l]) return store.invites[l]; // convidado por um gestor
  if (DEV_LOGINS.includes(l)) return 'dev';
  return 'pending';
}

// ---------- JWT ----------
function signToken(user) {
  return jwt.sign(
    { sub: user.key, login: user.login, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: TOKEN_TTL }
  );
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!tok) return res.status(401).json({ error: 'sem token' });
  try {
    req.claims = jwt.verify(tok, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'token inválido' });
  }
}
function requireGestor(req, res, next) {
  if (req.claims && req.claims.role === 'gestor') return next();
  res.status(403).json({ error: 'apenas gestor' });
}

// ---------- OAuth GitHub ----------
const pending = new Map(); // state -> { cb, exp }
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pending) if (v.exp < now) pending.delete(k);
}, 60 * 1000).unref();

function isLoopback(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost');
  } catch {
    return false;
  }
}

// Finaliza o login: faz upsert do usuário, resolve o papel, assina o JWT e
// devolve pro app pelo loopback. `profile` é normalizado (qualquer provider).
function completeLogin(profile, cb, res) {
  const store = loadStore();
  const key = profile.provider + ':' + profile.id;
  const role = resolveRole(store, key, profile.login);
  const user = {
    key,
    provider: profile.provider,
    login: profile.login,
    name: profile.name || profile.login,
    email: profile.email || null,
    avatar: profile.avatar || null,
    role,
    createdAt: (store.users[key] && store.users[key].createdAt) || new Date().toISOString(),
    lastLogin: new Date().toISOString(),
  };
  store.users[key] = user;
  saveStore(store);
  const token = signToken(user);
  const sep = cb.includes('#') ? '&' : '#';
  res.redirect(cb + sep + 'token=' + encodeURIComponent(token));
}

// Inicia um fluxo OAuth: valida o cb (loopback), guarda o state e redireciona.
function startOAuth(req, res, authUrl, clientId, scope) {
  const cb = String(req.query.cb || '');
  if (!isLoopback(cb)) return res.status(400).send('cb inválido (precisa ser loopback http://127.0.0.1:porta/...)');
  const state = crypto.randomBytes(16).toString('hex');
  pending.set(state, { cb, exp: Date.now() + 10 * 60 * 1000 });
  const u = new URL(authUrl);
  u.searchParams.set('client_id', clientId);
  u.searchParams.set('redirect_uri', PUBLIC_URL + req.path + '/callback');
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('scope', scope);
  u.searchParams.set('state', state);
  res.redirect(u.toString());
}

const app = express();
app.use(express.json());
app.disable('x-powered-by');

app.get('/health', (_req, res) => res.json({ ok: true, service: 'maestro-auth' }));

// quais providers estão configurados (o app usa p/ mostrar os botões)
app.get('/auth/providers', (_req, res) => {
  const list = [];
  if (GH_ID && GH_SECRET) list.push({ id: 'github', label: 'GitHub' });
  if (BB_ID && BB_SECRET) list.push({ id: 'bitbucket', label: 'Bitbucket' });
  res.json({ ok: true, providers: list });
});

// ---- GitHub ----
app.get('/auth/github', (req, res) => startOAuth(req, res, 'https://github.com/login/oauth/authorize', GH_ID, 'read:user user:email'));

app.get('/auth/github/callback', async (req, res) => {
  const { code, state } = req.query;
  const p = pending.get(String(state));
  pending.delete(String(state));
  if (!code || !p) return res.status(400).send('state inválido ou expirado — refaça o login.');
  try {
    const tokJson = await (
      await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ client_id: GH_ID, client_secret: GH_SECRET, code, state }),
      })
    ).json();
    const ghToken = tokJson.access_token;
    if (!ghToken) return res.status(400).send('falha ao autenticar no GitHub');
    const h = { Authorization: 'Bearer ' + ghToken, 'User-Agent': 'maestro-auth', Accept: 'application/vnd.github+json' };
    const gh = await (await fetch('https://api.github.com/user', { headers: h })).json();
    let email = gh.email;
    if (!email) {
      const emails = await (await fetch('https://api.github.com/user/emails', { headers: h })).json();
      const primary = Array.isArray(emails) ? emails.find((e) => e.primary) || emails[0] : null;
      email = primary ? primary.email : null;
    }
    completeLogin({ provider: 'github', id: gh.id, login: gh.login, name: gh.name, email, avatar: gh.avatar_url }, p.cb, res);
  } catch (e) {
    res.status(500).send('erro no login: ' + (e && e.message));
  }
});

// ---- Bitbucket ----
app.get('/auth/bitbucket', (req, res) => startOAuth(req, res, 'https://bitbucket.org/site/oauth2/authorize', BB_ID, 'account email'));

app.get('/auth/bitbucket/callback', async (req, res) => {
  const { code, state } = req.query;
  const p = pending.get(String(state));
  pending.delete(String(state));
  if (!code || !p) return res.status(400).send('state inválido ou expirado — refaça o login.');
  try {
    const basic = Buffer.from(BB_ID + ':' + BB_SECRET).toString('base64');
    const tokJson = await (
      await fetch('https://bitbucket.org/site/oauth2/access_token', {
        method: 'POST',
        headers: { Authorization: 'Basic ' + basic, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code: String(code), redirect_uri: PUBLIC_URL + '/auth/bitbucket/callback' }),
      })
    ).json();
    const bbToken = tokJson.access_token;
    if (!bbToken) return res.status(400).send('falha ao autenticar no Bitbucket');
    const h = { Authorization: 'Bearer ' + bbToken, Accept: 'application/json' };
    const bb = await (await fetch('https://api.bitbucket.org/2.0/user', { headers: h })).json();
    let email = null;
    try {
      const emails = await (await fetch('https://api.bitbucket.org/2.0/user/emails', { headers: h })).json();
      const vals = (emails && emails.values) || [];
      const primary = vals.find((e) => e.is_primary && e.is_confirmed) || vals.find((e) => e.is_primary) || vals[0];
      email = primary ? primary.email : null;
    } catch {}
    completeLogin(
      { provider: 'bitbucket', id: bb.uuid || bb.account_id, login: bb.username || bb.nickname, name: bb.display_name, email, avatar: bb.links && bb.links.avatar && bb.links.avatar.href },
      p.cb,
      res
    );
  } catch (e) {
    res.status(500).send('erro no login: ' + (e && e.message));
  }
});

// ---------- API ----------
app.get('/api/me', auth, (req, res) => {
  const store = loadStore();
  const u = store.users[req.claims.sub] || null;
  res.json({ ok: true, user: u, permissions: permissionsFor(req.claims.role) });
});

// gestão de usuários (gestor)
app.get('/api/users', auth, requireGestor, (_req, res) => {
  const store = loadStore();
  res.json({ ok: true, users: Object.values(store.users) });
});
app.post('/api/users/role', auth, requireGestor, (req, res) => {
  const { key, role } = req.body || {};
  if (!['gestor', 'dev', 'pending'].includes(role)) return res.status(400).json({ error: 'papel inválido' });
  const store = loadStore();
  if (!store.users[key]) return res.status(404).json({ error: 'usuário não encontrado' });
  store.users[key].role = role;
  saveStore(store);
  res.json({ ok: true, user: store.users[key] });
});
// pré-cadastra alguém por login do GitHub (antes do 1º acesso)
app.post('/api/users/invite', auth, requireGestor, (req, res) => {
  const login = String((req.body || {}).login || '').trim().toLowerCase();
  const role = ['gestor', 'dev'].includes((req.body || {}).role) ? req.body.role : 'dev';
  if (!login) return res.status(400).json({ error: 'login ausente' });
  const store = loadStore();
  store.invites = store.invites || {};
  store.invites[login] = role; // aplicado no próximo login desse usuário
  saveStore(store);
  res.json({ ok: true, invites: store.invites });
});

// pipelines (gestor) — CRUD simples
app.get('/api/pipelines', auth, (req, res) => {
  res.json({ ok: true, pipelines: loadStore().pipelines || [] });
});
app.post('/api/pipelines', auth, requireGestor, (req, res) => {
  const store = loadStore();
  store.pipelines = Array.isArray((req.body || {}).pipelines) ? req.body.pipelines : store.pipelines || [];
  saveStore(store);
  res.json({ ok: true, pipelines: store.pipelines });
});

// regras de acesso ao ambiente (gestor)
app.get('/api/access-rules', auth, (req, res) => {
  res.json({ ok: true, accessRules: loadStore().accessRules || [] });
});
app.post('/api/access-rules', auth, requireGestor, (req, res) => {
  const store = loadStore();
  store.accessRules = Array.isArray((req.body || {}).accessRules) ? req.body.accessRules : store.accessRules || [];
  saveStore(store);
  res.json({ ok: true, accessRules: store.accessRules });
});

app.listen(PORT, () => {
  const provs = [GH_ID && GH_SECRET && 'GitHub', BB_ID && BB_SECRET && 'Bitbucket'].filter(Boolean);
  console.log(`[auth] Maestro auth rodando na porta ${PORT}`);
  console.log(`[auth] público: ${PUBLIC_URL}`);
  console.log(`[auth] providers: ${provs.join(', ') || '(nenhum configurado!)'}`);
  for (const pr of [['github', GH_ID && GH_SECRET], ['bitbucket', BB_ID && BB_SECRET]]) {
    if (pr[1]) console.log(`[auth]   callback ${pr[0]}: ${PUBLIC_URL}/auth/${pr[0]}/callback`);
  }
  console.log(`[auth] gestores (allowlist): ${GESTOR_LOGINS.join(', ') || '(nenhum — defina GESTOR_LOGINS)'}`);
});
