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
  let s;
  try {
    s = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
  } catch {
    s = {};
  }
  // garante as chaves (e migra stores antigos sem quebrar)
  s.users = s.users || {}; // legado (modelo provider:id) — mantido p/ compat
  s.invites = s.invites || {};
  s.pipelines = s.pipelines || [];
  s.accessRules = s.accessRules || [];
  s.nucleos = s.nucleos || {}; // id -> { id,name,ownerKey,createdAt,projects:[],workspaces:[] }
  s.memberships = s.memberships || {}; // nucleoId -> userKey -> { caps:[],projectIds,invitedBy,joinedAt }
  s.nucleoInvites = s.nucleoInvites || {}; // nucleoId -> [ { token,login?,caps,projectIds,createdBy,createdAt,expiresAt,acceptedBy } ]
  // conta canônica por e-mail + conexões de provedor (N por provedor)
  s.accounts = s.accounts || {}; // accId -> { id,primaryEmail,emails{},name,avatar,role,createdAt,lastLogin }
  s.connections = s.connections || {}; // connId -> { id,accountId,provider,providerUserId,login,name,avatar,email,emailVerified,legacyKey,createdAt,lastUsedAt }
  s.connByProvider = s.connByProvider || {}; // "github:123" -> connId
  s.schemaVersion = s.schemaVersion || 1;
  return s;
}
function saveStore(s) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = STORE_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(s, null, 2));
  fs.renameSync(tmp, STORE_FILE);
}
// transação atômica: como os handlers de núcleo são síncronos do load ao save
// (sem await no meio), o Node garante exclusão mútua entre requisições.
function mutate(fn) {
  const store = loadStore();
  const r = fn(store);
  saveStore(store);
  return r;
}

// ---------- Núcleos (times) — permissões por núcleo ----------
const NUCLEO_CAPS = [
  'sessions.view',
  'sessions.resume',
  'code.view',
  'mcp.manage',
  'automations.manage',
  'deploy',
  'members.manage',
  'projects.manage',
];
function genId(prefix) {
  return prefix + '_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
}

// ---------- conta canônica + conexões ----------
// O `principal` (claims.sub) pode ser um accountId (JWT v2) OU um legado
// "provider:id" (JWT v1, durante a janela de 12h). Resolve p/ o accountId.
function canonicalAccountId(store, principal) {
  if (!principal) return null;
  if (store.accounts[principal]) return principal;
  const connId = store.connByProvider[principal];
  if (connId && store.connections[connId]) return store.connections[connId].accountId;
  return principal; // legado sem conexão mapeada ainda
}
// Todas as chaves que representam esta conta (accountId + chaves legadas das
// conexões). Usado p/ resolução dual-key dos Núcleos (ownerKey/membros antigos).
function keysFor(store, principal) {
  const accId = canonicalAccountId(store, principal);
  const keys = new Set([accId, principal]);
  for (const c of Object.values(store.connections)) {
    if (c.accountId === accId) {
      keys.add(c.legacyKey || c.provider + ':' + c.providerUserId);
    }
  }
  return keys;
}
// logins (provider:login) de uma conta — p/ GESTOR_LOGINS/invite-bind.
function accountLogins(store, accId) {
  return Object.values(store.connections)
    .filter((c) => c.accountId === accId)
    .map((c) => String(c.login || '').toLowerCase())
    .filter(Boolean);
}
function findAccountByVerifiedEmail(store, email) {
  const e = String(email || '').toLowerCase();
  if (!e) return null;
  for (const a of Object.values(store.accounts)) {
    if (a.emails && a.emails[e] && a.emails[e].verified) return a.id;
  }
  return null;
}
// papel global da conta: gestor se algum login está no GESTOR_LOGINS; senão
// mantém o que já tem; senão dev (DEV_LOGINS/convite por login); senão pending.
function effectiveRole(store, accId, current) {
  const logins = accountLogins(store, accId);
  if (logins.some((l) => GESTOR_LOGINS.includes(l))) return 'gestor';
  if (current && current !== 'pending') return current;
  if (logins.some((l) => store.invites[l])) return store.invites[logins.find((l) => store.invites[l])];
  if (logins.some((l) => DEV_LOGINS.includes(l))) return 'dev';
  return current || 'pending';
}

// papel do usuário dentro de um núcleo: dono (tudo), membro (whitelist) ou null.
// `principal` = claims.sub (accountId v2 ou provider:id v1). Resolução dual-key.
function nucleoRoleFor(store, nucleoId, principal) {
  const n = store.nucleos[nucleoId];
  if (!n) return null;
  const keys = keysFor(store, principal);
  if (keys.has(n.ownerKey)) return { owner: true, caps: NUCLEO_CAPS.slice(), projectIds: null };
  const ms = store.memberships[nucleoId] || {};
  for (const k of keys) {
    if (ms[k]) return { owner: false, caps: Array.isArray(ms[k].caps) ? ms[k].caps : [], projectIds: ms[k].projectIds || null };
  }
  return null;
}
function canInNucleo(store, principal, nucleoId, cap, projectId) {
  const r = nucleoRoleFor(store, nucleoId, principal);
  if (!r) return false;
  if (r.owner) return true;
  if (!r.caps.includes(cap)) return false;
  if (projectId && r.projectIds && !r.projectIds.includes(projectId)) return false;
  return true;
}
// resumo dos núcleos que o usuário acessa (dono + membro) p/ o /api/me e a lista.
function nucleosForUser(store, principal) {
  const out = [];
  for (const id of Object.keys(store.nucleos)) {
    const n = store.nucleos[id];
    const r = nucleoRoleFor(store, id, principal);
    if (!r) continue;
    out.push({
      id,
      name: n.name,
      owner: r.owner,
      caps: r.caps,
      projectIds: r.projectIds,
      ownerKey: n.ownerKey,
      projectCount: (n.projects || []).length,
      workspaceCount: (n.workspaces || []).length,
      memberCount: 1 + Object.keys(store.memberships[id] || {}).length,
    });
  }
  return out;
}

// ---------- JWT (v2: sub=accountId, logins[], cv:2) ----------
function signToken(account, store) {
  return jwt.sign(
    { sub: account.id, name: account.name, role: account.role, logins: accountLogins(store, account.id), cv: 2 },
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

// upsert de conexão + conta. Em LOGIN (connectAccountId vazio): acha/cria a conta
// (vínculo por e-mail verificado). Em CONNECT (connectAccountId): anexa à conta atual.
// Retorna { accountId, connId } ou { error }.
function upsertConnection(store, profile, connectAccountId) {
  const NOW = new Date().toISOString();
  const legacyKey = profile.provider + ':' + profile.id;
  let connId = store.connByProvider[legacyKey];
  let accountId;
  if (connId && store.connections[connId]) {
    accountId = store.connections[connId].accountId;
    if (connectAccountId && connectAccountId !== accountId) {
      return { error: 'Essa conta de ' + profile.provider + ' já está vinculada a outra conta Maestro.' };
    }
    Object.assign(store.connections[connId], {
      login: profile.login, name: profile.name || profile.login, avatar: profile.avatar || null,
      email: profile.email || null, emailVerified: !!profile.emailVerified, lastUsedAt: NOW,
    });
  } else {
    const verifiedEmail = profile.emailVerified && profile.email ? String(profile.email).toLowerCase() : null;
    if (connectAccountId) {
      accountId = connectAccountId; // anexa à conta autenticada
    } else {
      accountId = verifiedEmail ? findAccountByVerifiedEmail(store, verifiedEmail) : null;
      if (!accountId) {
        accountId = genId('acc');
        store.accounts[accountId] = {
          id: accountId, primaryEmail: verifiedEmail || profile.email || null, emails: {},
          name: profile.name || profile.login, avatar: profile.avatar || null,
          role: 'pending', createdAt: NOW, lastLogin: NOW,
        };
      }
    }
    connId = genId('conn');
    store.connections[connId] = {
      id: connId, accountId, provider: profile.provider, providerUserId: String(profile.id),
      login: profile.login, name: profile.name || profile.login, avatar: profile.avatar || null,
      email: profile.email || null, emailVerified: !!profile.emailVerified, legacyKey, createdAt: NOW, lastUsedAt: NOW,
    };
    store.connByProvider[legacyKey] = connId;
    if (verifiedEmail && store.accounts[accountId]) {
      store.accounts[accountId].emails[verifiedEmail] = { verified: true, via: connId, addedAt: NOW };
      if (!store.accounts[accountId].primaryEmail) store.accounts[accountId].primaryEmail = verifiedEmail;
    }
  }
  const acc = store.accounts[accountId];
  acc.lastLogin = NOW;
  acc.role = effectiveRole(store, accountId, acc.role);
  if (!acc.name && profile.name) acc.name = profile.name;
  if (!acc.avatar && profile.avatar) acc.avatar = profile.avatar;
  return { accountId, connId };
}

// Finaliza login/connect: upsert da conexão, assina o JWT (v2) e devolve pro app
// pelo loopback. `connectAccountId` setado = modo CONNECT (anexa sem trocar conta).
function completeLogin(profile, cb, res, providerToken, connectAccountId) {
  const store = loadStore();
  const r = upsertConnection(store, profile, connectAccountId);
  if (r.error) return res.status(409).send(r.error);
  saveStore(store);
  const acc = store.accounts[r.accountId];
  const token = signToken(acc, store);
  const sep = cb.includes('#') ? '&' : '#';
  // o provider token NÃO é persistido aqui — só repassado ao app local (loopback),
  // guardado localmente por conexão (cid) p/ listar os repos. Cada um tem sua credencial.
  let frag = 'token=' + encodeURIComponent(token);
  if (providerToken) {
    frag += '&pt=' + encodeURIComponent(providerToken) + '&pp=' + encodeURIComponent(profile.provider) + '&cid=' + encodeURIComponent(r.connId);
  }
  res.redirect(cb + sep + frag);
}

// Monta a URL do provedor; guarda o state com mode (login|connect) + accountId
// (no servidor, nunca na URL). Sempre usa o callback registrado /auth/<provider>/callback.
function buildOAuthUrl(provider, authUrl, clientId, scope, cb, mode, accountId) {
  const state = crypto.randomBytes(16).toString('hex');
  pending.set(state, { cb, exp: Date.now() + 10 * 60 * 1000, mode: mode || 'login', accountId: accountId || null });
  const u = new URL(authUrl);
  u.searchParams.set('client_id', clientId);
  u.searchParams.set('redirect_uri', PUBLIC_URL + '/auth/' + provider + '/callback');
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('scope', scope);
  u.searchParams.set('state', state);
  return u.toString();
}
const GH_AUTH = 'https://github.com/login/oauth/authorize';
const GH_SCOPE = 'read:user user:email repo';
const BB_AUTH = 'https://bitbucket.org/site/oauth2/authorize';
const BB_SCOPE = 'account email repository';
const PROV = { github: { authUrl: GH_AUTH, id: GH_ID, scope: GH_SCOPE }, bitbucket: { authUrl: BB_AUTH, id: BB_ID, scope: BB_SCOPE } };
// LOGIN: redireciona pro provedor. CONNECT: exige JWT e devolve a URL (o app abre).
function startLoginRoute(provider) {
  return (req, res) => {
    const cb = String(req.query.cb || '');
    if (!isLoopback(cb)) return res.status(400).send('cb inválido (precisa ser loopback http://127.0.0.1:porta/...)');
    const c = PROV[provider];
    res.redirect(buildOAuthUrl(provider, c.authUrl, c.id, c.scope, cb, 'login'));
  };
}
function startConnectRoute(provider) {
  return (req, res) => {
    const cb = String(req.query.cb || '');
    if (!isLoopback(cb)) return res.status(400).json({ error: 'cb inválido' });
    const store = loadStore();
    const accountId = canonicalAccountId(store, req.claims.sub);
    const c = PROV[provider];
    res.json({ ok: true, url: buildOAuthUrl(provider, c.authUrl, c.id, c.scope, cb, 'connect', accountId) });
  };
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
app.get('/auth/github', startLoginRoute('github'));
app.get('/auth/github/connect', auth, startConnectRoute('github'));
app.get('/auth/bitbucket/connect', auth, startConnectRoute('bitbucket'));

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
    // e-mail VERIFICADO (não confiar no e-mail público do perfil p/ vínculo de conta)
    let email = null;
    let emailVerified = false;
    try {
      const emails = await (await fetch('https://api.github.com/user/emails', { headers: h })).json();
      if (Array.isArray(emails)) {
        const pick = emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified) || emails.find((e) => e.primary) || emails[0];
        if (pick) { email = pick.email; emailVerified = !!pick.verified; }
      }
    } catch {}
    if (!email) { email = gh.email || null; emailVerified = false; }
    const connectAccountId = p.mode === 'connect' ? p.accountId : null;
    completeLogin({ provider: 'github', id: gh.id, login: gh.login, name: gh.name, email, emailVerified, avatar: gh.avatar_url }, p.cb, res, ghToken, connectAccountId);
  } catch (e) {
    res.status(500).send('erro no login: ' + (e && e.message));
  }
});

// ---- Bitbucket ----
app.get('/auth/bitbucket', startLoginRoute('bitbucket'));

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
    let emailVerified = false;
    try {
      const emails = await (await fetch('https://api.bitbucket.org/2.0/user/emails', { headers: h })).json();
      const vals = (emails && emails.values) || [];
      const pick = vals.find((e) => e.is_primary && e.is_confirmed) || vals.find((e) => e.is_confirmed) || vals.find((e) => e.is_primary) || vals[0];
      if (pick) { email = pick.email; emailVerified = !!pick.is_confirmed; }
    } catch {}
    const connectAccountId = p.mode === 'connect' ? p.accountId : null;
    completeLogin(
      { provider: 'bitbucket', id: bb.uuid || bb.account_id, login: bb.username || bb.nickname, name: bb.display_name, email, emailVerified, avatar: bb.links && bb.links.avatar && bb.links.avatar.href },
      p.cb,
      res,
      bbToken,
      connectAccountId
    );
  } catch (e) {
    res.status(500).send('erro no login: ' + (e && e.message));
  }
});

// ---------- API ----------
// visão de uma conta p/ o app (user p/ compat + account + connections).
function accountView(store, accId) {
  const a = store.accounts[accId];
  if (!a) return null;
  const conns = Object.values(store.connections)
    .filter((c) => c.accountId === accId)
    .map((c) => ({ id: c.id, provider: c.provider, login: c.login, name: c.name, avatar: c.avatar, email: c.email, emailVerified: c.emailVerified }));
  const primaryLogin = conns[0] ? conns[0].login : a.primaryEmail || accId;
  return {
    account: { id: a.id, primaryEmail: a.primaryEmail, name: a.name, avatar: a.avatar, role: a.role, emails: Object.keys(a.emails || {}) },
    connections: conns,
    user: { key: a.id, login: primaryLogin, name: a.name || primaryLogin, avatar: a.avatar, role: a.role, provider: conns[0] ? conns[0].provider : null },
  };
}
// nome/login p/ exibir um principal (accountId, legado provider:id, etc.)
function principalDisplay(store, key) {
  const accId = canonicalAccountId(store, key);
  const a = store.accounts[accId];
  if (a) { const v = accountView(store, accId); return { login: v.user.login, name: a.name || v.user.login, avatar: a.avatar }; }
  const legacy = store.users[key];
  if (legacy) return { login: legacy.login, name: legacy.name || legacy.login, avatar: legacy.avatar || null };
  return { login: key, name: key, avatar: null };
}

app.get('/api/me', auth, (req, res) => {
  const store = loadStore();
  const accId = canonicalAccountId(store, req.claims.sub);
  const v = accountView(store, accId);
  res.json({
    ok: true,
    user: v ? v.user : null,
    account: v ? v.account : null,
    connections: v ? v.connections : [],
    permissions: permissionsFor((v && v.user.role) || req.claims.role),
    nucleos: nucleosForUser(store, req.claims.sub),
    nucleoCaps: NUCLEO_CAPS,
  });
});

// gestão de usuários (gestor) — agora lista CONTAS
app.get('/api/users', auth, requireGestor, (_req, res) => {
  const store = loadStore();
  const users = Object.values(store.accounts).map((a) => {
    const v = accountView(store, a.id);
    return { key: a.id, login: v.user.login, name: a.name, role: a.role, email: a.primaryEmail, provider: v.user.provider, logins: accountLogins(store, a.id) };
  });
  res.json({ ok: true, users });
});
app.post('/api/users/role', auth, requireGestor, (req, res) => {
  const { key, role } = req.body || {};
  if (!['gestor', 'dev', 'pending'].includes(role)) return res.status(400).json({ error: 'papel inválido' });
  const store = loadStore();
  if (!store.accounts[key]) return res.status(404).json({ error: 'conta não encontrada' });
  store.accounts[key].role = role;
  saveStore(store);
  res.json({ ok: true });
});
// desconectar uma conexão da minha conta
app.post('/api/connections/disconnect', auth, (req, res) => {
  const store = loadStore();
  const accId = canonicalAccountId(store, req.claims.sub);
  const connId = String((req.body || {}).connId || '');
  const c = store.connections[connId];
  if (!c || c.accountId !== accId) return res.status(404).json({ error: 'conexão não encontrada' });
  // remove o e-mail do conjunto de auto-vínculo se foi essa conexão que o trouxe
  const acc = store.accounts[accId];
  if (acc && acc.emails) for (const e of Object.keys(acc.emails)) if (acc.emails[e].via === connId) delete acc.emails[e];
  delete store.connByProvider[c.legacyKey || c.provider + ':' + c.providerUserId];
  delete store.connections[connId];
  saveStore(store);
  res.json({ ok: true });
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

// ---------- Núcleos (times) ----------
// helper: carrega o store, exige o núcleo existir e a capacidade; senão responde erro.
function withNucleoCap(req, res, cap, fn) {
  const store = loadStore();
  const id = req.params.id;
  if (!store.nucleos[id]) return res.status(404).json({ error: 'núcleo não encontrado' });
  if (!canInNucleo(store, req.claims.sub, id, cap)) return res.status(403).json({ error: 'sem permissão neste núcleo' });
  return fn(store, store.nucleos[id]);
}
function nucleoDetail(store, id) {
  const n = store.nucleos[id];
  const members = [];
  const od = principalDisplay(store, n.ownerKey);
  members.push({ userKey: n.ownerKey, login: od.login, name: od.name, avatar: od.avatar, role: 'owner', caps: NUCLEO_CAPS.slice(), projectIds: null });
  const ms = store.memberships[id] || {};
  for (const k of Object.keys(ms)) {
    const d = principalDisplay(store, k);
    members.push({
      userKey: k,
      login: ms[k].login || d.login,
      name: d.name,
      avatar: d.avatar,
      role: 'member',
      caps: ms[k].caps || [],
      projectIds: ms[k].projectIds || null,
      invitedBy: ms[k].invitedBy || null,
    });
  }
  return { ...n, members };
}

// listar meus núcleos (dono + membro)
app.get('/api/nucleos', auth, (req, res) => {
  res.json({ ok: true, nucleos: nucleosForUser(loadStore(), req.claims.sub), caps: NUCLEO_CAPS });
});
// criar núcleo (qualquer logado vira dono)
app.post('/api/nucleos', auth, (req, res) => {
  const name = String((req.body || {}).name || '').trim().slice(0, 80);
  if (!name) return res.status(400).json({ error: 'nome ausente' });
  const n = mutate((store) => {
    const id = genId('ncl');
    const nucleo = { id, name, ownerKey: canonicalAccountId(store, req.claims.sub), createdAt: new Date().toISOString(), projects: [], workspaces: [] };
    store.nucleos[id] = nucleo;
    store.memberships[id] = store.memberships[id] || {};
    store.nucleoInvites[id] = store.nucleoInvites[id] || [];
    return nucleo;
  });
  res.json({ ok: true, nucleo: n });
});
// detalhe (membro ou dono)
app.get('/api/nucleos/:id', auth, (req, res) => {
  const store = loadStore();
  if (!store.nucleos[req.params.id]) return res.status(404).json({ error: 'núcleo não encontrado' });
  if (!nucleoRoleFor(store, req.params.id, req.claims.sub)) return res.status(403).json({ error: 'sem acesso a este núcleo' });
  res.json({ ok: true, nucleo: nucleoDetail(store, req.params.id), me: nucleoRoleFor(store, req.params.id, req.claims.sub) });
});
// renomear (projects.manage)
app.patch('/api/nucleos/:id', auth, (req, res) => {
  withNucleoCap(req, res, 'projects.manage', (store, n) => {
    const name = String((req.body || {}).name || '').trim().slice(0, 80);
    if (name) n.name = name;
    saveStore(store);
    res.json({ ok: true, nucleo: n });
  });
});
// excluir (só dono)
app.delete('/api/nucleos/:id', auth, (req, res) => {
  const store = loadStore();
  const n = store.nucleos[req.params.id];
  if (!n) return res.status(404).json({ error: 'núcleo não encontrado' });
  if (!keysFor(store, req.claims.sub).has(n.ownerKey)) return res.status(403).json({ error: 'só o dono exclui o núcleo' });
  delete store.nucleos[req.params.id];
  delete store.memberships[req.params.id];
  delete store.nucleoInvites[req.params.id];
  saveStore(store);
  res.json({ ok: true });
});

// ---- projetos do núcleo ----
app.post('/api/nucleos/:id/projects', auth, (req, res) => {
  withNucleoCap(req, res, 'projects.manage', (store, n) => {
    const b = req.body || {};
    if (!b.fullName || !b.provider) return res.status(400).json({ error: 'projeto inválido (fullName/provider)' });
    if ((n.projects || []).some((p) => p.provider === b.provider && p.fullName === b.fullName)) {
      return res.status(409).json({ error: 'projeto já está no núcleo' });
    }
    const prj = {
      id: genId('prj'),
      provider: String(b.provider),
      remoteId: b.remoteId != null ? String(b.remoteId) : '',
      fullName: String(b.fullName),
      cloneUrl: String(b.cloneUrl || ''),
      defaultBranch: String(b.defaultBranch || 'main'),
      addedBy: req.claims.sub,
      addedAt: new Date().toISOString(),
    };
    n.projects = n.projects || [];
    n.projects.push(prj);
    saveStore(store);
    res.json({ ok: true, project: prj });
  });
});
app.delete('/api/nucleos/:id/projects/:prjId', auth, (req, res) => {
  withNucleoCap(req, res, 'projects.manage', (store, n) => {
    n.projects = (n.projects || []).filter((p) => p.id !== req.params.prjId);
    // tira o projeto de qualquer workspace que o referencie
    n.workspaces = (n.workspaces || []).map((w) => ({ ...w, projectIds: (w.projectIds || []).filter((x) => x !== req.params.prjId) }));
    saveStore(store);
    res.json({ ok: true });
  });
});
// conexão de provedor a usar p/ ESTE projeto (override do workspace)
app.patch('/api/nucleos/:id/projects/:prjId', auth, (req, res) => {
  withNucleoCap(req, res, 'projects.manage', (store, n) => {
    const pr = (n.projects || []).find((p) => p.id === req.params.prjId);
    if (!pr) return res.status(404).json({ error: 'projeto não encontrado' });
    if ('connectionId' in (req.body || {})) pr.connectionId = req.body.connectionId || null;
    saveStore(store);
    res.json({ ok: true });
  });
});

// ---- workspaces do núcleo (metadado) ----
app.post('/api/nucleos/:id/workspaces', auth, (req, res) => {
  withNucleoCap(req, res, 'projects.manage', (store, n) => {
    const name = String((req.body || {}).name || '').trim().slice(0, 80);
    if (!name) return res.status(400).json({ error: 'nome ausente' });
    const ws = { id: genId('wsp'), name, projectIds: Array.isArray((req.body || {}).projectIds) ? req.body.projectIds : [], createdAt: new Date().toISOString() };
    n.workspaces = n.workspaces || [];
    n.workspaces.push(ws);
    saveStore(store);
    res.json({ ok: true, workspace: ws });
  });
});
app.patch('/api/nucleos/:id/workspaces/:wsId', auth, (req, res) => {
  withNucleoCap(req, res, 'projects.manage', (store, n) => {
    const ws = (n.workspaces || []).find((w) => w.id === req.params.wsId);
    if (!ws) return res.status(404).json({ error: 'workspace não encontrado' });
    const b = req.body || {};
    if ('connectionId' in b) ws.connectionId = b.connectionId || null;
    if ('name' in b) { const nm = String(b.name || '').trim().slice(0, 80); if (nm) ws.name = nm; }
    if (Array.isArray(b.projectIds)) ws.projectIds = b.projectIds;
    saveStore(store);
    res.json({ ok: true });
  });
});
app.delete('/api/nucleos/:id/workspaces/:wsId', auth, (req, res) => {
  withNucleoCap(req, res, 'projects.manage', (store, n) => {
    n.workspaces = (n.workspaces || []).filter((w) => w.id !== req.params.wsId);
    saveStore(store);
    res.json({ ok: true });
  });
});

// ---- membros ----
app.get('/api/nucleos/:id/members', auth, (req, res) => {
  const store = loadStore();
  if (!store.nucleos[req.params.id]) return res.status(404).json({ error: 'núcleo não encontrado' });
  if (!nucleoRoleFor(store, req.params.id, req.claims.sub)) return res.status(403).json({ error: 'sem acesso' });
  res.json({ ok: true, members: nucleoDetail(store, req.params.id).members });
});
app.patch('/api/nucleos/:id/members/:userKey', auth, (req, res) => {
  withNucleoCap(req, res, 'members.manage', (store, n) => {
    const k = req.params.userKey;
    if (k === n.ownerKey) return res.status(400).json({ error: 'o dono tem todas as permissões' });
    const ms = (store.memberships[req.params.id] = store.memberships[req.params.id] || {});
    if (!ms[k]) return res.status(404).json({ error: 'membro não encontrado' });
    const b = req.body || {};
    if (Array.isArray(b.caps)) ms[k].caps = b.caps.filter((c) => NUCLEO_CAPS.includes(c));
    if ('projectIds' in b) ms[k].projectIds = Array.isArray(b.projectIds) ? b.projectIds : null;
    saveStore(store);
    res.json({ ok: true });
  });
});
app.delete('/api/nucleos/:id/members/:userKey', auth, (req, res) => {
  withNucleoCap(req, res, 'members.manage', (store, n) => {
    const k = req.params.userKey;
    if (k === n.ownerKey) return res.status(400).json({ error: 'não dá p/ remover o dono' });
    const ms = store.memberships[req.params.id] || {};
    delete ms[k];
    saveStore(store);
    res.json({ ok: true });
  });
});

// ---- convites ----
app.post('/api/nucleos/:id/invites', auth, (req, res) => {
  withNucleoCap(req, res, 'members.manage', (store, n) => {
    const b = req.body || {};
    const caps = Array.isArray(b.caps) ? b.caps.filter((c) => NUCLEO_CAPS.includes(c)) : ['sessions.view'];
    const invite = {
      token: genId('inv'),
      login: b.login ? String(b.login).trim().toLowerCase() : null,
      provider: b.provider ? String(b.provider) : null,
      caps,
      projectIds: Array.isArray(b.projectIds) ? b.projectIds : null,
      createdBy: req.claims.sub,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
      acceptedBy: null,
    };
    store.nucleoInvites[req.params.id] = store.nucleoInvites[req.params.id] || [];
    store.nucleoInvites[req.params.id].push(invite);
    saveStore(store);
    res.json({ ok: true, invite });
  });
});
app.get('/api/nucleos/:id/invites', auth, (req, res) => {
  withNucleoCap(req, res, 'members.manage', (store) => {
    const list = (store.nucleoInvites[req.params.id] || []).filter((i) => !i.acceptedBy);
    res.json({ ok: true, invites: list });
  });
});
app.delete('/api/nucleos/:id/invites/:token', auth, (req, res) => {
  withNucleoCap(req, res, 'members.manage', (store) => {
    store.nucleoInvites[req.params.id] = (store.nucleoInvites[req.params.id] || []).filter((i) => i.token !== req.params.token);
    saveStore(store);
    res.json({ ok: true });
  });
});
// aceitar convite (qualquer logado) — o token é a autorização
app.post('/api/invites/:token/accept', auth, (req, res) => {
  const store = loadStore();
  let found = null;
  let nucleoId = null;
  for (const id of Object.keys(store.nucleoInvites)) {
    const inv = (store.nucleoInvites[id] || []).find((i) => i.token === req.params.token);
    if (inv) {
      found = inv;
      nucleoId = id;
      break;
    }
  }
  if (!found) return res.status(404).json({ error: 'convite inválido' });
  if (found.acceptedBy) return res.status(409).json({ error: 'convite já usado' });
  if (found.expiresAt && new Date(found.expiresAt) < new Date()) return res.status(410).json({ error: 'convite expirado' });
  // login-bind: se o convite foi pra um login específico, exige bater com ALGUM login da conta
  const myLogins = Array.isArray(req.claims.logins) ? req.claims.logins : req.claims.login ? [String(req.claims.login).toLowerCase()] : accountLogins(store, canonicalAccountId(store, req.claims.sub));
  if (found.login && !myLogins.includes(found.login)) {
    return res.status(403).json({ error: 'este convite é de outra conta (' + found.login + ')' });
  }
  if (!store.nucleos[nucleoId]) return res.status(404).json({ error: 'núcleo não existe mais' });
  const me = canonicalAccountId(store, req.claims.sub);
  if (keysFor(store, req.claims.sub).has(store.nucleos[nucleoId].ownerKey)) return res.status(400).json({ error: 'você já é o dono deste núcleo' });
  store.memberships[nucleoId] = store.memberships[nucleoId] || {};
  store.memberships[nucleoId][me] = {
    userKey: me,
    login: myLogins[0] || null,
    caps: found.caps || [],
    projectIds: found.projectIds || null,
    invitedBy: found.createdBy,
    joinedAt: new Date().toISOString(),
  };
  found.acceptedBy = me;
  saveStore(store);
  res.json({ ok: true, nucleoId, name: store.nucleos[nucleoId].name });
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
