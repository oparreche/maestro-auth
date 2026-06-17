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
  s.users = s.users || {};
  s.invites = s.invites || {};
  s.pipelines = s.pipelines || [];
  s.accessRules = s.accessRules || [];
  s.nucleos = s.nucleos || {}; // id -> { id,name,ownerKey,createdAt,projects:[],workspaces:[] }
  s.memberships = s.memberships || {}; // nucleoId -> userKey -> { caps:[],projectIds,invitedBy,joinedAt }
  s.nucleoInvites = s.nucleoInvites || {}; // nucleoId -> [ { token,login?,caps,projectIds,createdBy,createdAt,expiresAt,acceptedBy } ]
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
// papel do usuário dentro de um núcleo: dono (tudo), membro (whitelist) ou null.
function nucleoRoleFor(store, nucleoId, userKey) {
  const n = store.nucleos[nucleoId];
  if (!n) return null;
  if (n.ownerKey === userKey) return { owner: true, caps: NUCLEO_CAPS.slice(), projectIds: null };
  const m = store.memberships[nucleoId] && store.memberships[nucleoId][userKey];
  if (!m) return null;
  return { owner: false, caps: Array.isArray(m.caps) ? m.caps : [], projectIds: m.projectIds || null };
}
function canInNucleo(store, userKey, nucleoId, cap, projectId) {
  const r = nucleoRoleFor(store, nucleoId, userKey);
  if (!r) return false;
  if (r.owner) return true;
  if (!r.caps.includes(cap)) return false;
  if (projectId && r.projectIds && !r.projectIds.includes(projectId)) return false;
  return true;
}
// resumo dos núcleos que o usuário acessa (dono + membro) p/ o /api/me e a lista.
function nucleosForUser(store, userKey) {
  const out = [];
  for (const id of Object.keys(store.nucleos)) {
    const n = store.nucleos[id];
    const r = nucleoRoleFor(store, id, userKey);
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
function genId(prefix) {
  return prefix + '_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
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
function completeLogin(profile, cb, res, providerToken) {
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
  // o provider token NÃO é persistido aqui — só repassado ao app local (loopback),
  // que o guarda localmente p/ listar os repos do usuário. Cada um tem a sua credencial.
  let frag = 'token=' + encodeURIComponent(token);
  if (providerToken) {
    frag += '&pt=' + encodeURIComponent(providerToken) + '&pp=' + encodeURIComponent(profile.provider);
  }
  res.redirect(cb + sep + frag);
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
app.get('/auth/github', (req, res) => startOAuth(req, res, 'https://github.com/login/oauth/authorize', GH_ID, 'read:user user:email repo'));

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
    completeLogin({ provider: 'github', id: gh.id, login: gh.login, name: gh.name, email, avatar: gh.avatar_url }, p.cb, res, ghToken);
  } catch (e) {
    res.status(500).send('erro no login: ' + (e && e.message));
  }
});

// ---- Bitbucket ----
app.get('/auth/bitbucket', (req, res) => startOAuth(req, res, 'https://bitbucket.org/site/oauth2/authorize', BB_ID, 'account email repository'));

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
      res,
      bbToken
    );
  } catch (e) {
    res.status(500).send('erro no login: ' + (e && e.message));
  }
});

// ---------- API ----------
app.get('/api/me', auth, (req, res) => {
  const store = loadStore();
  const u = store.users[req.claims.sub] || null;
  res.json({
    ok: true,
    user: u,
    permissions: permissionsFor(req.claims.role),
    nucleos: nucleosForUser(store, req.claims.sub),
    nucleoCaps: NUCLEO_CAPS,
  });
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
  const owner = store.users[n.ownerKey];
  members.push({
    userKey: n.ownerKey,
    login: owner ? owner.login : n.ownerKey,
    name: owner ? owner.name : n.ownerKey,
    avatar: owner ? owner.avatar : null,
    role: 'owner',
    caps: NUCLEO_CAPS.slice(),
    projectIds: null,
  });
  const ms = store.memberships[id] || {};
  for (const k of Object.keys(ms)) {
    const u = store.users[k];
    members.push({
      userKey: k,
      login: u ? u.login : (ms[k].login || k),
      name: u ? u.name : (ms[k].login || k),
      avatar: u ? u.avatar : null,
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
    const nucleo = { id, name, ownerKey: req.claims.sub, createdAt: new Date().toISOString(), projects: [], workspaces: [] };
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
  if (n.ownerKey !== req.claims.sub) return res.status(403).json({ error: 'só o dono exclui o núcleo' });
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
  // login-bind: se o convite foi pra um login específico, exige bater
  if (found.login && String(req.claims.login || '').toLowerCase() !== found.login) {
    return res.status(403).json({ error: 'este convite é de outra conta (' + found.login + ')' });
  }
  if (!store.nucleos[nucleoId]) return res.status(404).json({ error: 'núcleo não existe mais' });
  if (store.nucleos[nucleoId].ownerKey === req.claims.sub) return res.status(400).json({ error: 'você já é o dono deste núcleo' });
  store.memberships[nucleoId] = store.memberships[nucleoId] || {};
  store.memberships[nucleoId][req.claims.sub] = {
    userKey: req.claims.sub,
    login: req.claims.login,
    caps: found.caps || [],
    projectIds: found.projectIds || null,
    invitedBy: found.createdBy,
    joinedAt: new Date().toISOString(),
  };
  found.acceptedBy = req.claims.sub;
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
