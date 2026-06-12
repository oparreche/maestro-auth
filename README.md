# Maestro Auth

Serviço de autenticação do Maestro: login via **OAuth GitHub e/ou Bitbucket**,
emissão de **JWT** e papéis **gestor / dev** (e `pending` para quem ainda não foi
aprovado). Os papéis e permissões são travados **no servidor**.

## Permissões

- **Gestor:** tudo, incluindo o que é exclusivo dele.
- **Dev:** tudo, **exceto**: `deploy`, gerenciar usuários (`users.manage`),
  definir pipelines (`pipelines.manage`) e regras de acesso ao ambiente (`access.manage`).
- **Pending:** sem acesso até um gestor aprovar.

## Rodar local

```bash
cd auth-server
cp .env.example .env   # preencha JWT_SECRET, GITHUB_CLIENT_ID/SECRET, GESTOR_LOGINS
npm install
npm start
```

## OAuth — criar os apps

Pode usar GitHub, Bitbucket ou os dois (o app mostra um botão por provider configurado).

**GitHub** → Settings → Developer settings → **OAuth Apps** → New:
- **Homepage URL:** sua `PUBLIC_URL`
- **Authorization callback URL:** `<PUBLIC_URL>/auth/github/callback`
- Copie o **Client ID** e gere um **Client Secret** → `.env`.

**Bitbucket** → Workspace settings → **OAuth consumers** → Add consumer:
- **Callback URL:** `<PUBLIC_URL>/auth/bitbucket/callback`
- **Permissions:** Account (read) + Email (read); marque "This is a private consumer".
- Copie o **Key** (= Client ID) e o **Secret** → `.env`.

## Deploy (VPS via EasyPanel/Coolify/Docker)

Há um `Dockerfile`. Monte um **volume persistente em `/data`** (guarda o `store.json`
com os usuários). Configure as variáveis de ambiente do `.env` no painel.

- EasyPanel/Coolify: criar um app a partir deste diretório/Dockerfile, expor a porta
  8080 atrás do domínio `PUBLIC_URL` (HTTPS) e setar o volume `/data`.

## Endpoints

| Método | Rota | Quem | O quê |
|---|---|---|---|
| GET | `/health` | público | status |
| GET | `/auth/providers` | público | lista os providers configurados (GitHub/Bitbucket) |
| GET | `/auth/github?cb=<loopback>` | público | inicia login GitHub (cb = loopback do app) |
| GET | `/auth/bitbucket?cb=<loopback>` | público | inicia login Bitbucket |
| GET | `/auth/{github,bitbucket}/callback` | provider | retorna o token pro app |
| GET | `/api/me` | logado | perfil + permissões |
| GET | `/api/users` | gestor | lista usuários |
| POST | `/api/users/role` | gestor | define papel `{ key, role }` |
| POST | `/api/users/invite` | gestor | pré-aprova `{ login, role }` |
| GET/POST | `/api/pipelines` | ver: logado / editar: gestor | pipelines |
| GET/POST | `/api/access-rules` | ver: logado / editar: gestor | regras de acesso ao ambiente |
