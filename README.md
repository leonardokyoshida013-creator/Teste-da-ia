# Sistema de Acesso Seguro com Painel ADM

Sistema web de autenticação e gestão de usuários com integração Firebase Firestore e camadas reforçadas de segurança criptográfica (OWASP).

## 🛡️ Camadas de Segurança Implementadas

- **Criptografia de Senhas (PBKDF2)**: Hashing com HMAC-SHA-256 e Salt criptográfico de 16 bytes via Web Crypto API. Contas novas usam **310.000 iterações** (recomendação OWASP); contas antigas preservam a iteração gravada no próprio documento. **Não existe fallback fraco**: sem Web Crypto (HTTP puro fora de localhost), o login é recusado em vez de enfraquecer o hash.
- **Timing igualitário no login**: quando o usuário não existe, o servidor de hash ainda executa um PBKDF2 completo, dificultando enumeração de contas por tempo de resposta.
- **Proteção contra Força Bruta (Rate Limiting)**: bloqueio temporário progressivo após 5 tentativas incorretas, com contagem regressiva na tela.
- **Proteção contra XSS**: escape de entidades HTML em toda saída dinâmica (incluindo iniciais e datas) e validação estrita de papéis (RBAC).
- **Política de Senhas Fortes**: mínimo 8 caracteres, maiúscula, minúscula e número; máximo 128 caracteres (evita DoS no hashing).
- **Expiração de Sessão por Inatividade**: logout automático após 30 minutos sem atividade (aviso por toast, sem `alert()` bloqueante).
- **Servidor local endurecido** (`server.js`): proteção contra path traversal, bloqueio de arquivos sensíveis (`.md`, `.rules`, `.bat`, `server.js`, `.env`…), apenas GET/HEAD, limite de URL e cabeçalhos de segurança (`nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, CSP com `object-src 'none'`).
- **Regras do Firestore**: impedem escalação de papel (ninguém se auto-promove a `adm` fora do seed), validam esquema completo e exigem hash+salt (senha em texto puro não é aceita).

## 🧪 Como rodar localmente

```bash
node server.js          # abre http://localhost:3000
NO_OPEN=1 node server.js  # não abre o navegador (testes/CI)
```

Ou execute `iniciar_site.bat` no Windows.

## ⚠️ Riscos residuais e próximos passos (importante)

Este é um projeto **educacional client-side**: a autenticação acontece no navegador e as regras do Firestore permitem leitura geral para que a própria aplicação funcione. Enquanto não houver backend ou Firebase Auth:

1. **Qualquer pessoa pode ler os documentos de usuários** (incluindo hash+salt) e as notas no Firestore. Em produção, exija `request.auth` nas regras.
2. **Rate limiting é por navegador** (localStorage) — trivial de contornar limpando o storage. A proteção real precisa acontecer no servidor.
3. **Recomendação nº 1**: migrar para **Firebase Authentication** (e-mail/senha) e amarrar as regras a `request.auth.token.email`, removendo a autenticação case-dor.

## Contas ADM Padrão

| Usuário | Senha Padrão | Função |
|---|---|---|
| `leonardo` | `Leonardo12@` | Administrador |
| `abner` | `adm123` | Administrador |
| `isabela` | `adm123` | Administrador |
| `matheus` | `adm123` | Administrador |

> As credenciais padrão são armazenadas como hash PBKDF2 com salt em `db.js`. **Troque as senhas fracas (`adm123`) após o primeiro acesso.**

## Estrutura de Arquivos

```
index.html              → Estrutura da página, CSP e landing/login/dashboard
style.css               → Design system, landing page, responsividade e a11y
db.js                   → Camada de banco (Firestore + fallback local) com PBKDF2
app.js                  → Lógica da aplicação, rate limiting, RBAC, toasts e modais
server.js               → Servidor estático local endurecido
firestore.rules         → Regras de validação e anti-escalação do Firestore
CONFIGURACAO_FIREBASE.md → Guia de configuração do Firebase
README.md               → Documentação do projeto
```

## Melhorias aplicadas nesta versão

**Segurança**
- `server.js` reescrito: bloqueio de path traversal (testado com `%2e%2e` e `/../` cru), arquivos sensíveis nunca servidos, cabeçalhos de segurança, cache por tipo, `spawn` em vez de `exec` de string.
- Removido o fallback `simpleHash` (djb2) — era pior que inútil se o Web Crypto faltasse.
- Regras do Firestore: bloqueio de auto-promoção a `adm`, validação de hash (64 hex), salt (32 hex) e iterações; texto puro proibido.
- Escape de XSS nas iniciais/`createdAt` da tabela; `formatDate` não retorna mais HTML.
- Limite de 128 caracteres na senha; estado do rate limit validado contra adulteração básica.
- Igualdade de timing em login com usuário inexistente; impedido auto-delete da conta logada.

**Programação**
- Toasts no lugar de `alert()` (UX e não bloqueiam).
- `Escape` fecha modais; modais fecham ao trocar de tela; `role="dialog"`/`aria-modal`.
- Logout limpa caches e inputs (dados não ficam na memória da página).
- Removido arquivo morto `landing_page_banco_seguro.html` (HTML parcial com `sendPrompt` inexistente).

**Design**
- CSS da landing e do header migrado do `<meta style>` para `style.css` (manutenção).
- Header responsivo (quebra corretamente no mobile), `:focus-visible` e `prefers-reduced-motion`.
- Copy honesta: removidas afirmações falsas ("ISO 27001", "12M+ registros", "zero vazamentos", testimonial inventado) — agora descreve o que o sistema realmente faz.
- `meta description`, `theme-color` e CSP reforçada (`object-src 'none'`, `form-action 'self'`).
