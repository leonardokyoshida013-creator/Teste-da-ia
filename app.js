// ============================================================
//  app.js — Lógica da aplicação com proteções de segurança reforçadas
//  - Proteção contra ataques de força bruta com rate limiting e bloqueio temporário
//  - Validação estrita de senhas fortes (8+ chars, maiúscula, minúscula, dígito)
//  - Sanitização profunda contra XSS (Cross-Site Scripting)
//  - Verificação de papéis e controle de acesso baseado em funções (RBAC)
//  - Encerramento de sessão por tempo limite de inatividade (30 min)
//  - Interatividade estética: medidor de força, alternador de senha e busca
// ============================================================

// Acesso ao banco de dados seguro inicializado globalmente
const DB = window.DB;

let currentUser = null;
let cachedAllUsers = [];
let cachedNotesMap = {};

// ---------- Utilitários de Interface e Segurança ----------

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;');
}

function sanitizeRole(role) {
  return role === 'adm' ? 'adm' : 'user';
}

function initials(name) {
  if (!name) return '??';
  const parts = String(name).trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '??';
  return parts.map(w => w[0]).slice(0, 2).join('').toUpperCase();
}

// ---------- Toast (substitui alert() bloqueantes) ----------

let toastTimerId = null;

function showToast(message, type = 'info') {
  let el = document.getElementById('appToast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'appToast';
    el.className = 'toast';
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
    document.body.appendChild(el);
  }
  el.textContent = message;
  el.className = `toast toast-${type} toast-show`;
  if (toastTimerId) clearTimeout(toastTimerId);
  toastTimerId = setTimeout(() => {
    el.className = 'toast';
  }, 4500);
}

function showEl(id)  { const el = document.getElementById(id); if (el) el.style.display = 'block'; }
function hideEl(id)  { const el = document.getElementById(id); if (el) el.style.display = 'none'; }
function flexEl(id)  { const el = document.getElementById(id); if (el) el.style.display = 'flex'; }

function showAlert(id, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.style.display = 'block';
}

function hideAlert(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = 'none';
}

function clearInputs(...ids) {
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
}

// ---------- Visual / Interatividade de Senha ----------

function togglePasswordVisibility(inputId, btnEl) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const isPass = input.type === 'password';
  input.type = isPass ? 'text' : 'password';
  const icon = btnEl.querySelector('i');
  if (icon) {
    icon.className = isPass ? 'ti ti-eye-off' : 'ti ti-eye';
  }
}

function updatePasswordStrength(password) {
  const strengthFill = document.getElementById('strengthFill');
  const strengthText = document.getElementById('strengthText');
  const ruleLen = document.getElementById('ruleLength');
  const ruleUp  = document.getElementById('ruleUpper');
  const ruleLow = document.getElementById('ruleLower');
  const ruleNum = document.getElementById('ruleNumber');

  if (!strengthFill || !strengthText) return;

  const hasLen = password.length >= 8;
  const hasUp  = /[A-Z]/.test(password);
  const hasLow = /[a-z]/.test(password);
  const hasNum = /[0-9]/.test(password);

  if (ruleLen) ruleLen.classList.toggle('valid', hasLen);
  if (ruleUp)  ruleUp.classList.toggle('valid', hasUp);
  if (ruleLow) ruleLow.classList.toggle('valid', hasLow);
  if (ruleNum) ruleNum.classList.toggle('valid', hasNum);

  let score = 0;
  if (password.length >= 4) score++;
  if (hasLen) score++;
  if (hasUp && hasLow) score++;
  if (hasNum) score++;
  if (password.length >= 12 && /[^A-Za-z0-9]/.test(password)) score++;

  let width = '0%';
  let color = 'transparent';
  let label = 'Segurança';

  if (!password) {
    width = '0%';
    label = 'Segurança';
  } else if (score <= 1) {
    width = '20%';
    color = '#f43f5e';
    label = 'Muito Fraca';
  } else if (score === 2) {
    width = '45%';
    color = '#fb923c';
    label = 'Fraca';
  } else if (score === 3) {
    width = '70%';
    color = '#fbbf24';
    label = 'Média';
  } else if (score === 4) {
    width = '90%';
    color = '#a855f7';
    label = 'Forte';
  } else {
    width = '100%';
    color = '#34d399';
    label = 'Excelente';
  }

  strengthFill.style.width = width;
  strengthFill.style.backgroundColor = color;
  strengthText.textContent = label;
  strengthText.style.color = color || 'var(--text-faint)';
}

// ---------- Validação de Entrada (Input Validation) ----------

function validatePasswordPolicy(password) {
  if (!password || password.length < 8) {
    return 'A senha deve ter no mínimo 8 caracteres.';
  }
  if (!/[A-Z]/.test(password)) {
    return 'A senha deve conter ao menos uma letra maiúscula.';
  }
  if (!/[a-z]/.test(password)) {
    return 'A senha deve conter ao menos uma letra minúscula.';
  }
  if (!/[0-9]/.test(password)) {
    return 'A senha deve conter ao menos um número.';
  }
  return null;
}

function validateUsernamePolicy(username) {
  const USERNAME_REGEX = /^[a-zA-Z0-9._-]{3,30}$/;
  if (!username || !USERNAME_REGEX.test(username)) {
    return 'O usuário deve ter de 3 a 30 caracteres (letras, números, ".", "_" ou "-").';
  }
  return null;
}

// ---------- Proteção contra Força Bruta (Rate Limiting) ----------

const AUTH_THROTTLE_KEY = 'banco_seguro_auth_throttle';
const MAX_FAILED_ATTEMPTS = 5;
const BASE_LOCKOUT_MS = 30000; // 30 segundos
let lockoutInterval = null;

function getThrottleState() {
  try {
    const raw = localStorage.getItem(AUTH_THROTTLE_KEY);
    if (!raw) return { attempts: 0, lockedUntil: 0 };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { attempts: 0, lockedUntil: 0 };
    const attempts = Number.parseInt(parsed.attempts, 10);
    const lockedUntil = Number.parseInt(parsed.lockedUntil, 10);
    return {
      attempts: Number.isFinite(attempts) && attempts > 0 ? Math.min(attempts, 999) : 0,
      lockedUntil: Number.isFinite(lockedUntil) && lockedUntil > 0 ? lockedUntil : 0
    };
  } catch {
    return { attempts: 0, lockedUntil: 0 };
  }
}

function recordFailedAttempt() {
  const state = getThrottleState();
  state.attempts = (state.attempts || 0) + 1;
  if (state.attempts >= MAX_FAILED_ATTEMPTS) {
    const multiplier = Math.min(state.attempts - MAX_FAILED_ATTEMPTS + 1, 4);
    state.lockedUntil = Date.now() + (BASE_LOCKOUT_MS * multiplier);
  }
  localStorage.setItem(AUTH_THROTTLE_KEY, JSON.stringify(state));
  return state;
}

function resetThrottleState() {
  localStorage.removeItem(AUTH_THROTTLE_KEY);
  if (lockoutInterval) {
    clearInterval(lockoutInterval);
    lockoutInterval = null;
  }
}

function checkLoginLockout() {
  const state = getThrottleState();
  const now = Date.now();
  const btn = document.getElementById('loginBtn');

  if (state.lockedUntil && state.lockedUntil > now) {
    const remainingSeconds = Math.ceil((state.lockedUntil - now) / 1000);
    showAlert('loginError', `Muitas tentativas falhas. Aguarde ${remainingSeconds}s para tentar novamente.`);
    if (btn) btn.disabled = true;

    if (!lockoutInterval) {
      lockoutInterval = setInterval(() => {
        const cur = getThrottleState();
        const rem = Math.ceil((cur.lockedUntil - Date.now()) / 1000);
        if (rem <= 0) {
          clearInterval(lockoutInterval);
          lockoutInterval = null;
          hideAlert('loginError');
          if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="ti ti-login"></i> Entrar';
          }
        } else {
          showAlert('loginError', `Muitas tentativas falhas. Aguarde ${rem}s para tentar novamente.`);
        }
      }, 1000);
    }
    return true;
  }
  return false;
}

// ---------- Tempo Limite de Sessão por Inatividade (30 min) ----------

const INACTIVITY_LIMIT_MS = 30 * 60 * 1000;
let inactivityTimeoutId = null;

function resetInactivityTimer() {
  if (!currentUser) return;
  if (inactivityTimeoutId) clearTimeout(inactivityTimeoutId);
  inactivityTimeoutId = setTimeout(() => {
    if (currentUser) {
      showToast('Sua sessão expirou após 30 minutos de inatividade.', 'warn');
      doLogout();
    }
  }, INACTIVITY_LIMIT_MS);
}

['mousedown', 'keydown', 'touchstart', 'scroll'].forEach(evtName => {
  window.addEventListener(evtName, () => {
    if (currentUser) resetInactivityTimer();
  }, { passive: true });
});

// ---------- Navegação entre telas ----------

function closeAllModals() {
  closeNoteModal();
  closeNotesModal();
  closeModal();
}

function showLanding() {
  closeAllModals();
  showEl('landingScreen');
  hideEl('loginScreen');
  hideEl('registerScreen');
  hideEl('dashboard');
}

function showLogin() {
  closeAllModals();
  hideEl('landingScreen');
  flexEl('loginScreen');
  hideEl('registerScreen');
  hideEl('dashboard');
  hideAlert('loginError');
  clearInputs('loginUser', 'loginPass');
  checkLoginLockout();
}

function showRegister() {
  closeAllModals();
  hideEl('landingScreen');
  hideEl('loginScreen');
  flexEl('registerScreen');
  hideEl('dashboard');
  hideAlert('regError');
  hideAlert('regSuccess');
  clearInputs('regName', 'regUser', 'regPass', 'regPassConf');
  updatePasswordStrength('');
}

// ---------- Login com Proteção ----------

async function doLogin() {
  if (checkLoginLockout()) return;

  hideAlert('loginError');
  const username = document.getElementById('loginUser').value.trim();
  const password = document.getElementById('loginPass').value;

  if (!username || !password) {
    showAlert('loginError', 'Preencha todos os campos.');
    return;
  }

  const btn = document.getElementById('loginBtn');
  btn.disabled = true;
  btn.textContent = 'Autenticando…';

  try {
    const user = await DB.authenticate(username, password);

    if (!user) {
      const state = recordFailedAttempt();
      btn.disabled = false;
      btn.innerHTML = '<i class="ti ti-login"></i> Entrar';

      if (state.lockedUntil && state.lockedUntil > Date.now()) {
        checkLoginLockout();
      } else {
        const remainingTries = MAX_FAILED_ATTEMPTS - (state.attempts || 0);
        const warning = remainingTries > 0 && remainingTries <= 2
          ? ` (${remainingTries} tentativa${remainingTries > 1 ? 's' : ''} restante${remainingTries > 1 ? 's' : ''})`
          : '';
        showAlert('loginError', `Usuário ou senha incorretos.${warning}`);
      }
      return;
    }

    // Sucesso na autenticação
    resetThrottleState();
    currentUser = user;
    btn.disabled = false;
    btn.innerHTML = '<i class="ti ti-login"></i> Entrar';

    resetInactivityTimer();
    renderDashboard();
  } catch (err) {
    console.error("Erro na autenticação:", err);
    btn.disabled = false;
    btn.innerHTML = '<i class="ti ti-login"></i> Entrar';
    if (err && err.code === 'WEBCRYPTO_UNAVAILABLE') {
      showAlert('loginError', err.message);
    } else {
      showAlert('loginError', 'Falha ao autenticar. Tente novamente mais tarde.');
    }
  }
}

// Submeter login com a tecla Enter
document.addEventListener('DOMContentLoaded', () => {
  const loginPass = document.getElementById('loginPass');
  const loginUser = document.getElementById('loginUser');
  if (loginPass) {
    loginPass.addEventListener('keydown', e => {
      if (e.key === 'Enter') doLogin();
    });
  }
  if (loginUser) {
    loginUser.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        if (loginPass) loginPass.focus();
      }
    });
  }
  checkLoginLockout();
});

// ---------- Registro de Conta ----------

async function doRegister() {
  hideAlert('regError');
  hideAlert('regSuccess');

  const name     = document.getElementById('regName').value.trim();
  const username = document.getElementById('regUser').value.trim();
  const password = document.getElementById('regPass').value;
  const confirm  = document.getElementById('regPassConf').value;

  if (!name || !username || !password || !confirm) {
    showAlert('regError', 'Preencha todos os campos.');
    return;
  }

  const usernameError = validateUsernamePolicy(username);
  if (usernameError) {
    showAlert('regError', usernameError);
    return;
  }

  if (password !== confirm) {
    showAlert('regError', 'As senhas digitadas não coincidem.');
    return;
  }

  const passError = validatePasswordPolicy(password);
  if (passError) {
    showAlert('regError', passError);
    return;
  }

  const btn = document.getElementById('regBtn');
  btn.disabled = true;
  btn.textContent = 'Criando…';

  try {
    const result = await DB.createUser({ name, username, password });
    btn.disabled = false;
    btn.innerHTML = '<i class="ti ti-user-plus"></i> Criar conta segura';

    if (!result.ok) {
      showAlert('regError', result.error);
      return;
    }

    showAlert('regSuccess', 'Conta criada com sucesso! Redirecionando para o login…');
    setTimeout(() => showLogin(), 1800);
  } catch (err) {
    console.error("Erro no cadastro:", err);
    btn.disabled = false;
    btn.innerHTML = '<i class="ti ti-user-plus"></i> Criar conta segura';
    if (err && err.code === 'WEBCRYPTO_UNAVAILABLE') {
      showAlert('regError', err.message);
    } else {
      showAlert('regError', 'Erro inesperado ao registrar usuário.');
    }
  }
}

// ---------- Dashboard ----------

async function renderDashboard() {
  if (!currentUser) {
    showLogin();
    return;
  }

  hideEl('landingScreen');
  hideEl('loginScreen');
  hideEl('registerScreen');
  showEl('dashboard');

  const safeRole = sanitizeRole(currentUser.role);
  const av = document.getElementById('topAvatar');
  av.textContent = initials(currentUser.name);
  av.className   = 'avatar ' + safeRole;

  document.getElementById('topName').textContent     = currentUser.name;
  document.getElementById('topUsername').textContent = '@' + currentUser.username;

  const badge = document.getElementById('topBadge');
  badge.textContent = safeRole === 'adm' ? 'ADM' : 'Usuário';
  badge.className   = 'badge ' + safeRole;

  if (safeRole === 'adm') {
    showEl('admPanel');
    hideEl('userPanel');
    await renderTable();
  } else {
    hideEl('admPanel');
    showEl('userPanel');
    await loadNotes();
  }
}

// ---------- Tabela de Usuários (ADM) ----------

async function renderTable() {
  if (!currentUser || currentUser.role !== 'adm') return;

  const s = await DB.stats();
  document.getElementById('statTotal').textContent = s.total;
  document.getElementById('statAdm').textContent   = s.adm;
  document.getElementById('statUsers').textContent = s.user;

  const tbody = document.getElementById('userTableBody');
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-faint);padding:2rem">Carregando usuários…</td></tr>';

  cachedAllUsers = await DB.getAll();

  const common = cachedAllUsers.filter(u => u.role === 'user');
  const notePromises = common.map(u => DB.getNotes(u.username).then(n => [u.username, n]));
  cachedNotesMap = Object.fromEntries(await Promise.all(notePromises));

  renderFilteredTable('');
}

function filterUserTable(query = '') {
  renderFilteredTable(query.toLowerCase().trim());
}

function renderFilteredTable(query = '') {
  const tbody = document.getElementById('userTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const sortByName = (a, b) => a.name.localeCompare(b.name, 'pt-BR');
  const filtered = query
    ? cachedAllUsers.filter(u => u.name.toLowerCase().includes(query) || u.username.toLowerCase().includes(query))
    : cachedAllUsers;

  const adms   = filtered.filter(u => u.role === 'adm').sort(sortByName);
  const common = filtered.filter(u => u.role === 'user').sort(sortByName);

  function buildRow(u) {
    const role      = sanitizeRole(u.role);
    const canDelete = role !== 'adm';
    const notes     = cachedNotesMap[u.username] || '';
    const hasNotes  = notes.trim().length > 0;
    const wordCount = hasNotes ? notes.trim().split(/\s+/).length : 0;
    const safeName  = escapeHtml(u.name);
    const safeUser  = escapeHtml(u.username);
    const safeDate  = escapeHtml(u.createdAt);

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>
        <div class="cell-name">
          <div class="avatar-sm ${role}">${escapeHtml(initials(u.name))}</div>
          <span>${safeName}</span>
        </div>
      </td>
      <td style="color:var(--text-muted);font-family:'DM Mono',monospace;font-size:12px">@${safeUser}</td>
      <td><span class="badge ${role}">${role === 'adm' ? 'ADM' : 'Usuário'}</span></td>
      <td style="color:var(--text-muted);font-size:12px"><i class="ti ti-calendar" style="margin-right:4px"></i>${safeDate}</td>
      <td>${role === 'user'
        ? hasNotes
          ? `<button class="btn-notes"><i class="ti ti-notes"></i> ${wordCount} pal.</button>`
          : '<span style="color:var(--text-faint);font-size:12px">—</span>'
        : '<span style="color:var(--text-faint);font-size:13px">—</span>'
      }</td>
      <td>${canDelete
        ? `<button class="btn-delete"><i class="ti ti-trash"></i> Remover</button>`
        : `<span style="color:var(--text-faint);font-size:13px">—</span>`
      }</td>
    `;

    if (role === 'user' && hasNotes) {
      const btnNotes = tr.querySelector('.btn-notes');
      if (btnNotes) btnNotes.addEventListener('click', () => viewNotes(u.username, u.name));
    }
    if (canDelete) {
      const btnDel = tr.querySelector('.btn-delete');
      if (btnDel) btnDel.addEventListener('click', () => deleteUser(u.username));
    }
    return tr;
  }

  function buildDivider(label, count) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td colspan="6" style="
        background: #f8fafc;
        padding: 8px 18px;
        font-size: 11px;
        font-weight: 700;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.08em;
        border-top: 1px solid var(--border-strong);
      ">${escapeHtml(label)} <span style="color:var(--accent-primary);font-weight:600">(${count})</span></td>
    `;
    return tr;
  }

  if (adms.length > 0) {
    tbody.appendChild(buildDivider('Administradores', adms.length));
    adms.forEach(u => tbody.appendChild(buildRow(u)));
  }

  if (common.length > 0) {
    tbody.appendChild(buildDivider('Usuários Cadastrados', common.length));
    common.forEach(u => tbody.appendChild(buildRow(u)));
  }

  if (filtered.length === 0) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="6" style="text-align:center;color:var(--text-faint);padding:2rem;font-size:14px">
      <i class="ti ti-search-off" style="font-size:24px;display:block;margin-bottom:8px"></i>
      Nenhum usuário encontrado para "${escapeHtml(query)}"
    </td>`;
    tbody.appendChild(tr);
  }
}

async function deleteUser(username) {
  if (!currentUser || currentUser.role !== 'adm') {
    showToast('Ação não autorizada. Apenas administradores podem remover contas.', 'error');
    return;
  }
  if (username === currentUser.username) {
    showToast('Você não pode remover a própria conta.', 'warn');
    return;
  }
  if (!confirm('Tem certeza que deseja remover este usuário? Esta ação é irreversível.')) return;
  try {
    await DB.deleteUser(username);
    await renderTable();
  } catch (err) {
    showToast(err.message || 'Erro ao remover usuário.', 'error');
  }
}

// ---------- Visualização de Notas (ADM) ----------

async function viewNotes(username, name) {
  if (!currentUser || currentUser.role !== 'adm') {
    showToast('Acesso restrito a administradores.', 'error');
    return;
  }

  const raw   = await DB.getNotes(username);
  const notes = parseNotes(raw);

  document.getElementById('notesModalTitle').textContent = 'Notas de ' + name;
  document.getElementById('notesModalSub').textContent   = '@' + username;
  document.getElementById('notesModalCount').textContent = `${notes.length} nota${notes.length !== 1 ? 's' : ''}`;

  const list = document.getElementById('notesModalList');
  list.innerHTML = '';

  if (notes.length === 0) {
    list.innerHTML = '<p style="color:var(--text-faint);font-size:13px;text-align:center;padding:2rem">(sem notas registradas)</p>';
    flexEl('notesModalOverlay');
    return;
  }

  notes.sort((a, b) => String(b.date || '').localeCompare(String(a.date || '')));
  notes.forEach(note => {
    const card = document.createElement('div');
    card.style.cssText = 'background:#f8fafc;border:1px solid var(--border);border-radius:var(--radius);padding:1rem 1.15rem;display:flex;flex-direction:column;gap:6px';
    card.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span style="font-size:11px;font-weight:600;color:var(--accent-primary);font-family:'DM Mono',monospace;background:#eef2ff;border:1px solid #e0e7ff;border-radius:8px;padding:2px 8px">
          <i class="ti ti-calendar" style="font-size:11px"></i> ${escapeHtml(formatDate(note.date))}
        </span>
        ${note.desc ? `<span style="font-size:12px;color:var(--text-muted);font-weight:500">${escapeHtml(note.desc)}</span>` : ''}
      </div>
      <p style="font-size:13px;color:var(--text);line-height:1.7;white-space:pre-wrap">${escapeHtml(note.content)}</p>
    `;
    list.appendChild(card);
  });

  flexEl('notesModalOverlay');
}

function closeNotesModal() {
  hideEl('notesModalOverlay');
}

function handleNotesOverlayClick(e) {
  if (e.target.id === 'notesModalOverlay') closeNotesModal();
}

// ---------- Modal de Criação de Usuário (ADM) ----------

function openModal() {
  if (!currentUser || currentUser.role !== 'adm') {
    showToast('Apenas administradores podem criar usuários pelo painel.', 'error');
    return;
  }
  flexEl('modalOverlay');
  hideAlert('modalError');
  hideAlert('modalSuccess');
  clearInputs('mName', 'mUser', 'mPass');
  setTimeout(() => {
    const el = document.getElementById('mName');
    if (el) el.focus();
  }, 50);
}

function closeModal() {
  hideEl('modalOverlay');
}

function handleOverlayClick(e) {
  if (e.target.id === 'modalOverlay') closeModal();
}

async function createUser() {
  if (!currentUser || currentUser.role !== 'adm') {
    showAlert('modalError', 'Ação não permitida para o seu perfil.');
    return;
  }

  hideAlert('modalError');
  hideAlert('modalSuccess');

  const name     = document.getElementById('mName').value.trim();
  const username = document.getElementById('mUser').value.trim();
  const password = document.getElementById('mPass').value;

  if (!name || !username || !password) {
    showAlert('modalError', 'Preencha todos os campos.');
    return;
  }

  const usernameError = validateUsernamePolicy(username);
  if (usernameError) {
    showAlert('modalError', usernameError);
    return;
  }

  const passError = validatePasswordPolicy(password);
  if (passError) {
    showAlert('modalError', passError);
    return;
  }

  const btn = document.getElementById('modalCreateBtn');
  btn.disabled = true;
  btn.textContent = 'Criando…';

  try {
    const result = await DB.createUser({ name, username, password });
    btn.disabled = false;
    btn.innerHTML = '<i class="ti ti-user-check"></i> Criar usuário protegido';

    if (!result.ok) {
      showAlert('modalError', result.error);
      return;
    }

    showAlert('modalSuccess', `Usuário "${name}" criado com sucesso!`);
    clearInputs('mName', 'mUser', 'mPass');
    setTimeout(async () => {
      closeModal();
      await renderTable();
    }, 1200);
  } catch (err) {
    btn.disabled = false;
    btn.innerHTML = '<i class="ti ti-user-check"></i> Criar usuário protegido';
    showAlert('modalError', err.message || 'Erro ao criar usuário.');
  }
}

// ---------- Bloco de Notas do Usuário Comum ----------

let editingNoteId = null;

async function loadNotes() {
  await renderNotesList();
}

async function renderNotesList() {
  const wrap = document.getElementById('notesListWrap');
  if (!wrap || !currentUser) return;
  wrap.innerHTML = '<p style="color:var(--text-faint);font-size:13px;text-align:center;padding:2rem">Carregando notas seguras…</p>';

  const raw   = await DB.getNotes(currentUser.username);
  const notes = parseNotes(raw);

  if (notes.length === 0) {
    wrap.innerHTML = `
      <div class="card" style="text-align:center;padding:3.5rem 1.5rem;color:var(--text-faint)">
        <div style="width:64px;height:64px;border-radius:18px;background:#eef2ff;border:1px solid #e0e7ff;display:flex;align-items:center;justify-content:center;margin:0 auto 1rem;color:var(--accent-primary);font-size:30px">
          <i class="ti ti-notes"></i>
        </div>
        <h3 style="font-size:16px;color:var(--text);margin-bottom:6px">Nenhuma nota cadastrada ainda</h3>
        <p style="font-size:13px;color:var(--text-muted);max-width:320px;margin:0 auto 1.5rem">Suas anotações são sincronizadas com validação de esquema no Firestore.</p>
        <button class="btn btn-primary" onclick="openNoteModal()" style="width:auto">
          <i class="ti ti-plus"></i> Criar Primeira Nota
        </button>
      </div>`;
    return;
  }

  notes.sort((a, b) => String(b.date || '').localeCompare(String(a.date || '')));

  wrap.innerHTML = '';
  notes.forEach(note => {
    const card = document.createElement('div');
    card.className = 'card';
    card.style.cssText = 'padding:1.25rem 1.4rem;display:flex;flex-direction:column;gap:8px';
    card.innerHTML = `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <span style="font-size:12px;font-weight:600;color:var(--accent-primary);font-family:'DM Mono',monospace;background:#eef2ff;border:1px solid #e0e7ff;border-radius:8px;padding:3px 9px">
            <i class="ti ti-calendar" style="font-size:12px"></i> ${escapeHtml(formatDate(note.date))}
          </span>
          ${note.desc ? `<span style="font-size:13px;font-weight:600;color:var(--text)">${escapeHtml(note.desc)}</span>` : ''}
        </div>
        <div style="display:flex;gap:6px;flex-shrink:0">
          <button class="btn-icon btn-edit-note" title="Editar nota"><i class="ti ti-pencil"></i></button>
          <button class="btn-icon btn-del-note" title="Excluir nota" style="color:var(--red-text)"><i class="ti ti-trash"></i></button>
        </div>
      </div>
      <p style="font-size:14px;color:var(--text);line-height:1.7;white-space:pre-wrap;margin-top:2px">${escapeHtml(note.content)}</p>
    `;

    const btnEdit = card.querySelector('.btn-edit-note');
    if (btnEdit) btnEdit.addEventListener('click', () => openNoteModal(note.id));

    const btnDel = card.querySelector('.btn-del-note');
    if (btnDel) btnDel.addEventListener('click', () => deleteNote(note.id));

    wrap.appendChild(card);
  });
}

function parseNotes(raw) {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed;
  } catch {}
  return [];
}

function formatDate(iso) {
  if (!iso) return '—';
  const parts = String(iso).split('-');
  if (parts.length === 3) {
    return `${parts[2]}/${parts[1]}/${parts[0]}`;
  }
  // Não retorna HTML: quem chama aplica escapeHtml ao inserir no DOM.
  return String(iso).replace(/[^0-9/\-]/g, '') || '—';
}

function openNoteModal(id = null) {
  if (!currentUser) return;
  editingNoteId = id;
  hideAlert('noteModalError');

  if (id !== null) {
    DB.getNotes(currentUser.username).then(raw => {
      const notes = parseNotes(raw);
      const note  = notes.find(n => n.id === id);
      if (!note) return;
      document.getElementById('noteModalTitle').textContent = 'Editar Nota';
      document.getElementById('noteDate').value    = note.date || '';
      document.getElementById('noteDesc').value    = note.desc || '';
      document.getElementById('noteContent').value = note.content || '';
      flexEl('noteModalOverlay');
      setTimeout(() => {
        const d = document.getElementById('noteDesc');
        if (d) d.focus();
      }, 50);
    });
  } else {
    document.getElementById('noteModalTitle').textContent = 'Nova Nota';
    document.getElementById('noteDate').value    = new Date().toISOString().slice(0, 10);
    document.getElementById('noteDesc').value    = '';
    document.getElementById('noteContent').value = '';
    flexEl('noteModalOverlay');
    setTimeout(() => {
      const d = document.getElementById('noteDesc');
      if (d) d.focus();
    }, 50);
  }
}

function closeNoteModal() {
  hideEl('noteModalOverlay');
  editingNoteId = null;
}

function handleNoteOverlayClick(e) {
  if (e.target.id === 'noteModalOverlay') closeNoteModal();
}

async function saveNoteModal() {
  if (!currentUser) return;

  const date    = document.getElementById('noteDate').value;
  const desc    = document.getElementById('noteDesc').value.trim();
  const content = document.getElementById('noteContent').value.trim();

  if (!date) {
    showAlert('noteModalError', 'Selecione uma data válida.');
    return;
  }
  if (!content) {
    showAlert('noteModalError', 'O conteúdo da nota não pode estar vazio.');
    return;
  }

  const btn = document.getElementById('noteModalSaveBtn');
  btn.disabled = true;
  btn.textContent = 'Salvando…';

  try {
    const raw   = await DB.getNotes(currentUser.username);
    const notes = parseNotes(raw);

    if (editingNoteId !== null) {
      const idx = notes.findIndex(n => n.id === editingNoteId);
      if (idx !== -1) {
        notes[idx].date = date;
        notes[idx].desc = desc.slice(0, 100);
        notes[idx].content = content.slice(0, 20000);
      }
    } else {
      const newId = notes.length > 0 ? Math.max(...notes.map(n => n.id)) + 1 : 1;
      notes.push({
        id: newId,
        date,
        desc: desc.slice(0, 100),
        content: content.slice(0, 20000)
      });
    }

    await DB.saveNotes(currentUser.username, JSON.stringify(notes));

    btn.disabled = false;
    btn.innerHTML = '<i class="ti ti-device-floppy"></i> Salvar nota';

    closeNoteModal();
    await renderNotesList();
  } catch (err) {
    btn.disabled = false;
    btn.innerHTML = '<i class="ti ti-device-floppy"></i> Salvar nota';
    showToast('Erro ao salvar nota.', 'error');
  }
}

async function deleteNote(id) {
  if (!currentUser) return;
  if (!confirm('Excluir esta nota? Esta ação não pode ser desfeita.')) return;

  try {
    const raw   = await DB.getNotes(currentUser.username);
    const notes = parseNotes(raw).filter(n => n.id !== id);
    await DB.saveNotes(currentUser.username, JSON.stringify(notes));
    await renderNotesList();
  } catch (err) {
    showToast('Erro ao excluir nota.', 'error');
  }
}

// ---------- Logout Seguro ----------

function doLogout() {
  if (inactivityTimeoutId) {
    clearTimeout(inactivityTimeoutId);
    inactivityTimeoutId = null;
  }
  closeAllModals();
  currentUser = null;
  cachedAllUsers = [];
  cachedNotesMap = {};
  clearInputs('loginUser', 'loginPass', 'regName', 'regUser', 'regPass', 'regPassConf');
  showLanding();
}

// ---------- Fechar modais com Escape + proteção de foco ----------

document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  const openOverlay = ['noteModalOverlay', 'notesModalOverlay', 'modalOverlay']
    .map(id => document.getElementById(id))
    .find(el => el && el.style.display !== 'none' && el.style.display !== '');
  if (openOverlay) {
    if (openOverlay.id === 'noteModalOverlay') closeNoteModal();
    else if (openOverlay.id === 'notesModalOverlay') closeNotesModal();
    else closeModal();
  }
});

// ---------- Exposição Controlada para Eventos do HTML ----------
window.showLogin                = showLogin;
window.showRegister             = showRegister;
window.showLanding              = showLanding;
window.doLogin                  = doLogin;
window.doRegister               = doRegister;
window.doLogout                 = doLogout;
window.openModal                = openModal;
window.closeModal               = closeModal;
window.handleOverlayClick       = handleOverlayClick;
window.createUser               = createUser;
window.deleteUser               = deleteUser;
window.viewNotes                = viewNotes;
window.closeNotesModal          = closeNotesModal;
window.handleNotesOverlayClick  = handleNotesOverlayClick;
window.openNoteModal            = openNoteModal;
window.closeNoteModal           = closeNoteModal;
window.handleNoteOverlayClick   = handleNoteOverlayClick;
window.saveNoteModal            = saveNoteModal;
window.deleteNote               = deleteNote;
window.togglePasswordVisibility = togglePasswordVisibility;
window.updatePasswordStrength   = updatePasswordStrength;
window.filterUserTable          = filterUserTable;
