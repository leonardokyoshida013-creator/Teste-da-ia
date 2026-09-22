

(function(window) {
  'use strict';

  const firebaseConfig = {
    apiKey: "AIzaSyDbCZZtRHDn_BXOSOSCk54g62izOTyFFYc",
    authDomain: "banco-seguro-1aa9b.firebaseapp.com",
    projectId: "banco-seguro-1aa9b",
    storageBucket: "banco-seguro-1aa9b.firebasestorage.app",
    messagingSenderId: "247629826149",
    appId: "1:247629826149:web:0af77cbada0f263da1de8c"
  };

  const USERS_COL = "usuarios";
  const NOTES_COL = "notas";
  // Usuários antigos gravam a iteração no próprio documento; este valor
  // só vale para contas novas (OWASP recomenda >= 310k para PBKDF2-SHA256).
  const PBKDF2_ITERATIONS = 310000;
  const LEGACY_PBKDF2_ITERATIONS = 100000;
  const MAX_PASSWORD_LENGTH = 128;
  const LOCAL_STORAGE_USERS_KEY = "banco_seguro_db_users";
  const LOCAL_STORAGE_NOTES_KEY = "banco_seguro_db_notes";

  // Inicializa Firebase Compat com segurança
  let firestoreDb = null;
  try {
    if (typeof firebase !== 'undefined') {
      if (!firebase.apps || !firebase.apps.length) {
        firebase.initializeApp(firebaseConfig);
      }
      firestoreDb = firebase.firestore();
    }
  } catch (err) {
    console.warn("Firebase Firestore não pôde ser iniciado em segundo plano. Utilizando armazenamento local seguro:", err);
  }

  // ---------- Funções Criptográficas ----------

  function generateSalt() {
    const bytes = new Uint8Array(16);
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
    }
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async function hashPassword(password, saltHex, iterations = PBKDF2_ITERATIONS) {
    // Web Crypto é obrigatório: um "fallback" fraco aqui quebraria toda a
    // segurança do armazenamento. Em contextos inseguros (HTTP puro),
    // crypto.subtle não existe — recusamos em vez de enfraquecer o hash.
    if (!(window.crypto && window.crypto.subtle)) {
      const err = new Error(
        "Web Crypto indisponível. Abra o site via https:// ou http://localhost."
      );
      err.code = "WEBCRYPTO_UNAVAILABLE";
      throw err;
    }

    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const salt = hexToBytes(saltHex);
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: Math.max(1, iterations | 0),
        hash: "SHA-256"
      },
      keyMaterial,
      256
    );
    return bufferToHex(derivedBits);
  }

  // Salt fixo usado apenas para igualar o tempo de resposta quando o
  // usuário não existe (previne enumeração de contas por timing).
  const DUMMY_SALT = "00112233445566778899aabbccddeeff";

  function constantTimeEquals(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }

  function sanitizeUser(u) {
    if (!u) return null;
    return {
      id: String(u.id || ''),
      name: String(u.name || '').trim(),
      username: String(u.username || '').toLowerCase().trim(),
      role: u.role === 'adm' ? 'adm' : 'user',
      createdAt: String(u.createdAt || '')
    };
  }

  
  const DEFAULT_USERS = [
    {
      id: "1",
      name: "Leonardo",
      username: "leonardo",
      passwordHash: "36ba688431ced3eb254af303d7dd6dbf2ffbc0b461de4ddf12fa3011f5a5a84c",
      salt: "fcbbc14cb7e185ffb3203f65df4636c5",
      iterations: LEGACY_PBKDF2_ITERATIONS,
      role: "adm",
      createdAt: "27/05/2025"
    },
    {
      id: "2",
      name: "Abner",
      username: "abner",
      passwordHash: "5f30cf2c7ff1ec1dc0bab077a4eaf1a41c8ae1ab3692afd41519059b90cb1d92",
      salt: "ff259a1398888c62e7c1e42f354fe35c",
      iterations: LEGACY_PBKDF2_ITERATIONS,
      role: "adm",
      createdAt: "27/05/2025"
    },
    {
      id: "3",
      name: "Isabela",
      username: "isabela",
      passwordHash: "fa2fc12be4dcbaa360fed02509c37b39b7742a1997080e097d6cb1c1f031d9b8",
      salt: "3c8da68864451b00bcfec362d35ac56d",
      iterations: LEGACY_PBKDF2_ITERATIONS,
      role: "adm",
      createdAt: "27/05/2025"
    },
    {
      id: "4",
      name: "Matheus",
      username: "matheus",
      passwordHash: "2f700e5a6211a3dd47f451c23045bb0dbb5b82e97e3089cb53e395cbf583d966",
      salt: "01d5cd668a1c155da602c2ac1ec2b39e",
      iterations: LEGACY_PBKDF2_ITERATIONS,
      role: "adm",
      createdAt: "27/05/2025"
    }
  ];

  // ---------- Gerenciamento de Armazenamento Local Seguro ----------

    function getLocalUsers() {
    try {
      const raw = localStorage.getItem(LOCAL_STORAGE_USERS_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch {}
    return [...DEFAULT_USERS];
  }

  function setLocalUsers(users) {
    try {
      localStorage.setItem(LOCAL_STORAGE_USERS_KEY, JSON.stringify(users));
    } catch {}
  }

  function getLocalNotes() {
    try {
      const raw = localStorage.getItem(LOCAL_STORAGE_NOTES_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
      }
    } catch {}
    return {};
  }

  function setLocalNotes(notesMap) {
    try {
      localStorage.setItem(LOCAL_STORAGE_NOTES_KEY, JSON.stringify(notesMap));
    } catch {}
  }

  // ---------- Objeto DB ----------

  const DB = {
    _initialized: false,

    async init() {
      if (this._initialized) return;
      this._initialized = true;

      // Garante que o armazenamento local tem os ADMs
      let localUsers = getLocalUsers();
      let updatedLocal = false;
      for (const defU of DEFAULT_USERS) {
        if (!localUsers.some(u => u.username === defU.username)) {
          localUsers.push(defU);
          updatedLocal = true;
        }
      }

      // ── Limpeza: remove conta @snapv duplicada ──
      const beforeLen = localUsers.length;
      localUsers = localUsers.filter(u => String(u.username).toLowerCase() !== 'snapv');
      if (localUsers.length !== beforeLen) updatedLocal = true;

      // ── Limpeza: remove usernames duplicados (mantém o primeiro de cada) ──
      const seen = new Set();
      const deduped = [];
      for (const u of localUsers) {
        const key = String(u.username).toLowerCase();
        if (!seen.has(key)) {
          seen.add(key);
          deduped.push(u);
        }
      }
      if (deduped.length !== localUsers.length) {
        localUsers = deduped;
        updatedLocal = true;
      }

      if (updatedLocal) setLocalUsers(localUsers);

      // Sincroniza com o Firestore se disponível
      if (firestoreDb) {
        try {
          // Remove @snapv do Firestore se existir
          const snapvRef = firestoreDb.collection(USERS_COL).doc('snapv');
          const snapvSnap = await snapvRef.get();
          if (snapvSnap.exists) {
            await snapvRef.delete();
            console.log("Conta @snapv removida do Firestore.");
          }
        } catch (e) {}

        try {
          for (const u of DEFAULT_USERS) {
            const docRef = firestoreDb.collection(USERS_COL).doc(u.username);
            const snap = await docRef.get();
            if (!snap.exists) {
              await docRef.set(u);
            }
          }
        } catch (err) {
          console.warn("Firestore offline ou não configurado. Continuando com banco local:", err.message);
        }
      }
    },

    async _getUserDoc(username) {
      if (!username) return null;
      const clean = String(username).toLowerCase().trim();

      // Tenta Firestore primeiro
      if (firestoreDb) {
        try {
          const snap = await firestoreDb.collection(USERS_COL).doc(clean).get();
          if (snap.exists) return snap.data();
        } catch (e) {}
      }

      // Fallback para armazenamento local
      const localUsers = getLocalUsers();
      return localUsers.find(u => u.username === clean) || null;
    },

    async getAll() {
      await this.init();

      // Função auxiliar para deduplicar por username
      function deduplicate(users) {
        const seen = new Set();
        return users.filter(u => {
          if (!u || !u.username) return false;
          const key = u.username.toLowerCase();
          if (key === 'snapv') return false; // conta removida
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
      }

      if (firestoreDb) {
        try {
          const snap = await firestoreDb.collection(USERS_COL).get();
          if (snap.docs && snap.docs.length > 0) {
            return deduplicate(snap.docs.map(d => sanitizeUser(d.data())));
          }
        } catch (e) {}
      }

      const localUsers = getLocalUsers();
      return deduplicate(localUsers.map(sanitizeUser));
    },

    async findByUsername(username) {
      const doc = await this._getUserDoc(username);
      return doc ? sanitizeUser(doc) : null;
    },

    async authenticate(username, password) {
      if (!username || !password) return null;
      if (typeof password !== 'string' || password.length > MAX_PASSWORD_LENGTH) return null;
      await this.init();

      const clean = String(username).toLowerCase().trim();
      const userDoc = await this._getUserDoc(clean);

      // Timing igualitário: usuário inexistente ainda executa um PBKDF2
      // completo, evitando descobrir contas pela velocidade da resposta.
      if (!userDoc) {
        try {
          await hashPassword(password, DUMMY_SALT, LEGACY_PBKDF2_ITERATIONS);
        } catch (e) {
          if (e && e.code === 'WEBCRYPTO_UNAVAILABLE') throw e;
        }
        return null;
      }

      // Autenticação com PBKDF2 (iteração gravada no documento)
      if (userDoc.passwordHash && userDoc.salt) {
        const hash = await hashPassword(
          password,
          userDoc.salt,
          userDoc.iterations || LEGACY_PBKDF2_ITERATIONS
        );
        if (constantTimeEquals(hash, userDoc.passwordHash)) {
          return sanitizeUser(userDoc);
        }
      }

      // Suporte a migração de senha em texto claro (docs legados)
      if (
        typeof userDoc.password === 'string' &&
        userDoc.password.length <= MAX_PASSWORD_LENGTH &&
        constantTimeEquals(password, userDoc.password)
      ) {
        const salt = generateSalt();
        const hash = await hashPassword(password, salt, PBKDF2_ITERATIONS);
        const upgraded = {
          ...userDoc,
          passwordHash: hash,
          salt,
          iterations: PBKDF2_ITERATIONS
        };
        delete upgraded.password;

        // Atualiza local
        const local = getLocalUsers().map(u => u.username === clean ? upgraded : u);
        setLocalUsers(local);

        // Atualiza Firestore (pode ser recusado pelas regras; login segue válido)
        if (firestoreDb) {
          try {
            await firestoreDb.collection(USERS_COL).doc(clean).set(upgraded);
          } catch (e) {}
        }
        return sanitizeUser(upgraded);
      }

      return null;
    },

    async createUser({ name, username, password, role = "user" }) {
      await this.init();
      const cleanName = String(name || '').trim();
      const cleanUsername = String(username || '').toLowerCase().trim();

      if (!cleanName || cleanName.length > 100) {
        return { ok: false, error: "Nome completo inválido (máx. 100 caracteres)." };
      }

      const USERNAME_REGEX = /^[a-zA-Z0-9._-]{3,30}$/;
      if (!USERNAME_REGEX.test(cleanUsername)) {
        return { ok: false, error: "Nome de usuário deve ter entre 3 e 30 caracteres (letras, números, '.', '_' ou '-')." };
      }

      if (typeof password !== 'string' || password.length < 8) {
        return { ok: false, error: "A senha deve ter no mínimo 8 caracteres." };
      }
      if (password.length > MAX_PASSWORD_LENGTH) {
        return { ok: false, error: `A senha deve ter no máximo ${MAX_PASSWORD_LENGTH} caracteres.` };
      }
      if (!/[A-Z]/.test(password)) {
        return { ok: false, error: "A senha deve conter ao menos uma letra maiúscula." };
      }
      if (!/[a-z]/.test(password)) {
        return { ok: false, error: "A senha deve conter ao menos uma letra minúscula." };
      }
      if (!/[0-9]/.test(password)) {
        return { ok: false, error: "A senha deve conter ao menos um número." };
      }

      const existing = await this._getUserDoc(cleanUsername);
      if (existing) return { ok: false, error: "Este nome de usuário já está cadastrado." };

      const allUsers = await this.getAll();
      const maxId = allUsers.reduce((m, u) => Math.max(m, parseInt(u.id) || 0), 0);

      const salt = generateSalt();
      const passwordHash = await hashPassword(password, salt);

      const newUserDoc = {
        id: String(maxId + 1),
        name: cleanName,
        username: cleanUsername,
        passwordHash,
        salt,
        iterations: PBKDF2_ITERATIONS,
        role: role === 'adm' ? 'adm' : 'user',
        createdAt: new Date().toLocaleDateString("pt-BR")
      };

      // Salva no armazenamento local
      const localUsers = getLocalUsers();
      localUsers.push(newUserDoc);
      setLocalUsers(localUsers);

      // Salva no Firestore
      if (firestoreDb) {
        try {
          await firestoreDb.collection(USERS_COL).doc(cleanUsername).set(newUserDoc);
        } catch (e) {
          console.warn("Aviso ao salvar no Firestore:", e.message);
        }
      }

      return { ok: true, user: sanitizeUser(newUserDoc) };
    },

    async deleteUser(username) {
      await this.init();
      if (!username) return;
      const clean = String(username).toLowerCase().trim();

      // Verifica papel do usuário em ambas as fontes antes de remover
      const userDoc = await this._getUserDoc(clean);
      if (!userDoc) {
        throw new Error("Usuário não encontrado.");
      }
      if (userDoc.role === 'adm') {
        throw new Error("Contas de administrador não podem ser removidas.");
      }

      // Remove do armazenamento local (por username)
      const localUsers = getLocalUsers();
      const updated = localUsers.filter(u => String(u.username).toLowerCase() !== clean);
      setLocalUsers(updated);

      // Remove notas locais
      const localNotes = getLocalNotes();
      delete localNotes[clean];
      setLocalNotes(localNotes);

      // Remove do Firestore
      if (firestoreDb) {
        try {
          await firestoreDb.collection(USERS_COL).doc(clean).delete();
        } catch (e) {
          console.warn("Aviso ao remover usuário do Firestore:", e.message);
        }
        try {
          await firestoreDb.collection(NOTES_COL).doc(clean).delete();
        } catch (e) {
          console.warn("Aviso ao remover notas do Firestore:", e.message);
        }
      }
    },

    async stats() {
      const users = await this.getAll();
      return {
        total: users.length,
        adm:   users.filter(u => u.role === "adm").length,
        user:  users.filter(u => u.role === "user").length,
      };
    },

    async getNotes(username) {
      if (!username) return "";
      const clean = String(username).toLowerCase().trim();

      if (firestoreDb) {
        try {
          const snap = await firestoreDb.collection(NOTES_COL).doc(clean).get();
          if (snap.exists) return snap.data().text || "";
        } catch (e) {}
      }

      const localNotes = getLocalNotes();
      return localNotes[clean] || "";
    },

    async saveNotes(username, text) {
      if (!username) throw new Error("Usuário obrigatório");
      const clean = String(username).toLowerCase().trim();
      const safeText = typeof text === 'string' ? text.slice(0, 50000) : "";

      const localNotes = getLocalNotes();
      localNotes[clean] = safeText;
      setLocalNotes(localNotes);

      if (firestoreDb) {
        try {
          await firestoreDb.collection(NOTES_COL).doc(clean).set({
            text: safeText,
            updatedAt: new Date().toISOString()
          });
        } catch (e) {}
      }
    }
  };

  // Exposição global
  window.DB = DB;

})(window);
