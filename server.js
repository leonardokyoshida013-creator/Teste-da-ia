// ============================================================
//  server.js — Servidor estático local com defesa em profundidade
//  - Proteção contra path traversal (normalização + verificação de raiz)
//  - Bloqueio de arquivos sensíveis (README, regras, .bat, .env, etc.)
//  - Cabeçalhos de segurança em todas as respostas
//  - Apenas GET/HEAD; limite de tamanho de URL
//  - Cache apropriado por tipo de arquivo
//  - NO_OPEN=1 não abre o navegador (útil para testes/CI)
// ============================================================

const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const PORT = Number(process.env.PORT) > 0 ? Number(process.env.PORT) : 3000;
const ROOT = __dirname;
const ROOT_SEP = ROOT.endsWith(path.sep) ? ROOT : ROOT + path.sep;
const MAX_URL_LENGTH = 2048;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.webp': 'image/webp',
  '.woff2':'font/woff2',
  '.txt':  'text/plain; charset=utf-8'
};

// Extensões que nunca devem ser servidas publicamente
const BLOCKED_EXTENSIONS = new Set([
  '.md', '.rules', '.bat', '.cmd', '.ps1', '.sh', '.log', '.env',
  '.zip', '.map', '.yml', '.yaml', '.ini', '.conf', '.config'
]);

// Arquivos específicos bloqueados (mesmo com extensão permitida)
const BLOCKED_FILES = new Set([
  'server.js', 'package.json', 'package-lock.json', '.gitignore', '.env'
]);

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'X-Permitted-Cross-Domain-Policies': 'none'
};

function cacheControlFor(ext) {
  if (ext === '.html') return 'no-cache';
  if (ext === '.css' || ext === '.js') return 'public, max-age=300';
  return 'public, max-age=86400';
}

function resolveSafePath(urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch {
    return null; // percent-encoding inválido
  }

  if (decoded.includes('\0')) return null;

  // Normaliza separadores e remove elementos de navegação
  const relative = decoded.replace(/\\/g, '/').replace(/^\/+/, '');
  const normalized = path.normalize(relative);

  if (normalized === '..' || normalized.startsWith('..' + path.sep) || normalized.startsWith('../')) {
    return null;
  }

  const full = path.resolve(ROOT, normalized);
  if (full !== ROOT && !full.startsWith(ROOT_SEP)) return null;
  return full;
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS, ...headers });
  res.end(body);
}

const server = http.createServer((req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    send(res, 405, 'Metodo nao permitido.', { Allow: 'GET, HEAD' });
    return;
  }

  if (!req.url || req.url.length > MAX_URL_LENGTH) {
    send(res, 414, 'URL muito longa.');
    return;
  }

  const urlPath = req.url.split('?')[0].split('#')[0];
  const safePath = resolveSafePath(urlPath === '/' ? '/index.html' : urlPath);

  if (!safePath) {
    send(res, 403, 'Acesso negado.');
    return;
  }

  const ext = path.extname(safePath).toLowerCase();
  const baseName = path.basename(safePath);

  if (BLOCKED_EXTENSIONS.has(ext) || BLOCKED_FILES.has(baseName) || baseName.startsWith('.')) {
    send(res, 403, 'Acesso negado.');
    return;
  }

  fs.stat(safePath, (err, stat) => {
    if (err || !stat.isFile()) {
      send(res, 404, 'Arquivo nao encontrado.');
      return;
    }

    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    const headers = {
      'Content-Type': contentType,
      'Cache-Control': cacheControlFor(ext),
      'Content-Length': stat.size,
      ...SECURITY_HEADERS
    };

    if (req.method === 'HEAD') {
      res.writeHead(200, headers);
      res.end();
      return;
    }

    const stream = fs.createReadStream(safePath);
    stream.on('error', () => {
      if (!res.headersSent) send(res, 500, 'Erro ao ler o arquivo.');
      else res.destroy();
    });
    res.writeHead(200, headers);
    stream.pipe(res);
  });
});

server.listen(PORT, () => {
  const url = `http://localhost:${PORT}`;
  console.log('\n======================================================');
  console.log('🛡️  BANCO SEGURO — SERVIDOR LOCAL ATIVO');
  console.log(`👉 Acesse no navegador: ${url}`);
  console.log('======================================================\n');

  if (!process.env.NO_OPEN) {
    try {
      if (process.platform === 'win32') {
        spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore' }).unref();
      } else {
        spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
      }
    } catch {
      console.log('Abra manualmente o endereco acima no navegador.');
    }
  }
});
