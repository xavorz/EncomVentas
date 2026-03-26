/**
 * EncomVentas — Sistema de Gestión de Propuestas Comerciales con IA
 * Servidor HTTP puro con Node.js (sin dependencias externas)
 * Encom: OWN Valencia · Valencia Game City
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

// ─── Config ───────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ─── Helpers ──────────────────────────────────────────────
function readJSON(file) {
  const fp = path.join(DATA_DIR, file);
  if (!fs.existsSync(fp)) return [];
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); }
  catch { return []; }
}
function writeJSON(file, data) {
  fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2), 'utf8');
}
function uuid() { return crypto.randomUUID(); }
function hashPassword(pw) { return crypto.createHash('sha256').update(pw).digest('hex'); }
function generateToken() { return crypto.randomBytes(32).toString('hex'); }
function now() { return new Date().toISOString(); }

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 50e6) { req.destroy(); reject(new Error('Body too large')); }
    });
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}
function json(res, data, status = 200) {
  cors(res);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}
function error(res, msg, status = 400) { json(res, { error: msg }, status); }

function getAuth(req) {
  const h = req.headers.authorization;
  const urlToken = new URL(req.url, `http://${req.headers.host || 'localhost'}`).searchParams.get('_token');
  const token = h ? h.replace('Bearer ', '') : urlToken;
  if (!token) return null;
  const sessions = readJSON('sessions.json');
  const s = sessions.find(s => s.token === token);
  if (!s) return null;
  const users = readJSON('users.json');
  return users.find(u => u.id === s.userId) || null;
}
function requireAuth(req, res) {
  const user = getAuth(req);
  if (!user) { error(res, 'No autorizado', 401); return null; }
  return user;
}
function requireAdmin(req, res) {
  const user = requireAuth(req, res);
  if (user && user.role !== 'admin') { error(res, 'Acceso denegado', 403); return null; }
  return user;
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

// ─── Router ───────────────────────────────────────────────
function matchRoute(method, urlPath, routeMethod, routePattern) {
  if (method !== routeMethod) return null;
  const rp = routePattern.split('/'), up = urlPath.split('/');
  if (rp.length !== up.length) return null;
  const params = {};
  for (let i = 0; i < rp.length; i++) {
    if (rp[i].startsWith(':')) params[rp[i].slice(1)] = up[i];
    else if (rp[i] !== up[i]) return null;
  }
  return params;
}
const routes = [];
function route(method, pattern, handler) { routes.push({ method, pattern, handler }); }

// ════════════════════════════════════════════════════════════
// HEALTH CHECK (no auth required)
// ════════════════════════════════════════════════════════════
route('GET', '/api/health', async (req, res) => {
  const users = readJSON('users.json');
  json(res, {
    status: 'ok',
    usersCount: users.length,
    userEmails: users.map(u => u.email),
    hasApiKey: !!ANTHROPIC_API_KEY,
    dataFiles: fs.readdirSync(DATA_DIR),
  });
});

// ════════════════════════════════════════════════════════════
// SSO (Encom Tools Portal)
// ════════════════════════════════════════════════════════════
const httpsModule = require('https');
const PORTAL_URL = process.env.PORTAL_URL || 'https://tools.encom.es';

function ssoValidate(token) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(`${PORTAL_URL}/api/auth/sso/validate?token=${token}`);
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || 443,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      rejectUnauthorized: false,
      headers: { 'Accept': 'application/json' },
    };
    const r = httpsModule.request(options, (response) => {
      let data = '';
      response.on('data', chunk => data += chunk);
      response.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`SSO parse error: ${data.substring(0, 200)}`)); }
      });
    });
    r.on('error', reject);
    r.setTimeout(10000, () => { r.destroy(); reject(new Error('SSO timeout')); });
    r.end();
  });
}

route('GET', '/api/sso', async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const ssoToken = url.searchParams.get('token');
  if (!ssoToken) { res.writeHead(302, { Location: '/login' }); return res.end(); }

  try {
    console.log('[SSO] Validating token against portal:', PORTAL_URL);
    const result = await ssoValidate(ssoToken);
    console.log('[SSO] Validation result:', JSON.stringify(result));
    if (!result.valid) { res.writeHead(302, { Location: '/login' }); return res.end(); }

    // Create local session
    const localToken = generateToken();
    const users = readJSON('users.json');
    let user = users.find(u => u.email === result.user.email);
    if (!user) {
      user = { id: uuid(), name: result.user.name, email: result.user.email, role: result.user.role || 'user', passwordHash: '', createdAt: now() };
      users.push(user);
      writeJSON('users.json', users);
    }
    const sessions = readJSON('sessions.json');
    sessions.push({ token: localToken, userId: user.id, createdAt: now() });
    writeJSON('sessions.json', sessions);

    cors(res);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html><html><head><script>
      localStorage.setItem('ev_token', '${localToken}');
      localStorage.setItem('user', JSON.stringify(${JSON.stringify({ id: user.id, name: user.name, email: user.email, role: user.role })}));
      window.location.href = '/';
    </script></head><body></body></html>`);
  } catch (err) {
    console.error('[SSO] Error:', err.message);
    res.writeHead(302, { Location: '/login' });
    res.end();
  }
});

// ════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════
route('POST', '/api/auth/login', async (req, res) => {
  const { email, password } = await parseBody(req);
  if (!email || !password) return error(res, 'Email y contraseña requeridos');
  const users = readJSON('users.json');
  const user = users.find(u => u.email === email.toLowerCase().trim());
  if (!user || user.passwordHash !== hashPassword(password)) return error(res, 'Credenciales incorrectas', 401);
  const token = generateToken();
  const sessions = readJSON('sessions.json');
  sessions.push({ token, userId: user.id, createdAt: now() });
  writeJSON('sessions.json', sessions);
  json(res, { token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

route('POST', '/api/auth/logout', async (req, res) => {
  const h = req.headers.authorization;
  if (h) {
    const token = h.replace('Bearer ', '');
    const sessions = readJSON('sessions.json').filter(s => s.token !== token);
    writeJSON('sessions.json', sessions);
  }
  json(res, { ok: true });
});

route('GET', '/api/auth/me', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  json(res, { id: user.id, name: user.name, email: user.email, role: user.role });
});

// ════════════════════════════════════════════════════════════
// USERS (admin only)
// ════════════════════════════════════════════════════════════
route('GET', '/api/users', async (req, res) => {
  const user = requireAdmin(req, res);
  if (!user) return;
  const users = readJSON('users.json').map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, createdAt: u.createdAt }));
  json(res, users);
});

route('POST', '/api/users', async (req, res) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  const { name, email, password, role } = await parseBody(req);
  if (!name || !email || !password) return error(res, 'Nombre, email y contraseña requeridos');
  if (!['admin', 'vendedor'].includes(role)) return error(res, 'Rol debe ser admin o vendedor');
  const users = readJSON('users.json');
  if (users.find(u => u.email === email.toLowerCase().trim())) return error(res, 'Email ya existe');
  const u = { id: uuid(), name, email: email.toLowerCase().trim(), passwordHash: hashPassword(password), role, createdAt: now() };
  users.push(u);
  writeJSON('users.json', users);
  json(res, { id: u.id, name: u.name, email: u.email, role: u.role }, 201);
});

route('DELETE', '/api/users/:id', async (req, res, params) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  if (params.id === admin.id) return error(res, 'No puedes eliminarte a ti mismo');
  let users = readJSON('users.json');
  users = users.filter(u => u.id !== params.id);
  writeJSON('users.json', users);
  json(res, { ok: true });
});

// ════════════════════════════════════════════════════════════
// CLIENTS (CRM básico)
// ════════════════════════════════════════════════════════════
route('GET', '/api/clients', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const clients = readJSON('clients.json');
  json(res, clients);
});

route('GET', '/api/clients/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const clients = readJSON('clients.json');
  const client = clients.find(c => c.id === params.id);
  if (!client) return error(res, 'Cliente no encontrado', 404);
  // Include proposals for this client
  const proposals = readJSON('proposals.json').filter(p => p.clientId === params.id);
  json(res, { ...client, proposals });
});

route('POST', '/api/clients', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const { company, contactName, contactEmail, contactPhone, sector, size, notes } = body;
  if (!company) return error(res, 'Nombre de empresa requerido');
  const clients = readJSON('clients.json');
  const client = {
    id: uuid(), company, contactName: contactName || '', contactEmail: contactEmail || '',
    contactPhone: contactPhone || '', sector: sector || '', size: size || '',
    notes: notes || '', createdBy: user.id, createdAt: now(), updatedAt: now()
  };
  clients.push(client);
  writeJSON('clients.json', clients);
  json(res, client, 201);
});

route('PUT', '/api/clients/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const clients = readJSON('clients.json');
  const idx = clients.findIndex(c => c.id === params.id);
  if (idx === -1) return error(res, 'Cliente no encontrado', 404);
  const allowed = ['company', 'contactName', 'contactEmail', 'contactPhone', 'sector', 'size', 'notes'];
  allowed.forEach(k => { if (body[k] !== undefined) clients[idx][k] = body[k]; });
  clients[idx].updatedAt = now();
  writeJSON('clients.json', clients);
  json(res, clients[idx]);
});

route('GET', '/api/clients-search', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const q = new URL(req.url, `http://${req.headers.host}`).searchParams.get('q') || '';
  if (q.length < 2) return json(res, []);
  const clients = readJSON('clients.json');
  const ql = q.toLowerCase();
  const matches = clients.filter(c => c.company.toLowerCase().includes(ql) || (c.contactName && c.contactName.toLowerCase().includes(ql)));
  json(res, matches.slice(0, 10));
});

// ════════════════════════════════════════════════════════════
// PROPOSALS
// ════════════════════════════════════════════════════════════

// List proposals (vendedor sees own, admin sees all)
route('GET', '/api/proposals', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  let proposals = readJSON('proposals.json');
  if (user.role !== 'admin') proposals = proposals.filter(p => p.vendedorId === user.id);
  // Enrich with client & vendedor names
  const clients = readJSON('clients.json');
  const users = readJSON('users.json');
  proposals = proposals.map(p => ({
    ...p,
    clientName: (clients.find(c => c.id === p.clientId) || {}).company || 'Desconocido',
    vendedorName: (users.find(u => u.id === p.vendedorId) || {}).name || 'Desconocido',
  }));
  // Sort by most recent
  proposals.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  json(res, proposals);
});

// Get single proposal
route('GET', '/api/proposals/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const proposals = readJSON('proposals.json');
  const p = proposals.find(p => p.id === params.id);
  if (!p) return error(res, 'Propuesta no encontrada', 404);
  if (user.role !== 'admin' && p.vendedorId !== user.id) return error(res, 'Acceso denegado', 403);
  const clients = readJSON('clients.json');
  const users = readJSON('users.json');
  p.clientName = (clients.find(c => c.id === p.clientId) || {}).company || 'Desconocido';
  p.clientData = clients.find(c => c.id === p.clientId) || {};
  p.vendedorName = (users.find(u => u.id === p.vendedorId) || {}).name || 'Desconocido';
  json(res, p);
});

// Create proposal (lead intake form)
route('POST', '/api/proposals', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const { clientId, formData } = body;
  if (!clientId || !formData) return error(res, 'Cliente y datos del formulario requeridos');

  const required = ['eventType', 'eventName'];
  for (const f of required) {
    if (!formData[f]) return error(res, `Campo requerido: ${f}`);
  }

  const proposals = readJSON('proposals.json');
  const proposal = {
    id: uuid(),
    clientId,
    vendedorId: user.id,
    formData,
    variants: [],
    selectedVariantId: null,
    versions: [],
    status: 'draft',
    adminNotes: '',
    vendedorNotes: '',
    validatedBy: null,
    validatedAt: null,
    sentAt: null,
    resolvedAt: null,
    resolution: null,
    createdAt: now(),
    updatedAt: now(),
  };
  proposals.push(proposal);
  writeJSON('proposals.json', proposals);
  json(res, proposal, 201);
});

// Generate proposals with Claude AI
route('POST', '/api/proposals/:id/generate', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const feedback = body.feedback || '';

  const proposals = readJSON('proposals.json');
  const idx = proposals.findIndex(p => p.id === params.id);
  if (idx === -1) return error(res, 'Propuesta no encontrada', 404);
  const p = proposals[idx];
  if (user.role !== 'admin' && p.vendedorId !== user.id) return error(res, 'Acceso denegado', 403);

  // Get client info
  const clients = readJSON('clients.json');
  const client = clients.find(c => c.id === p.clientId) || {};

  if (!ANTHROPIC_API_KEY) return error(res, 'API Key de Anthropic no configurada', 500);

  // Save current variants as version before regenerating
  if (p.variants && p.variants.length > 0) {
    p.versions.push({ variants: JSON.parse(JSON.stringify(p.variants)), createdAt: now(), feedback });
  }

  try {
    const aiResponse = await callClaude(client, p.formData, feedback, p.versions);
    p.variants = aiResponse;
    p.status = p.status === 'draft' ? 'generated' : p.status;
    p.updatedAt = now();
    proposals[idx] = p;
    writeJSON('proposals.json', proposals);
    json(res, p);
  } catch (err) {
    console.error('Claude API error:', err.message);
    error(res, 'Error generando propuestas: ' + err.message, 500);
  }
});

// Update proposal status
route('PATCH', '/api/proposals/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const proposals = readJSON('proposals.json');
  const idx = proposals.findIndex(p => p.id === params.id);
  if (idx === -1) return error(res, 'Propuesta no encontrada', 404);
  const p = proposals[idx];
  if (user.role !== 'admin' && p.vendedorId !== user.id) return error(res, 'Acceso denegado', 403);

  // Vendedor actions
  if (body.status === 'pending_validation') {
    p.status = 'pending_validation';
    if (body.vendedorNotes) p.vendedorNotes = body.vendedorNotes;
  }
  if (body.status === 'sent') {
    if (p.status !== 'validated') return error(res, 'Solo se pueden enviar propuestas validadas');
    p.status = 'sent';
    p.sentAt = now();
  }
  if (['approved', 'rejected', 'redo'].includes(body.status)) {
    if (p.status !== 'sent') return error(res, 'Solo se pueden resolver propuestas enviadas');
    p.status = body.status;
    p.resolvedAt = now();
    p.resolution = body.status;
  }

  // Admin actions
  if (body.status === 'validated' && user.role === 'admin') {
    if (!body.selectedVariantId) return error(res, 'Debes seleccionar una variante');
    p.status = 'validated';
    p.selectedVariantId = body.selectedVariantId;
    p.validatedBy = user.id;
    p.validatedAt = now();
    if (body.adminNotes) p.adminNotes = body.adminNotes;
  }

  // Admin can edit variant directly
  if (body.editVariant && user.role === 'admin') {
    const vIdx = p.variants.findIndex(v => v.id === body.editVariant.id);
    if (vIdx !== -1) {
      // Save version before edit
      p.versions.push({ variants: JSON.parse(JSON.stringify(p.variants)), createdAt: now(), feedback: 'Edición manual admin' });
      p.variants[vIdx] = { ...p.variants[vIdx], ...body.editVariant };
    }
  }

  // Vendedor notes
  if (body.vendedorNotes !== undefined) p.vendedorNotes = body.vendedorNotes;
  if (body.adminNotes !== undefined && user.role === 'admin') p.adminNotes = body.adminNotes;

  p.updatedAt = now();
  proposals[idx] = p;
  writeJSON('proposals.json', proposals);
  json(res, p);
});

// Delete proposal (admin or owner if draft)
route('DELETE', '/api/proposals/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  let proposals = readJSON('proposals.json');
  const p = proposals.find(p => p.id === params.id);
  if (!p) return error(res, 'Propuesta no encontrada', 404);
  if (user.role !== 'admin' && (p.vendedorId !== user.id || p.status !== 'draft')) {
    return error(res, 'Acceso denegado', 403);
  }
  proposals = proposals.filter(pr => pr.id !== params.id);
  writeJSON('proposals.json', proposals);
  json(res, { ok: true });
});

// ════════════════════════════════════════════════════════════
// DASHBOARD (admin)
// ════════════════════════════════════════════════════════════
route('GET', '/api/dashboard', async (req, res) => {
  const user = requireAdmin(req, res);
  if (!user) return;
  const proposals = readJSON('proposals.json');
  const users = readJSON('users.json');
  const clients = readJSON('clients.json');

  // Overall stats
  const total = proposals.length;
  const byStatus = {};
  proposals.forEach(p => { byStatus[p.status] = (byStatus[p.status] || 0) + 1; });

  // Revenue stats
  let totalProposed = 0, totalApproved = 0;
  proposals.forEach(p => {
    if (p.selectedVariantId) {
      const v = p.variants.find(v => v.id === p.selectedVariantId);
      if (v) {
        totalProposed += v.totalClient || 0;
        if (p.status === 'approved') totalApproved += v.totalClient || 0;
      }
    }
  });

  // Per user stats (ALL users, including admin)
  const allUsers = users;
  const vendedorStats = allUsers.map(v => {
    const vp = proposals.filter(p => p.vendedorId === v.id);
    const sent = vp.filter(p => ['sent', 'approved', 'rejected'].includes(p.status));
    const approved = vp.filter(p => p.status === 'approved');
    let revenue = 0;
    approved.forEach(p => {
      const variant = p.variants.find(va => va.id === p.selectedVariantId);
      if (variant) revenue += variant.totalClient || 0;
    });
    return {
      id: v.id, name: v.name, role: v.role,
      total: vp.length, sent: sent.length, approved: approved.length,
      conversionRate: sent.length > 0 ? Math.round((approved.length / sent.length) * 100) : 0,
      revenue
    };
  });

  // Medal ranking: gold (approved) > silver (sent) > bronze (created) — like Olympics
  const medalRanking = [...vendedorStats]
    .filter(v => v.sent > 0 || v.approved > 0 || v.total > 0)
    .sort((a, b) => {
      if (b.approved !== a.approved) return b.approved - a.approved;
      if (b.sent !== a.sent) return b.sent - a.sent;
      return b.total - a.total;
    });

  // Pending validation
  const pendingValidation = proposals
    .filter(p => p.status === 'pending_validation')
    .map(p => ({
      id: p.id,
      clientName: (clients.find(c => c.id === p.clientId) || {}).company || 'Desconocido',
      vendedorName: (users.find(u => u.id === p.vendedorId) || {}).name || 'Desconocido',
      eventName: p.formData.eventName,
      createdAt: p.createdAt,
    }));

  // Recent proposals
  const recent = proposals.slice().sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt)).slice(0, 10).map(p => ({
    id: p.id, status: p.status,
    clientName: (clients.find(c => c.id === p.clientId) || {}).company || 'Desconocido',
    vendedorName: (users.find(u => u.id === p.vendedorId) || {}).name || 'Desconocido',
    eventName: p.formData.eventName,
    updatedAt: p.updatedAt,
  }));

  // Monthly trend (last 6 months)
  const monthlyTrend = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date();
    d.setMonth(d.getMonth() - i);
    const m = d.getMonth(), y = d.getFullYear();
    const mp = proposals.filter(p => {
      const pd = new Date(p.createdAt);
      return pd.getMonth() === m && pd.getFullYear() === y;
    });
    monthlyTrend.push({
      month: d.toLocaleDateString('es-ES', { month: 'short', year: 'numeric' }),
      created: mp.length,
      approved: mp.filter(p => p.status === 'approved').length,
    });
  }

  json(res, {
    total, byStatus, totalProposed, totalApproved,
    pendingValidation, vendedorStats, medalRanking, recent, monthlyTrend,
    totalClients: clients.length,
  });
});

// ════════════════════════════════════════════════════════════
// CLAUDE AI INTEGRATION
// ════════════════════════════════════════════════════════════

async function callClaude(client, formData, feedback, previousVersions) {
  const systemPrompt = `Eres el director creativo y comercial de Encom, la empresa referente en España en gestión de eventos, festivales (OWN Valencia, Valencia Game City), activaciones de marca, patrocinios y experiencias digitales e inmersivas.

Tu misión: crear 3 PROPUESTAS COMERCIALES QUE VENDAN. No estás haciendo un presupuesto — estás construyendo un pitch irresistible. El documento que generes irá directamente al cliente. Debe emocionar, convencer y cerrar.

Cada propuesta debe variar en:
- Nivel de precio y ambición (desde una opción enfocada hasta una experiencia premium transformadora)
- Concepto creativo diferente (cada una con su propia narrativa y ángulo estratégico)

Para CADA propuesta debes devolver un JSON con esta estructura EXACTA:
{
  "id": "variant-1",
  "title": "Nombre potente y creativo del proyecto (que suene a marca)",
  "tagline": "Frase gancho de 1 línea que resuma la esencia (para la portada del PDF)",
  "storytelling": "Narrativa de venta de 150-250 palabras. Escribe como si le contaras al cliente la visión del proyecto. Hazle imaginar el día del evento, el impacto, la emoción. Usa lenguaje visual y aspiracional. Esto es lo primero que leerá el cliente — debe engancharse aquí.",
  "concept": "Descripción del concepto creativo en 80-120 palabras. ¿Qué hace único este enfoque? ¿Cuál es la idea central?",
  "experience": "Descripción detallada de la experiencia en 100-150 palabras: qué vivirán los asistentes, paso a paso, desde que llegan hasta que se van. Hazlo tangible y sensorial.",
  "kpis": [
    {"metric": "Nombre del KPI", "target": "Valor objetivo", "description": "Cómo se mide y por qué importa"}
  ],
  "roi": "Texto de 60-100 palabras explicando el retorno esperado de la inversión para el cliente. Incluye estimaciones concretas (alcance, impacto en marca, leads, conversiones, etc.)",
  "whyEncom": "Texto de 60-80 palabras sobre por qué Encom es el partner ideal para este proyecto (experiencia, casos, capacidades únicas)",
  "timeline": [
    {"phase": "Nombre de fase", "duration": "X semanas", "tasks": "Descripción de tareas clave"}
  ],
  "services": [
    {
      "name": "Nombre potente de la activación o servicio (que suene a experiencia, no a partida contable)",
      "headline": "Frase gancho de 1 línea que resuma qué es y por qué importa",
      "fullDescription": "Descripción comercial de 80-120 palabras. Explica en qué consiste esta activación: qué vivirá el asistente o el cliente, cómo funciona, qué la hace especial. Vende la experiencia, no el servicio técnico. Si es un stand, describe la experiencia inmersiva. Si es producción, describe el impacto visual que tendrá.",
      "objectives": ["Objetivo 1 concreto de esta activación", "Objetivo 2", "Objetivo 3"],
      "includes": ["Qué incluye: elemento 1", "Elemento 2", "Elemento 3 (sé específico: 2 pantallas LED 4K, no solo pantallas)"],
      "quantity": 1,
      "unitPrice": 5000,
      "totalClient": 5000,
      "costInternal": 3000
    }
  ],
  "totalClient": 15000,
  "totalCost": 9000,
  "margin": 6000,
  "marginPercent": 40,
  "summary": "Resumen ejecutivo de 3-4 frases impactantes para el inicio del documento"
}

REGLAS CRÍTICAS DE PRESUPUESTO (OBLIGATORIAS — NO SALTARSE NUNCA):
- Si el cliente indica un presupuesto orientativo (ej: "15.000€", "entre 10-20k", "máximo 50.000€"), ese es el TECHO ABSOLUTO. NINGUNA de las 3 propuestas puede superar esa cifra en su totalClient.
- Las 3 propuestas deben distribuirse DENTRO del presupuesto indicado:
  · Propuesta 1 (Esencial): ~40-55% del presupuesto máximo. Enfocada, eficiente, alto impacto con lo justo.
  · Propuesta 2 (Recomendada): ~65-80% del presupuesto máximo. Buen equilibrio entre ambición y coste.
  · Propuesta 3 (Premium): ~85-100% del presupuesto máximo. La experiencia más completa posible DENTRO del límite.
- Si el presupuesto es un rango (ej: "10-20k"), usa el valor máximo del rango como techo.
- Si el cliente dice "No indicado" o no hay presupuesto, entonces sí puedes proponer rangos variados basándote en el tipo de evento y mercado español.
- VERIFICA: antes de devolver el JSON, comprueba que el campo "totalClient" de CADA propuesta no supere el presupuesto. Si lo supera, reduce servicios o ajusta precios hasta encajar.
- La suma de (unitPrice * quantity) de todos los servicios DEBE coincidir con el totalClient de esa propuesta. No inventes números que no cuadren.

REGLAS CRÍTICAS DE CONTENIDO:
- Estás VENDIENDO. Cada palabra debe acercar al cierre. Nada de texto genérico o corporativo vacío.
- Precios realistas para el mercado español de eventos (investiga mentalmente rangos reales)
- Margen objetivo 25-50% según servicio
- Los KPIs deben ser concretos y medibles (no "mejorar la imagen de marca" sino "alcance estimado de 500K impactos en RRSS")
- El ROI debe incluir números estimados que justifiquen la inversión
- El timeline debe ser creíble y profesional
- Entre 5-10 servicios/activaciones por propuesta. Cada uno es una SECCIÓN PROPIA en el PDF final.
- CADA SERVICIO/ACTIVACIÓN debe tener fullDescription (80-120 palabras), objectives (3 concretos) e includes (3-5 elementos específicos). No escatimes aquí: el cliente leerá cada activación como si fuera un mini-proyecto. Debe entender qué es, por qué importa y qué incluye exactamente.
- La primera propuesta debe ser la más ajustada, la tercera la más premium — pero SIEMPRE dentro del techo presupuestario.
- El storytelling es LO MÁS IMPORTANTE. Si el cliente no se emociona en los primeros párrafos, no sigue leyendo.
- Escribe en español natural y persuasivo, no en "lenguaje de consultoría"
- Los nombres de servicios deben sonar a EXPERIENCIA, no a partida presupuestaria. No "Sonido e iluminación" sino "Escenario Inmersivo 360° con Mapping Audiovisual"

Responde SOLO con un JSON array de 3 objetos. Sin texto adicional, sin markdown, solo JSON válido.`;

  let userMessage = `DATOS DEL CLIENTE:
- Empresa: ${client.company || 'No especificado'}
- Sector: ${client.sector || 'No especificado'}
- Tamaño: ${client.size || 'No especificado'}
- Contacto: ${client.contactName || 'No especificado'}

DATOS DEL EVENTO/NECESIDAD:
- Tipo: ${formData.eventType || 'No especificado'}
- Nombre/Descripción: ${formData.eventName || 'No especificado'}
- Fecha: ${formData.eventDate || 'No especificada'}
- Ubicación: ${formData.location || 'No especificada'}
- Duración: ${formData.duration || 'No especificada'}
- Asistentes esperados: ${formData.attendees || 'No especificado'}
- Presupuesto orientativo del cliente: ${formData.budget || 'No indicado'}

OBJETIVOS DEL CLIENTE:
${formData.objectives || 'No especificados'}

PÚBLICO OBJETIVO:
${formData.targetAudience || 'No especificado'}

REQUISITOS ESPECIALES:
${formData.specialRequirements || 'Ninguno'}

SERVICIOS DE INTERÉS:
${(formData.servicesInterest || []).join(', ') || 'No especificados'}

CONTEXTO ADICIONAL DE LA REUNIÓN:
${formData.freeContext || 'Sin contexto adicional'}`;

  if (feedback) {
    userMessage += `\n\nFEEDBACK PARA MEJORAR LAS PROPUESTAS:\n${feedback}`;
  }

  if (previousVersions && previousVersions.length > 0) {
    const lastVersion = previousVersions[previousVersions.length - 1];
    userMessage += `\n\nVERSIÓN ANTERIOR DE REFERENCIA (mejórala según el feedback):\n${JSON.stringify(lastVersion.variants, null, 2)}`;
  }

  const requestBody = JSON.stringify({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 16000,
    system: systemPrompt,
    messages: [{ role: 'user', content: userMessage }]
  });

  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(requestBody),
      }
    };

    const https = require('https');
    const apiReq = https.request(options, (apiRes) => {
      let data = '';
      apiRes.on('data', chunk => data += chunk);
      apiRes.on('end', () => {
        try {
          const result = JSON.parse(data);
          if (result.error) return reject(new Error(result.error.message || 'API error'));
          const text = result.content[0].text;
          // Try to parse the JSON from Claude's response
          let parsed;
          try {
            parsed = JSON.parse(text);
          } catch {
            // Try extracting JSON from markdown code block
            const match = text.match(/\[[\s\S]*\]/);
            if (match) parsed = JSON.parse(match[0]);
            else throw new Error('No se pudo parsear la respuesta de Claude');
          }
          if (!Array.isArray(parsed) || parsed.length !== 3) {
            reject(new Error('Claude no devolvió 3 propuestas'));
          } else {
            // Ensure IDs
            parsed.forEach((v, i) => { v.id = v.id || `variant-${i + 1}`; });
            resolve(parsed);
          }
        } catch (e) {
          reject(e);
        }
      });
    });

    apiReq.on('error', reject);
    apiReq.write(requestBody);
    apiReq.end();
  });
}

// ════════════════════════════════════════════════════════════
// PDF GENERATION (client-facing, no internal costs)
// ════════════════════════════════════════════════════════════
route('GET', '/api/proposals/:id/pdf', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const proposals = readJSON('proposals.json');
  const p = proposals.find(p => p.id === params.id);
  if (!p) return error(res, 'Propuesta no encontrada', 404);
  if (!p.selectedVariantId) return error(res, 'No hay variante seleccionada');
  const variant = p.variants.find(v => v.id === p.selectedVariantId);
  if (!variant) return error(res, 'Variante no encontrada');

  const clients = readJSON('clients.json');
  const client = clients.find(c => c.id === p.clientId) || {};

  // Generate HTML for PDF
  const html = generatePDFHTML(client, p, variant);

  cors(res);
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Disposition': `inline; filename="Propuesta_${client.company || 'Cliente'}_${p.formData.eventName || 'Evento'}.html"`,
  });
  res.end(html);
});

function generatePDFHTML(client, proposal, variant) {
  const fd = proposal.formData;
  const today = new Date().toLocaleDateString('es-ES', { day: 'numeric', month: 'long', year: 'numeric' });
  const ref = proposal.id.slice(0, 8).toUpperCase();

  const servicesRows = variant.services.map(s => `
    <tr>
      <td style="padding:14px 20px;border-bottom:1px solid #f0f0f0;"><strong style="color:#1a1a2e;">${s.name}</strong></td>
      <td style="padding:14px 20px;border-bottom:1px solid #f0f0f0;text-align:center;color:#555;">${s.quantity}</td>
      <td style="padding:14px 20px;border-bottom:1px solid #f0f0f0;text-align:right;font-weight:600;">${(s.totalClient || 0).toLocaleString('es-ES')} &euro;</td>
    </tr>
  `).join('');

  const serviceBlocksHTML = variant.services.map((s, i) => `
    <div style="page-break-inside:avoid;margin-bottom:40px;${i > 0 ? 'padding-top:20px;border-top:1px solid #eee;' : ''}">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;">
        <div style="flex:1;">
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#e94560;font-weight:700;">Activaci&oacute;n ${String(i + 1).padStart(2, '0')}</div>
          <h4 style="font-size:20px;font-weight:800;color:#1a1a2e;margin-top:4px;line-height:1.3;">${s.name}</h4>
          ${s.headline ? `<div style="font-size:14px;color:#666;font-style:italic;margin-top:4px;">${s.headline}</div>` : ''}
        </div>
        <div style="background:#1a1a2e;color:#fff;padding:8px 16px;border-radius:8px;font-size:16px;font-weight:700;flex-shrink:0;margin-left:16px;">
          ${(s.totalClient || 0).toLocaleString('es-ES')} &euro;
        </div>
      </div>
      ${s.fullDescription ? `<p style="font-size:14px;line-height:1.8;color:#444;margin-bottom:16px;">${s.fullDescription}</p>` : (s.description ? `<p style="font-size:14px;line-height:1.8;color:#444;margin-bottom:16px;">${s.description}</p>` : '')}
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
        ${(s.objectives && s.objectives.length > 0) ? `
          <div style="background:#f8f9fb;padding:16px;border-radius:10px;">
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:#e94560;font-weight:700;margin-bottom:10px;">Objetivos</div>
            ${s.objectives.map(o => `<div style="font-size:13px;color:#444;padding:4px 0;padding-left:16px;position:relative;"><span style="position:absolute;left:0;color:#e94560;">&#9654;</span> ${o}</div>`).join('')}
          </div>
        ` : ''}
        ${(s.includes && s.includes.length > 0) ? `
          <div style="background:#f8f9fb;padding:16px;border-radius:10px;">
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:#1a1a2e;font-weight:700;margin-bottom:10px;">Incluye</div>
            ${s.includes.map(inc => `<div style="font-size:13px;color:#444;padding:4px 0;padding-left:16px;position:relative;"><span style="position:absolute;left:0;color:#2ecc71;">&#10003;</span> ${inc}</div>`).join('')}
          </div>
        ` : ''}
      </div>
    </div>
  `).join('');

  const kpisHTML = (variant.kpis || []).map(k => `
    <div style="background:#f8f9fb;border-radius:10px;padding:20px;text-align:center;">
      <div style="font-size:24px;font-weight:800;color:#e94560;">${k.target}</div>
      <div style="font-size:13px;font-weight:600;color:#1a1a2e;margin-top:4px;">${k.metric}</div>
      <div style="font-size:11px;color:#888;margin-top:4px;">${k.description || ''}</div>
    </div>
  `).join('');

  const timelineHTML = (variant.timeline || []).map((t, i) => `
    <div style="display:flex;gap:16px;margin-bottom:16px;">
      <div style="width:40px;height:40px;background:${i === 0 ? '#e94560' : '#1a1a2e'};border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:14px;flex-shrink:0;">${i + 1}</div>
      <div style="flex:1;padding-top:4px;">
        <strong style="font-size:15px;color:#1a1a2e;">${t.phase}</strong>
        <span style="font-size:12px;color:#e94560;margin-left:8px;">${t.duration}</span>
        <div style="font-size:13px;color:#666;margin-top:4px;line-height:1.5;">${t.tasks}</div>
      </div>
    </div>
  `).join('');

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Propuesta Comercial - ${variant.title} - ${client.company || 'Cliente'}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:'Inter',sans-serif; color:#1a1a2e; background:#fff; font-size:14px; line-height:1.6; }
  .page { max-width:820px; margin:0 auto; }

  /* ─ Cover ─ */
  .cover { min-height:100vh; background:linear-gradient(135deg, #1a1a2e 0%, #16213e 40%, #0f3460 100%); color:#fff; display:flex; flex-direction:column; justify-content:center; padding:80px 60px; position:relative; overflow:hidden; page-break-after:always; }
  .cover::before { content:''; position:absolute; top:-100px; right:-100px; width:500px; height:500px; background:radial-gradient(circle, rgba(233,69,96,0.15) 0%, transparent 70%); border-radius:50%; }
  .cover::after { content:''; position:absolute; bottom:-50px; left:-50px; width:300px; height:300px; background:radial-gradient(circle, rgba(233,69,96,0.1) 0%, transparent 70%); border-radius:50%; }
  .cover-logo { font-size:20px; font-weight:700; letter-spacing:1px; opacity:0.7; position:relative; z-index:1; }
  .cover-logo span { color:#e94560; }
  .cover-title { font-size:42px; font-weight:900; line-height:1.1; margin-top:60px; position:relative; z-index:1; }
  .cover-tagline { font-size:18px; font-weight:300; opacity:0.8; margin-top:16px; position:relative; z-index:1; line-height:1.5; }
  .cover-client { margin-top:60px; position:relative; z-index:1; }
  .cover-client-label { font-size:11px; text-transform:uppercase; letter-spacing:2px; opacity:0.5; }
  .cover-client-name { font-size:24px; font-weight:700; margin-top:4px; }
  .cover-meta { position:absolute; bottom:40px; right:60px; text-align:right; font-size:12px; opacity:0.5; z-index:1; }
  .cover-accent { width:60px; height:4px; background:#e94560; border-radius:2px; margin-top:24px; position:relative; z-index:1; }

  /* ─ Content pages ─ */
  .content { padding:60px; }
  .section { margin-bottom:48px; page-break-inside:avoid; }
  h2 { font-size:11px; text-transform:uppercase; letter-spacing:3px; color:#e94560; font-weight:700; margin-bottom:8px; }
  h3 { font-size:24px; font-weight:800; color:#1a1a2e; margin-bottom:20px; line-height:1.3; }
  .lead-text { font-size:16px; line-height:1.8; color:#444; }
  .divider { width:40px; height:3px; background:#e94560; border-radius:2px; margin:32px 0; }

  /* ─ Storytelling block ─ */
  .story-block { background:linear-gradient(135deg, #fafbfc 0%, #f5f6f8 100%); border-left:4px solid #e94560; padding:32px; border-radius:0 12px 12px 0; margin:24px 0; }
  .story-block p { font-size:15px; line-height:1.9; color:#333; }

  /* ─ KPIs grid ─ */
  .kpis-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(160px, 1fr)); gap:16px; margin:20px 0; }

  /* ─ Experience ─ */
  .experience-block { background:#1a1a2e; color:#fff; padding:40px; border-radius:16px; margin:20px 0; }
  .experience-block p { font-size:15px; line-height:1.8; opacity:0.9; }

  /* ─ ROI ─ */
  .roi-block { background:linear-gradient(135deg, #e94560 0%, #c23152 100%); color:#fff; padding:32px; border-radius:12px; margin:20px 0; }
  .roi-block p { font-size:15px; line-height:1.8; }

  /* ─ Table ─ */
  table { width:100%; border-collapse:collapse; margin:20px 0; }
  thead th { background:#1a1a2e; color:#fff; padding:14px 20px; font-size:11px; text-transform:uppercase; letter-spacing:1px; font-weight:600; }
  thead th:first-child { border-radius:10px 0 0 0; }
  thead th:last-child { border-radius:0 10px 0 0; }
  .total-row td { padding:20px; font-size:20px; font-weight:800; background:#f8f9fb; }

  /* ─ Why Encom ─ */
  .why-block { display:flex; gap:20px; align-items:flex-start; margin:20px 0; padding:24px; background:#f8f9fb; border-radius:12px; }
  .why-icon { width:48px; height:48px; background:#e94560; border-radius:12px; display:flex; align-items:center; justify-content:center; color:#fff; font-size:24px; flex-shrink:0; }
  .why-text { font-size:14px; line-height:1.7; color:#444; }

  /* ─ Footer ─ */
  .page-footer { text-align:center; padding:32px 0; border-top:2px solid #f0f0f0; margin-top:48px; }
  .page-footer strong { color:#1a1a2e; }

  /* ─ Conditions ─ */
  .conditions { font-size:12px; color:#888; line-height:1.8; padding:20px; background:#fafbfc; border-radius:8px; }

  /* ─ CTA ─ */
  .cta-block { text-align:center; padding:48px 40px; background:linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color:#fff; border-radius:16px; margin:32px 0; }
  .cta-block h3 { color:#fff; font-size:22px; }
  .cta-block p { opacity:0.8; margin-top:12px; font-size:15px; }

  @media print {
    .cover { min-height:auto; padding:60px 40px; }
    body { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  }
</style>
</head>
<body>

<!-- ═══ COVER PAGE ═══ -->
<div class="page">
  <div class="cover">
    <div class="cover-logo">ENCOM<span>.</span></div>
    <div class="cover-accent"></div>
    <div class="cover-title">${variant.title}</div>
    <div class="cover-tagline">${variant.tagline || variant.summary || ''}</div>
    <div class="cover-client">
      <div class="cover-client-label">Propuesta exclusiva para</div>
      <div class="cover-client-name">${client.company || 'Cliente'}</div>
    </div>
    <div class="cover-meta">${today}<br>Ref: ${ref}</div>
  </div>

  <!-- ═══ CONTENT ═══ -->
  <div class="content">

    <!-- Executive Summary -->
    <div class="section">
      <h2>Resumen ejecutivo</h2>
      <h3>${variant.title}</h3>
      <div class="story-block">
        <p>${variant.storytelling || variant.summary || ''}</p>
      </div>
    </div>

    <!-- The Concept -->
    ${variant.concept ? `
    <div class="section">
      <h2>El concepto</h2>
      <h3>Una experiencia que marca la diferencia</h3>
      <p class="lead-text">${variant.concept}</p>
    </div>
    ` : ''}

    <!-- The Experience -->
    ${variant.experience ? `
    <div class="section">
      <h2>La experiencia</h2>
      <h3>Lo que vivir&aacute;n los asistentes</h3>
      <div class="experience-block">
        <p>${variant.experience}</p>
      </div>
    </div>
    ` : ''}

    <!-- KPIs -->
    ${(variant.kpis || []).length > 0 ? `
    <div class="section">
      <h2>Impacto esperado</h2>
      <h3>KPIs y m&eacute;tricas de &eacute;xito</h3>
      <div class="kpis-grid">
        ${kpisHTML}
      </div>
    </div>
    ` : ''}

    <!-- ROI -->
    ${variant.roi ? `
    <div class="section">
      <h2>Retorno de la inversi&oacute;n</h2>
      <h3>Por qu&eacute; esta inversi&oacute;n vale la pena</h3>
      <div class="roi-block">
        <p>${variant.roi}</p>
      </div>
    </div>
    ` : ''}

    <!-- Services Detail Blocks -->
    <div class="section">
      <h2>Qu&eacute; incluye esta propuesta</h2>
      <h3>Activaciones y servicios en detalle</h3>
      ${serviceBlocksHTML}
    </div>

    <!-- Investment Summary Table -->
    <div class="section" style="page-break-inside:avoid;">
      <h2>Resumen de inversi&oacute;n</h2>
      <h3>Cuadro econ&oacute;mico</h3>
      <table>
        <thead>
          <tr>
            <th style="text-align:left;">Concepto</th>
            <th style="text-align:center;width:80px;">Uds.</th>
            <th style="text-align:right;width:120px;">Importe</th>
          </tr>
        </thead>
        <tbody>
          ${servicesRows}
        </tbody>
        <tfoot>
          <tr class="total-row">
            <td colspan="2" style="text-align:right;padding-right:20px;">INVERSI&Oacute;N TOTAL</td>
            <td style="text-align:right;color:#e94560;">${(variant.totalClient || 0).toLocaleString('es-ES')} &euro;</td>
          </tr>
        </tfoot>
      </table>
      <div style="font-size:11px;color:#aaa;margin-top:8px;text-align:right;">* IVA no incluido</div>
    </div>

    <!-- Timeline -->
    ${(variant.timeline || []).length > 0 ? `
    <div class="section">
      <h2>Plan de ejecuci&oacute;n</h2>
      <h3>Timeline del proyecto</h3>
      ${timelineHTML}
    </div>
    ` : ''}

    <!-- Why Encom -->
    ${variant.whyEncom ? `
    <div class="section">
      <h2>Sobre Encom</h2>
      <h3>Por qu&eacute; somos tu partner ideal</h3>
      <div class="why-block">
        <div class="why-icon">E</div>
        <div class="why-text">${variant.whyEncom}</div>
      </div>
    </div>
    ` : ''}

    <!-- Project Info Grid -->
    <div class="section">
      <h2>Datos del proyecto</h2>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div style="background:#f8f9fb;padding:16px;border-radius:8px;"><div style="font-size:10px;text-transform:uppercase;color:#888;letter-spacing:1px;">Cliente</div><div style="font-weight:600;margin-top:4px;">${client.company || '-'}</div></div>
        <div style="background:#f8f9fb;padding:16px;border-radius:8px;"><div style="font-size:10px;text-transform:uppercase;color:#888;letter-spacing:1px;">Contacto</div><div style="font-weight:600;margin-top:4px;">${client.contactName || '-'}</div></div>
        <div style="background:#f8f9fb;padding:16px;border-radius:8px;"><div style="font-size:10px;text-transform:uppercase;color:#888;letter-spacing:1px;">Fecha prevista</div><div style="font-weight:600;margin-top:4px;">${fd.eventDate || 'Por determinar'}</div></div>
        <div style="background:#f8f9fb;padding:16px;border-radius:8px;"><div style="font-size:10px;text-transform:uppercase;color:#888;letter-spacing:1px;">Ubicaci&oacute;n</div><div style="font-weight:600;margin-top:4px;">${fd.location || 'Por determinar'}</div></div>
      </div>
    </div>

    <!-- CTA -->
    <div class="cta-block">
      <h3>Hagamos que suceda</h3>
      <p>Estamos listos para convertir esta visi&oacute;n en realidad.<br>Contacta con nosotros para dar el siguiente paso.</p>
      <div style="margin-top:20px;font-size:13px;opacity:0.6;">contacto@encom.es &middot; encom.es</div>
    </div>

    <!-- Conditions -->
    <div class="section">
      <div class="conditions">
        <strong>Condiciones generales:</strong> Propuesta v&aacute;lida 30 d&iacute;as desde su emisi&oacute;n. Precios en euros, IVA no incluido. Forma de pago: 50% a la confirmaci&oacute;n, 50% a la finalizaci&oacute;n. Cualquier modificaci&oacute;n sobre el alcance descrito se presupuestar&aacute; por separado. Esta propuesta es confidencial y ha sido elaborada exclusivamente para ${client.company || 'el cliente'}.
      </div>
    </div>

    <div class="page-footer">
      <strong>ENCOM</strong> &mdash; OWN Valencia &middot; Valencia Game City<br>
      <span style="font-size:12px;color:#aaa;">Experiencias que transforman</span>
    </div>
  </div>
</div>
</body>
</html>`;
}

// ════════════════════════════════════════════════════════════
// NOTIFICATIONS
// ════════════════════════════════════════════════════════════
route('GET', '/api/notifications', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const proposals = readJSON('proposals.json');
  const clients = readJSON('clients.json');
  const users = readJSON('users.json');
  let notifs = [];

  if (user.role === 'admin') {
    // Admin sees pending validations
    proposals.filter(p => p.status === 'pending_validation').forEach(p => {
      notifs.push({
        type: 'pending_validation',
        message: `${(users.find(u => u.id === p.vendedorId) || {}).name || 'Vendedor'} solicita validación para "${p.formData.eventName}"`,
        proposalId: p.id,
        date: p.updatedAt,
      });
    });
  } else {
    // Vendedor sees validated proposals ready to send
    proposals.filter(p => p.vendedorId === user.id && p.status === 'validated').forEach(p => {
      notifs.push({
        type: 'validated',
        message: `Tu propuesta "${p.formData.eventName}" ha sido validada. Lista para enviar.`,
        proposalId: p.id,
        date: p.validatedAt,
      });
    });
  }

  notifs.sort((a, b) => new Date(b.date) - new Date(a.date));
  json(res, notifs);
});

// ════════════════════════════════════════════════════════════
// HTTP Server
// ════════════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const urlPath = parsedUrl.pathname;
  const method = req.method;

  // CORS preflight
  if (method === 'OPTIONS') { cors(res); res.writeHead(204); res.end(); return; }

  // API routes
  for (const r of routes) {
    const params = matchRoute(method, urlPath, r.method, r.pattern);
    if (params) {
      try { await r.handler(req, res, params); }
      catch (err) { console.error(err); error(res, 'Error interno', 500); }
      return;
    }
  }

  // Static files
  let filePath = urlPath === '/' ? '/index.html' : urlPath;
  filePath = path.join(PUBLIC_DIR, filePath);
  const ext = path.extname(filePath);
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const mime = MIME[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    fs.createReadStream(filePath).pipe(res);
  } else {
    // SPA fallback
    const indexPath = path.join(PUBLIC_DIR, 'index.html');
    if (fs.existsSync(indexPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      fs.createReadStream(indexPath).pipe(res);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    }
  }
});

server.listen(PORT, () => {
  console.log(`\n  🚀 EncomVentas running on http://localhost:${PORT}\n`);
});
