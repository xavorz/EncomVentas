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
function requireNotCaptador(req, res) {
  const user = requireAuth(req, res);
  if (user && user.role === 'captador') { error(res, 'Acceso denegado para captadores', 403); return null; }
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
const SSO_AUTO_CREATE = (process.env.SSO_AUTO_CREATE || 'true') === 'true';

const SSO_STYLE = `*{margin:0;padding:0;box-sizing:border-box}body{background:#0f1117;display:flex;align-items:center;justify-content:center;height:100vh;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}.c{text-align:center}.logo{width:48px;height:48px;background:#FFB800;border-radius:12px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:24px;color:#0f1117;margin:0 auto 16px}.t{color:#fff;font-size:15px;margin-bottom:8px}.s{color:rgba(255,255,255,.4);font-size:13px}.e{color:#ef4444;font-size:14px;margin-top:12px}.bar{width:120px;height:3px;background:rgba(255,255,255,.1);border-radius:3px;margin:20px auto 0;overflow:hidden}.bar::after{content:'';display:block;width:40%;height:100%;background:#FFB800;border-radius:3px;animation:slide 1s ease-in-out infinite}@keyframes slide{0%{transform:translateX(-100%)}100%{transform:translateX(350%)}}a{color:#FFB800;text-decoration:none;font-size:13px;margin-top:16px;display:inline-block}`;

function ssoErrorPage(message) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>${SSO_STYLE}</style></head><body><div class="c"><div class="logo">E</div><div class="t">Error de acceso</div><div class="e">${message}</div><a href="https://tools.encom.es">Volver al portal</a></div></body></html>`;
}

function ssoLoadingPage(tokenKey, tokenValue, userKey, userValue) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>${SSO_STYLE}</style></head><body><div class="c"><div class="logo">E</div><div class="t">Conectando...</div><div class="s">Encom Tools</div><div class="bar"></div></div><script type="text/javascript">try{localStorage.setItem("${tokenKey}","${tokenValue}");localStorage.setItem("${userKey}",'${userValue.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}');window.location.replace("/")}catch(e){document.querySelector(".t").textContent="Error";document.querySelector(".s").textContent=e.message}</script></body></html>`;
}

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
  if (!ssoToken) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(ssoErrorPage('Token no proporcionado'));
  }

  try {
    console.log('[SSO] Validating token against portal:', PORTAL_URL);
    const result = await ssoValidate(ssoToken);
    console.log('[SSO] Validation result:', JSON.stringify(result));
    if (!result.valid) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(ssoErrorPage('Token inválido o expirado. Vuelve al portal e inténtalo de nuevo.'));
    }

    // Create local session
    const localToken = generateToken();
    const users = readJSON('users.json');
    let user = users.find(u => u.email === result.user.email);
    if (!user) {
      if (!SSO_AUTO_CREATE) {
        console.log('[SSO] User not found and auto-create disabled:', result.user.email);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(ssoErrorPage('No tienes cuenta en esta herramienta. Contacta con un administrador.'));
      }
      user = { id: uuid(), name: result.user.name, email: result.user.email, role: result.user.role || 'captador', passwordHash: '', createdAt: now() };
      users.push(user);
      writeJSON('users.json', users);
    }
    const sessions = readJSON('sessions.json');
    sessions.push({ token: localToken, userId: user.id, createdAt: now() });
    writeJSON('sessions.json', sessions);

    const userData = JSON.stringify({ id: user.id, name: user.name, email: user.email, role: user.role });
    cors(res);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(ssoLoadingPage('ev_token', localToken, 'user', userData));
  } catch (err) {
    console.error('[SSO] Error:', err.message);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(ssoErrorPage('No se pudo conectar con el portal. Inténtalo de nuevo.'));
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
  if (!['admin', 'vendedor', 'captador'].includes(role)) return error(res, 'Rol debe ser admin, vendedor o captador');
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
// LEADS (Captador system)
// ════════════════════════════════════════════════════════════

// Create a lead (captador, vendedor, admin)
route('POST', '/api/leads', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await parseBody(req);
  const { company, contactName, contactRole, contactEmail, contactPhone, notes } = body;

  // Validation: company AND contactName AND contactRole are REQUIRED
  if (!company || !contactName || !contactRole) {
    return error(res, 'Empresa, nombre del contacto y cargo son requeridos');
  }

  const leads = readJSON('leads.json');
  const lead = {
    id: uuid(),
    company: company.trim(),
    contactName: contactName.trim(),
    contactRole: contactRole.trim(),
    contactEmail: contactEmail ? contactEmail.trim() : '',
    contactPhone: contactPhone ? contactPhone.trim() : '',
    notes: notes || '',
    status: 'pending',
    createdBy: user.id,
    createdAt: now(),
    validatedBy: null,
    validatedAt: null,
    validatorNotes: ''
  };
  leads.push(lead);
  writeJSON('leads.json', leads);
  json(res, lead, 201);
});

// List leads (captador sees own, vendedor/admin sees all)
route('GET', '/api/leads', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  let leads = readJSON('leads.json');

  // Filter based on role
  if (user.role === 'captador') {
    leads = leads.filter(l => l.createdBy === user.id);
  }
  // vendedor and admin see all

  // Enrich with creator names
  const users = readJSON('users.json');
  leads = leads.map(l => ({
    ...l,
    creatorName: (users.find(u => u.id === l.createdBy) || {}).name || 'Desconocido'
  }));

  // Sort by most recent
  leads.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  json(res, leads);
});

// Validate or reject a lead (vendedor/admin only)
route('PATCH', '/api/leads/:id', async (req, res, params) => {
  const user = requireAuth(req, res);
  if (!user) return;

  if (!['vendedor', 'admin'].includes(user.role)) {
    return error(res, 'Solo vendedores y admins pueden validar leads', 403);
  }

  const body = await parseBody(req);
  const { status, validatorNotes } = body;

  if (!['validated', 'rejected'].includes(status)) {
    return error(res, 'Estado debe ser validated o rejected');
  }

  const leads = readJSON('leads.json');
  const idx = leads.findIndex(l => l.id === params.id);
  if (idx === -1) return error(res, 'Lead no encontrado', 404);

  leads[idx].status = status;
  leads[idx].validatedBy = user.id;
  leads[idx].validatedAt = now();
  leads[idx].validatorNotes = validatorNotes || '';

  writeJSON('leads.json', leads);
  json(res, leads[idx]);
});

// Get ranking of captadores
route('GET', '/api/leads/ranking', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const leads = readJSON('leads.json');
  const users = readJSON('users.json');

  // Build stats by captador
  const captadores = users.filter(u => u.role === 'captador');
  const ranking = captadores.map(c => {
    const userLeads = leads.filter(l => l.createdBy === c.id);
    const validatedLeads = userLeads.filter(l => l.status === 'validated').length;
    const rejectedLeads = userLeads.filter(l => l.status === 'rejected').length;
    const pendingLeads = userLeads.filter(l => l.status === 'pending').length;
    const totalLeads = userLeads.length;
    const validationRate = totalLeads > 0 ? Math.round((validatedLeads / totalLeads) * 100) : 0;

    return {
      userId: c.id,
      userName: c.name,
      totalLeads,
      validatedLeads,
      rejectedLeads,
      pendingLeads,
      validationRate
    };
  });

  // Sort by validated leads descending
  ranking.sort((a, b) => b.validatedLeads - a.validatedLeads);

  json(res, ranking);
});

// Delete a lead (admin only)
route('DELETE', '/api/leads/:id', async (req, res, params) => {
  const user = requireAdmin(req, res);
  if (!user) return;

  let leads = readJSON('leads.json');
  const lead = leads.find(l => l.id === params.id);
  if (!lead) return error(res, 'Lead no encontrado', 404);

  leads = leads.filter(l => l.id !== params.id);
  writeJSON('leads.json', leads);
  json(res, { ok: true });
});

// ════════════════════════════════════════════════════════════
// PROPOSALS
// ════════════════════════════════════════════════════════════

// List proposals (todos los vendedores y admin ven todas — solo el dueño/admin puede modificar)
route('GET', '/api/proposals', async (req, res) => {
  const user = requireNotCaptador(req, res);
  if (!user) return;
  let proposals = readJSON('proposals.json');
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

// Get single proposal (lectura abierta a todos los vendedores y admin)
route('GET', '/api/proposals/:id', async (req, res, params) => {
  const user = requireNotCaptador(req, res);
  if (!user) return;
  const proposals = readJSON('proposals.json');
  const p = proposals.find(p => p.id === params.id);
  if (!p) return error(res, 'Propuesta no encontrada', 404);
  const clients = readJSON('clients.json');
  const users = readJSON('users.json');
  p.clientName = (clients.find(c => c.id === p.clientId) || {}).company || 'Desconocido';
  p.clientData = clients.find(c => c.id === p.clientId) || {};
  p.vendedorName = (users.find(u => u.id === p.vendedorId) || {}).name || 'Desconocido';
  json(res, p);
});

// Create proposal (lead intake form)
route('POST', '/api/proposals', async (req, res) => {
  const user = requireNotCaptador(req, res);
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
  const user = requireNotCaptador(req, res);
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
  const user = requireNotCaptador(req, res);
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
  const user = requireNotCaptador(req, res);
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

  // Leads stats
  const leads = readJSON('leads.json');
  const totalLeads = leads.length;
  const pendingLeads = leads.filter(l => l.status === 'pending').length;
  const validatedLeads = leads.filter(l => l.status === 'validated').length;
  const rejectedLeads = leads.filter(l => l.status === 'rejected').length;

  // Top captadores
  const captadores = users.filter(u => u.role === 'captador');
  const topCaptadores = captadores.map(c => {
    const cLeads = leads.filter(l => l.createdBy === c.id);
    const validated = cLeads.filter(l => l.status === 'validated').length;
    return { id: c.id, name: c.name, validatedLeads: validated, totalLeads: cLeads.length };
  })
  .filter(c => c.totalLeads > 0)
  .sort((a, b) => b.validatedLeads - a.validatedLeads)
  .slice(0, 5);

  const leadsStats = { totalLeads, pendingLeads, validatedLeads, rejectedLeads, topCaptadores };

  json(res, {
    total, byStatus, totalProposed, totalApproved,
    pendingValidation, vendedorStats, medalRanking, recent, monthlyTrend,
    totalClients: clients.length, leadsStats,
  });
});

// ════════════════════════════════════════════════════════════
// CLAUDE AI INTEGRATION
// ════════════════════════════════════════════════════════════

async function callClaude(client, formData, feedback, previousVersions) {
  const systemPrompt = `Eres el director comercial de Encom, productor de DreamHack España (12 años), FIA Motorsport Games, ICE Barcelona Esports Arena, OWN Valencia (+20K asistentes, 15 países, 2.8M impresiones RRSS).

Tu misión: 3 PROPUESTAS COMERCIALES QUE VENDAN. Cada propuesta es un pitch irresistible que va directo al cliente. Debe emocionar, convencer y cerrar.

TRACK RECORD (úsalo como argumento):
- DreamHack España (2011-2023): +12 años, mayor punto de encuentro gaming sur Europa
- OWN Valencia 2025: +20K asistentes únicos, 15 países, +2.8M impresiones RRSS, 8.93M€ valor comunicación
- Eventos propios: Valencia Game City, ICE Barcelona (45K asistentes), FIA Motorsport Games
- Partnership: Supercell/Blast, Winamax, Monster Energy, Movistar (2.8M€ en sponsors confirmados)
Cuándo usarlo: para marcas que dudan ("hemos producido DreamHack 12 años + FIA"), para alcance ("OWN Valencia: +2.8M impresiones"), para instituciones.

PRINCIPIOS DE COPYWRITING (aplica en cada sección):
1. Especificidad (Hopkins): nunca "gran impacto" sino "+428M impresiones digitales en OWN 2025", "alcance estimado 500K impactos en RRSS", "20K asistentes reales de 15 países"
2. Conversación mental del cliente: qué tiene en la cabeza AHORA (Gen Z, ROI, visibilidad) — empieza por ahí
3. El headline manda (Caples): "Grefusa Fuel Station: torneo express con premios instantáneos" > "Propuesta de activación"
4. Investigación (Ogilvy): demuestra que conoces la marca
5. Tono persona, no corporación (Halbert): "esto es lo que funciona en OWN" > "presentamos nuestra propuesta de colaboración estratégica"
6. Transparencia (Cialdini): admite limitaciones primero, luego fortalezas ("somos caros, pero diseñamos la experiencia completa")

ESTRUCTURA ACTIVACIONES:
- SIEMPRE un NOMBRE propio ("Grefusa Fuel Station", "Monster Night Arena", "KFC Pollómetro", no "Stand interactivo")
- Ser concreto: "torneos express nocturnos con premios inmediatos", no "dinámicas interactivas"
- Explicar formato, duración, mecánica, qué se lleva el asistente

REGLAS PRESUPUESTO (OBLIGATORIAS):
- Si cliente da techo (ej: "15.000€", "máximo 50K"), NINGUNA propuesta lo supera
- 3 propuestas distribuidas: Esencial ~40-55%, Recomendada ~65-80%, Premium ~85-100% del techo
- Si rango (10-20k), usa máximo como techo. Si "No indicado", propón rangos variados
- VERIFICA suma servicios = totalClient. Números deben cuadrar exactamente
- Margen objetivo 25-50% según servicio

REGLAS CONTENIDO:
- Cada palabra acerca al cierre. Nada genérico o corporativo vacío
- Precios realistas mercado español
- KPIs: concretos medibles (no "mejorar marca" sino "500K impactos RRSS")
- ROI: números estimados que justifiquen inversión
- Timeline: creíble, profesional
- 5-10 servicios/activaciones por propuesta
- CADA servicio: fullDescription 80-120 palabras, 3 objectives concretos, 3-5 elements específicos ("2 pantallas LED 4K", no "pantallas")
- Propuesta 1: ajustada. Propuesta 3: premium. SIEMPRE dentro presupuesto máximo
- STORYTELLING ES CRÍTICO: si cliente no se emociona en párrafos 1-2, no sigue leyendo
- Español natural, persuasivo. Nombres servicios = EXPERIENCIA ("Escenario Inmersivo 360° con Mapping Audiovisual", no "Sonido e iluminación")

JSON ESTRUCTURA (exacta):
{
  "id": "variant-1",
  "title": "Nombre potente (para marca)",
  "tagline": "1 línea esencia",
  "storytelling": "150-250 palabras. Visión proyecto, imaginar día evento, impacto, emoción. Visual, aspiracional.",
  "concept": "80-120 palabras. Qué hace único. Idea central.",
  "experience": "100-150 palabras. Qué vivirán asistentes paso a paso, tangible, sensorial.",
  "kpis": [{"metric": "Nombre", "target": "Valor", "description": "Cómo mide, por qué importa"}],
  "roi": "60-100 palabras. ROI esperado, estimaciones concretas (alcance, impacto marca, leads, conversiones)",
  "whyEncom": "60-80 palabras. Por qué Encom es ideal (experiencia, casos, capacidades)",
  "timeline": [{"phase": "Nombre", "duration": "X semanas", "tasks": "Tareas clave"}],
  "services": [
    {
      "name": "Nombre experiencia",
      "headline": "1 línea qué es, por qué importa",
      "fullDescription": "80-120 palabras comercial. Qué vivirá asistente/cliente, cómo funciona, qué especial. Experiencia, no técnico.",
      "objectives": ["Objetivo 1", "Objetivo 2", "Objetivo 3"],
      "includes": ["Elemento 1", "Elemento 2", "Elemento 3 (específico)"],
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
  "summary": "3-4 frases impacto para inicio documento"
}

Responde SOLO JSON array de 3 objetos. Sin markdown, sin texto adicional.`;

  let userMessage = `CLIENTE: ${client.company || '?'} (${client.sector || '?'}) | Contacto: ${client.contactName || '?'}

EVENTO: ${formData.eventName || 'Sin nombre'} | Tipo: ${formData.eventType || '?'} | Fecha: ${formData.eventDate || '?'} | Ubicación: ${formData.location || '?'}
Duración: ${formData.duration || '?'} | Asistentes: ${formData.attendees || '?'} | Presupuesto: ${formData.budget || 'No indicado'}

OBJETIVOS: ${formData.objectives || 'No especificados'}

AUDIENCIA: ${formData.targetAudience || 'No especificada'}

SERVICIOS: ${(formData.servicesInterest || []).join(', ') || 'Abierto'}

CONTEXTO: ${formData.freeContext || 'Sin contexto'}`;

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
    system: [
      {
        type: 'text',
        text: systemPrompt,
        cache_control: { type: 'ephemeral' }
      }
    ],
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
// COLD EMAILS — MÉTODO OWN (importado de Encom Assistant V2.1)
// ════════════════════════════════════════════════════════════

const COLD_EMAIL_SYSTEM_PROMPT = `Eres un redactor senior de cold outreach B2B especializado en patrocinios, colaboraciones de marca y activaciones para OWN Valencia (festival cultura pop, gaming, K-pop, cosplay, +20K asistentes únicos, 15 países, +2.8M impresiones RRSS, 8.93M€ valor comunicación) y para Encom (productor de DreamHack España 12 años, FIA Motorsport Games, ICE Barcelona, Valencia Game City). Tu trabajo NO es escribir mails bonitos. Tu trabajo es generar interés real, abrir conversación y hacer que la marca vea por qué tiene sentido estar en OWN.

## Objetivo del mail
El mail no cierra una venta. El mail abre una conversación. Cada mail debe conseguir que el destinatario piense "esto tiene sentido para mi marca", vea OWN como contexto útil (no como "otro evento"), y sienta una mezcla de oportunidad, encaje, curiosidad y a veces necesidad de no quedarse fuera.

## Proceso obligatorio antes de redactar
1. **Identifica la categoría de la marca** (moda, retail tech, alimentación, telco, gaming hardware, juguetes/familia, banca/crypto, movilidad, etc.).
2. **Investiga con web_search**: campañas recientes, colaboraciones, activaciones, partnerships, posicionamiento, tono de marca, lanzamientos. NO escribas sin haber buscado. Si no encuentras nada útil, dilo internamente y escribe sin hook personalizado — un mail sin referencia es mejor que un mail con una mentira.
3. **Decide**: qué pain o insight usar, qué parte de OWN encaja mejor, si meter una idea concreta de activación, si usar prueba social.
4. **Redacta**: corto o medio, con valor real, sin relleno, tono humano, sin estructura repetitiva.

## Reglas de oro

**1. NO empieces hablando de OWN sin contexto.** En frío, el destinatario no conoce OWN. NO abras con "OWN es...", "Del 3 al 5 de julio celebramos OWN...", "OWN es el mayor evento...". Abre con un insight, un pain, una oportunidad, una observación útil sobre la marca o una referencia a algo que han hecho. Después introduces OWN.

**2. Ataca un pain o una oportunidad real.** Cada vertical tiene pains distintos. No uses el mismo mail para todas las marcas. Ejemplos:
- moda/lifestyle: seguir siendo relevante en un entorno saturado
- retail tech: no basta con vender, hay que generar preferencia
- alimentación/snacks: estar en el momento de consumo, no solo en el lineal
- telco: conectar con audiencia tech-savvy en contexto real
- gaming hardware: que el producto se vea funcionando, no se explique
- juguetes/familia: pasar de producto a experiencia compartida

El pain aparece de forma natural, no como frase de manual. NO escribas "Vuestro gran reto es..." ni "Uno de vuestros principales desafíos es...". Mejor: "Hoy muchas marcas de X están encontrando un límite claro...", "Cada vez más marcas de X buscan...", "Hay contextos donde vuestro producto se entiende mucho mejor...".

**3. Cada frase debe justificar su existencia.** Nada de relleno. PROHIBIDO escribir: "Somos un evento innovador donde las marcas conectan con los jóvenes", "Creemos firmemente en crear sinergias", "Sería una gran oportunidad para ambas partes", "Nos encantaría contar con vosotros". Eso no aporta nada. Sí aporta valor: explicar por qué ese contexto es útil para esa marca, mostrar una activación concreta, conectar con un lanzamiento o collab reciente.

**4. Personaliza de verdad.** Usa la info que has buscado para conectar con OWN. NO expliques a la marca quién es ni qué hace. NO digas "Sois líderes en...", "Lleváis años haciendo...", "Tenéis una trayectoria increíble...". Sí di "He visto vuestra activación con X", "Al ver vuestra colaboración con X, pensé que podía tener sentido escribiros", "La forma en que habéis trabajado X encaja bastante con...".

**5. NO suenes a IA.** Prohibido sonar excesivamente limpio, redondo, marketiniano, abstracto o "perfecto". NUNCA digas "creo". La escritura humana corta frases antes, no lo explica todo, suena conversacional, deja espacio, prioriza la idea sobre la forma.

**6. NO uses siempre la misma estructura.** Evita la plantilla repetitiva pain → OWN → encaje → CTA. Varía el punto de entrada: insight, referencia a campaña, observación sectorial, uso real del producto, oportunidad estratégica, tensión competitiva, caso de éxito, idea concreta, contexto temporal, afinidad con un bloque específico de OWN (K-pop, cosplay, gaming, familia, etc.).

**7. Si metes una idea de activación, simple y visual.** Que se entienda rápido, se visualice en una línea, parezca fácil de imaginar. Ejemplos: cata a ciegas en escenario, zona de descanso, backstage beauty zone, reto con producto, presencia integrada en el bloque K-pop, edición especial llevada al evento. NO desarrolles la producción entera, solo deja ver el potencial.

**8. CTA final natural.** Buenos cierres: "Si tiene sentido explorarlo, lo vemos", "Si os encaja, lo comentamos con calma", "Si te parece, lo vemos y valoramos opciones", "Si tiene sentido, hablamos". Malos cierres: "Esperamos contar con su respuesta", "Quedamos a su disposición", "Agendemos una reunión a la mayor brevedad", "Nos encantaría formar parte de vuestra estrategia".

**9. Asuntos cortos y naturales.** NO metas OWN en el asunto en puerta fría salvo caso muy justificado. Buenos asuntos: "¿Lo vemos con calma?", "Una oportunidad interesante para 2026", "Un encaje natural con vuestro público", "Hay sitios donde tiene sentido estar", "Una idea que puede encajar bien". Evita hype, amenazas, comparativas obvias, claims grandilocuentes.

## Cuándo formal y cuándo cercano
- **Más formal**: institución pública, fundación, entidad municipal, perfil senior muy corporativo.
- **Más cercano**: marca de consumo, marketing brand, partnerships, lifestyle, gaming, alimentación, moda. Pero incluso siendo cercano: no infantil, no demasiado "creativo", no fuerces chistes.

## Casos de éxito (Burger King, Domino's, Movistar, Tesla, Nintendo, Monster, Winamax, Supercell, etc.)
Si hay caso previo relevante para la categoría, úsalo como prueba social — no como catálogo de venta. Ejemplo: "Te adjunto un breve PDF con el caso de Burger King y Domino's para que veas cómo hemos trabajado la categoría". NO conviertas el mail en resumen del PDF.

## Cuando la marca ya ha hecho algo parecido
1. Menciónalo. 2. Demuestra que lo has visto. 3. Conecta esa lógica con OWN. Ejemplo: "Al ver vuestra colaboración con Pokémon, pensamos que este año puede haber un encaje muy natural en OWN, donde ese universo va a tener bastante peso".

## Reglas operativas (sin excepción)
- **NO inventes**. Antes de escribir, usa web_search. Si no encuentras nada verificable, escribe sin hook personalizado — un mail sin referencia inventada es mejor que un mail con una mentira.
- **QUIÉN FIRMA**: el mail lo firma SIEMPRE la persona que se te indica en el bloque "FIRMA" del mensaje del usuario. Usa ese nombre exacto. NUNCA "Javi Carrión, CEO" salvo que sea Javi quien firma.
- Si no tienes nombre de contacto, pon [Nombre] y avanza.
- Cuerpo MÁXIMO 6-8 líneas. Si te sale más largo, recórtalo.

## Formato de salida (OBLIGATORIO)
Devuelve SOLO un objeto JSON válido con esta estructura, sin texto adicional ni markdown:
{
  "subject": "asunto corto y natural",
  "body": "cuerpo del mail completo, con saludos y firma incluidos. Usa \\n para saltos de línea.",
  "hook_used": "1 línea explicando qué hook real has usado (qué encontraste con web_search) o 'sin hook personalizado' si no encontraste nada"
}

## Misión final
Escribe mails que parezcan escritos por una persona real, tengan intención, aporten valor, generen curiosidad y hagan que la marca vea por qué OWN tiene sentido para ellos. NO escribas como una IA que "redacta bien". Escribe como alguien que entiende la marca, entiende el contexto y sabe abrir puertas.`;

async function callClaudeColdEmail({ company, contactName, contactRole, sector, notes, brief, signerName, signerEmail }) {
  const userMessage = `MARCA: ${company || '?'}
SECTOR/CATEGORÍA: ${sector || 'no especificado'}
CONTACTO: ${contactName || '[Nombre]'}${contactRole ? ' (' + contactRole + ')' : ''}
NOTAS INTERNAS DEL CLIENTE: ${notes || 'sin notas'}

CONTEXTO/HOOK QUE APORTA EL USUARIO (úsalo si es útil, ignóralo si no):
${brief || '(ninguno — investiga tú con web_search)'}

FIRMA (úsala literal al final del mail):
${signerName}
Encom · OWN Valencia
${signerEmail}

Investiga la marca con web_search antes de escribir. Devuelve SOLO el JSON con subject, body y hook_used.`;

  const requestBody = JSON.stringify({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 4000,
    tools: [
      { type: 'web_search_20250305', name: 'web_search', max_uses: 5 }
    ],
    system: [
      { type: 'text', text: COLD_EMAIL_SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } }
    ],
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
          // Concat all text blocks (response may include web_search tool blocks)
          const text = (result.content || [])
            .filter(b => b.type === 'text')
            .map(b => b.text)
            .join('\n')
            .trim();
          if (!text) return reject(new Error('Respuesta vacía de Claude'));

          let parsed;
          try {
            parsed = JSON.parse(text);
          } catch {
            const match = text.match(/\{[\s\S]*\}/);
            if (match) {
              try { parsed = JSON.parse(match[0]); }
              catch (e) { return reject(new Error('No se pudo parsear el JSON del mail')); }
            } else {
              return reject(new Error('No se pudo parsear el JSON del mail'));
            }
          }
          if (!parsed.subject || !parsed.body) {
            return reject(new Error('JSON sin subject o body'));
          }
          resolve(parsed);
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

// Generate a cold email
route('POST', '/api/cold-emails/generate', async (req, res) => {
  const user = requireNotCaptador(req, res);
  if (!user) return;
  if (!ANTHROPIC_API_KEY) return error(res, 'API Key de Anthropic no configurada', 500);

  const body = await parseBody(req);
  let { clientId, company, contactName, contactRole, sector, notes, brief } = body;

  // If clientId provided, hydrate from CRM
  if (clientId) {
    const clients = readJSON('clients.json');
    const c = clients.find(c => c.id === clientId);
    if (!c) return error(res, 'Cliente no encontrado', 404);
    company = company || c.company;
    contactName = contactName || c.contactName;
    sector = sector || c.sector;
    notes = notes || c.notes;
  }

  if (!company) return error(res, 'Empresa requerida');

  try {
    const ai = await callClaudeColdEmail({
      company, contactName, contactRole, sector, notes, brief,
      signerName: user.name,
      signerEmail: user.email,
    });

    const coldEmails = readJSON('cold-emails.json');
    const record = {
      id: uuid(),
      clientId: clientId || null,
      company,
      contactName: contactName || '',
      contactRole: contactRole || '',
      sector: sector || '',
      brief: brief || '',
      subject: ai.subject,
      body: ai.body,
      hookUsed: ai.hook_used || '',
      signerId: user.id,
      signerName: user.name,
      signerEmail: user.email,
      createdAt: now(),
    };
    coldEmails.push(record);
    writeJSON('cold-emails.json', coldEmails);
    json(res, record, 201);
  } catch (err) {
    console.error('Cold email error:', err.message);
    error(res, 'Error generando mail: ' + err.message, 500);
  }
});

// List cold emails (filter by clientId optional)
route('GET', '/api/cold-emails', async (req, res) => {
  const user = requireNotCaptador(req, res);
  if (!user) return;
  const clientId = new URL(req.url, `http://${req.headers.host}`).searchParams.get('clientId');
  let coldEmails = readJSON('cold-emails.json');
  if (user.role !== 'admin') coldEmails = coldEmails.filter(e => e.signerId === user.id);
  if (clientId) coldEmails = coldEmails.filter(e => e.clientId === clientId);
  coldEmails.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  json(res, coldEmails);
});

// Delete a cold email (owner or admin)
route('DELETE', '/api/cold-emails/:id', async (req, res, params) => {
  const user = requireNotCaptador(req, res);
  if (!user) return;
  let coldEmails = readJSON('cold-emails.json');
  const target = coldEmails.find(e => e.id === params.id);
  if (!target) return error(res, 'Mail no encontrado', 404);
  if (user.role !== 'admin' && target.signerId !== user.id) return error(res, 'Acceso denegado', 403);
  coldEmails = coldEmails.filter(e => e.id !== params.id);
  writeJSON('cold-emails.json', coldEmails);
  json(res, { ok: true });
});

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
