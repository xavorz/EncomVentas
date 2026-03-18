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

  // Per vendedor stats
  const vendedores = users.filter(u => u.role === 'vendedor');
  const vendedorStats = vendedores.map(v => {
    const vp = proposals.filter(p => p.vendedorId === v.id);
    const sent = vp.filter(p => ['sent', 'approved', 'rejected'].includes(p.status));
    const approved = vp.filter(p => p.status === 'approved');
    let revenue = 0;
    approved.forEach(p => {
      const variant = p.variants.find(va => va.id === p.selectedVariantId);
      if (variant) revenue += variant.totalClient || 0;
    });
    return {
      id: v.id, name: v.name,
      total: vp.length, sent: sent.length, approved: approved.length,
      conversionRate: sent.length > 0 ? Math.round((approved.length / sent.length) * 100) : 0,
      revenue
    };
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
    pendingValidation, vendedorStats, recent, monthlyTrend,
    totalClients: clients.length,
  });
});

// ════════════════════════════════════════════════════════════
// CLAUDE AI INTEGRATION
// ════════════════════════════════════════════════════════════

async function callClaude(client, formData, feedback, previousVersions) {
  const systemPrompt = `Eres un experto en diseño de propuestas comerciales para Encom, una empresa líder en gestión de eventos, festivales (OWN Valencia, Valencia Game City), activaciones de marca, patrocinios y experiencias digitales.

Tu trabajo es generar exactamente 3 propuestas comerciales diferentes para un cliente basándote en el contexto proporcionado.

Cada propuesta debe variar en:
- Nivel de precio y alcance (desde una opción más ajustada hasta una premium)
- Enfoque creativo (diferentes conceptos y enfoques para resolver la necesidad del cliente)

Para CADA propuesta debes devolver un JSON con esta estructura exacta:
{
  "id": "variant-1" (o 2, 3),
  "title": "Nombre creativo de la propuesta",
  "approach": "Descripción de 2-3 frases del enfoque creativo y diferencial",
  "summary": "Resumen ejecutivo de 3-4 frases para presentar al cliente",
  "services": [
    {
      "name": "Nombre del servicio/partida",
      "description": "Descripción breve",
      "quantity": 1,
      "unitPrice": 5000,
      "totalClient": 5000,
      "costInternal": 3000
    }
  ],
  "totalClient": 15000,
  "totalCost": 9000,
  "margin": 6000,
  "marginPercent": 40
}

REGLAS IMPORTANTES:
- Los precios deben ser realistas para el mercado español de eventos
- El margen objetivo debe estar entre 25-50% según el tipo de servicio
- Incluye partidas detalladas (producción, logística, personal, tecnología, catering si aplica, etc.)
- Los costes internos son una estimación realista de lo que le costaría a Encom ejecutar
- Cada propuesta debe tener entre 5-12 partidas de servicios
- Los precios al cliente siempre en euros, números enteros
- Sé creativo en los nombres y enfoques, diferencia bien las 3 opciones

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
    max_tokens: 8000,
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

  const servicesRows = variant.services.map(s => `
    <tr>
      <td style="padding:12px 16px;border-bottom:1px solid #eee;font-weight:500;">${s.name}</td>
      <td style="padding:12px 16px;border-bottom:1px solid #eee;color:#555;">${s.description}</td>
      <td style="padding:12px 16px;border-bottom:1px solid #eee;text-align:center;">${s.quantity}</td>
      <td style="padding:12px 16px;border-bottom:1px solid #eee;text-align:right;">${(s.unitPrice || 0).toLocaleString('es-ES')} &euro;</td>
      <td style="padding:12px 16px;border-bottom:1px solid #eee;text-align:right;font-weight:600;">${(s.totalClient || 0).toLocaleString('es-ES')} &euro;</td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Propuesta Comercial - ${client.company || 'Cliente'}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', sans-serif; color: #1a1a2e; background: #fff; }
  .page { max-width: 800px; margin: 0 auto; padding: 40px; }
  .header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 48px; padding-bottom: 24px; border-bottom: 3px solid #e94560; }
  .logo { font-size: 28px; font-weight: 700; color: #1a1a2e; }
  .logo span { color: #e94560; }
  .date { color: #888; font-size: 13px; text-align: right; }
  .ref { font-size: 12px; color: #aaa; margin-top: 4px; }
  h1 { font-size: 26px; font-weight: 700; margin-bottom: 8px; color: #1a1a2e; }
  h2 { font-size: 18px; font-weight: 600; margin: 32px 0 16px; color: #e94560; border-bottom: 1px solid #eee; padding-bottom: 8px; }
  .subtitle { font-size: 16px; color: #555; margin-bottom: 32px; }
  .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 32px; }
  .info-item { background: #f8f9fa; padding: 16px; border-radius: 8px; }
  .info-label { font-size: 11px; text-transform: uppercase; color: #888; font-weight: 600; letter-spacing: 0.5px; }
  .info-value { font-size: 15px; margin-top: 4px; font-weight: 500; }
  .summary { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #fff; padding: 24px; border-radius: 12px; margin: 24px 0; }
  .summary p { font-size: 15px; line-height: 1.7; opacity: 0.9; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; }
  thead th { background: #1a1a2e; color: #fff; padding: 12px 16px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
  thead th:first-child { border-radius: 8px 0 0 0; }
  thead th:last-child { border-radius: 0 8px 0 0; }
  .total-row { background: #f8f9fa; }
  .total-row td { padding: 16px; font-size: 18px; font-weight: 700; }
  .footer { margin-top: 48px; padding-top: 24px; border-top: 2px solid #eee; text-align: center; color: #888; font-size: 12px; }
  @media print { .page { padding: 20px; } body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div>
      <div class="logo">Encom<span>.</span></div>
      <div style="font-size:12px;color:#888;margin-top:4px;">Experiencias que transforman</div>
    </div>
    <div class="date">
      ${today}
      <div class="ref">Ref: ${proposal.id.slice(0, 8).toUpperCase()}</div>
    </div>
  </div>

  <h1>${variant.title}</h1>
  <div class="subtitle">Propuesta comercial para ${client.company || 'Cliente'}</div>

  <div class="info-grid">
    <div class="info-item">
      <div class="info-label">Cliente</div>
      <div class="info-value">${client.company || '-'}</div>
    </div>
    <div class="info-item">
      <div class="info-label">Contacto</div>
      <div class="info-value">${client.contactName || '-'}</div>
    </div>
    <div class="info-item">
      <div class="info-label">Evento</div>
      <div class="info-value">${fd.eventName || '-'}</div>
    </div>
    <div class="info-item">
      <div class="info-label">Fecha</div>
      <div class="info-value">${fd.eventDate || 'Por determinar'}</div>
    </div>
    <div class="info-item">
      <div class="info-label">Ubicaci&oacute;n</div>
      <div class="info-value">${fd.location || 'Por determinar'}</div>
    </div>
    <div class="info-item">
      <div class="info-label">Asistentes estimados</div>
      <div class="info-value">${fd.attendees || 'Por determinar'}</div>
    </div>
  </div>

  <h2>Nuestra propuesta</h2>
  <div class="summary">
    <p>${variant.summary || variant.approach}</p>
  </div>

  <h2>Desglose de servicios</h2>
  <table>
    <thead>
      <tr>
        <th style="text-align:left;">Servicio</th>
        <th style="text-align:left;">Descripci&oacute;n</th>
        <th style="text-align:center;">Uds.</th>
        <th style="text-align:right;">Precio ud.</th>
        <th style="text-align:right;">Total</th>
      </tr>
    </thead>
    <tbody>
      ${servicesRows}
    </tbody>
    <tfoot>
      <tr class="total-row">
        <td colspan="4" style="text-align:right;padding-right:16px;">TOTAL PRESUPUESTO</td>
        <td style="text-align:right;color:#e94560;">${(variant.totalClient || 0).toLocaleString('es-ES')} &euro;</td>
      </tr>
    </tfoot>
  </table>

  ${fd.objectives ? `<h2>Objetivos</h2><p style="line-height:1.7;color:#444;">${fd.objectives}</p>` : ''}

  <h2>Condiciones</h2>
  <p style="line-height:1.7;color:#444;">
    &bull; Presupuesto v&aacute;lido durante 30 d&iacute;as desde la fecha de emisi&oacute;n.<br>
    &bull; Precios expresados en euros, IVA no incluido.<br>
    &bull; Pago: 50% a la confirmaci&oacute;n, 50% a la finalizaci&oacute;n del evento.<br>
    &bull; Cualquier modificaci&oacute;n sobre el alcance descrito ser&aacute; presupuestada por separado.
  </p>

  <div class="footer">
    <strong>Encom</strong> &mdash; OWN Valencia &middot; Valencia Game City<br>
    contacto@encom.es &bull; encom.es
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
