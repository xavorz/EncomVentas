/**
 * EncomVentas — Seed script (safe: no overwrite if data exists)
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function hash(pw) { return crypto.createHash('sha256').update(pw).digest('hex'); }
function uuid() { return crypto.randomUUID(); }

const usersFile = path.join(DATA_DIR, 'users.json');

// Only seed if users.json doesn't exist or is empty
if (fs.existsSync(usersFile)) {
  try {
    const existing = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
    if (existing.length > 0) {
      console.log('⏭️  Seed omitido: ya existen usuarios. Datos preservados.');
      process.exit(0);
    }
  } catch {}
}

const users = [
  {
    id: uuid(),
    name: 'Javi',
    email: 'javier@encom.es',
    passwordHash: hash('admin2025'),
    role: 'admin',
    createdAt: new Date().toISOString(),
  },
  {
    id: uuid(),
    name: 'Prada',
    email: 'prada@encom.es',
    passwordHash: hash('test2026!'),
    role: 'vendedor',
    createdAt: new Date().toISOString(),
  },
  {
    id: uuid(),
    name: 'Vicente',
    email: 'vicente@encom.es',
    passwordHash: hash('test2026!'),
    role: 'vendedor',
    createdAt: new Date().toISOString(),
  },
  {
    id: uuid(),
    name: 'Jon Fermín',
    email: 'jonfermin@encom.es',
    passwordHash: hash('test2026!'),
    role: 'vendedor',
    createdAt: new Date().toISOString(),
  },
  {
    id: uuid(),
    name: 'Araujo',
    email: 'araujo@encom.es',
    passwordHash: hash('test2026!'),
    role: 'vendedor',
    createdAt: new Date().toISOString(),
  },
];

fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
// Only create other files if they don't exist
['sessions.json', 'clients.json', 'proposals.json'].forEach(f => {
  const fp = path.join(DATA_DIR, f);
  if (!fs.existsSync(fp)) fs.writeFileSync(fp, '[]');
});

console.log('✅ Seed completado:');
console.log('   Admin:      javier@encom.es / admin2025');
console.log('   Vendedores: prada@encom.es, vicente@encom.es, jonfermin@encom.es, araujo@encom.es / test2026!');
