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

// Seed users: if file exists, only ADD missing users (by email). Never overwrite.
let existingUsers = [];
if (fs.existsSync(usersFile)) {
  try { existingUsers = JSON.parse(fs.readFileSync(usersFile, 'utf8')); } catch {}
}

const seedUsers = [
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
  {
    id: uuid(),
    name: 'Demo Captador',
    email: 'captador@encom.es',
    passwordHash: hash('test2026!'),
    role: 'captador',
    createdAt: new Date().toISOString(),
  },
];

// Merge: add only users whose email doesn't exist yet
const existingEmails = new Set(existingUsers.map(u => u.email));
let added = 0;
for (const u of seedUsers) {
  if (!existingEmails.has(u.email)) {
    existingUsers.push(u);
    added++;
    console.log(`   ➕ Nuevo usuario añadido: ${u.email} (${u.role})`);
  }
}
fs.writeFileSync(usersFile, JSON.stringify(existingUsers, null, 2));
if (added === 0 && existingUsers.length > 0) {
  console.log('⏭️  Todos los usuarios ya existían. Datos preservados.');
}
// Only create other files if they don't exist
['sessions.json', 'clients.json', 'proposals.json', 'leads.json'].forEach(f => {
  const fp = path.join(DATA_DIR, f);
  if (!fs.existsSync(fp)) fs.writeFileSync(fp, '[]');
});

console.log('✅ Seed completado:');
console.log('   Admin:      javier@encom.es / admin2025');
console.log('   Vendedores: prada@encom.es, vicente@encom.es, jonfermin@encom.es, araujo@encom.es / test2026!');
console.log('   Captador:   captador@encom.es / test2026!');
