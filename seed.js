/**
 * EncomVentas — Seed script
 * Creates initial admin user and sample vendedor
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function hash(pw) { return crypto.createHash('sha256').update(pw).digest('hex'); }
function uuid() { return crypto.randomUUID(); }

// Users
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
    name: 'Laura Martínez',
    email: 'laura@encom.es',
    passwordHash: hash('ventas2025'),
    role: 'vendedor',
    createdAt: new Date().toISOString(),
  },
  {
    id: uuid(),
    name: 'Carlos Ruiz',
    email: 'carlos@encom.es',
    passwordHash: hash('ventas2025'),
    role: 'vendedor',
    createdAt: new Date().toISOString(),
  },
];

fs.writeFileSync(path.join(DATA_DIR, 'users.json'), JSON.stringify(users, null, 2));
fs.writeFileSync(path.join(DATA_DIR, 'sessions.json'), '[]');
fs.writeFileSync(path.join(DATA_DIR, 'clients.json'), '[]');
fs.writeFileSync(path.join(DATA_DIR, 'proposals.json'), '[]');

console.log('✅ Seed completado:');
console.log(`   Admin: javier@encom.es / admin2025`);
console.log(`   Vendedores: laura@encom.es, carlos@encom.es / ventas2025`);
