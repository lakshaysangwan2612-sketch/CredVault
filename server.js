require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { PORT = 3000, MONGO_URI, JWT_SECRET } = process.env;
if (!MONGO_URI || !JWT_SECRET) { console.error('Set MONGO_URI and JWT_SECRET in .env'); process.exit(1); }

/* ---------------- models ---------------- */
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, lowercase: true },
  passwordHash: String,
  role: { type: String, enum: ['student', 'admin'], default: 'student' },
}));

const Credential = mongoose.model('Credential', new mongoose.Schema({
  credId: { type: String, unique: true },
  studentEmail: { type: String, index: true },
  studentName: String,
  title: String,
  issuer: String,
  date: String,
  hash: String,         // SHA-256 of canonical payload
  signature: String,    // Ed25519 signature of the hash (base64)
  isPublic: { type: Boolean, default: true },
  revoked: { type: Boolean, default: false },
}, { timestamps: true }));

/* ---------------- crypto ---------------- */
// Institution key pair. Persisted in Mongo so signatures survive restarts.
const Key = mongoose.model('Key', new mongoose.Schema({ privatePem: String, publicPem: String }));
let keys;
async function loadKeys() {
  let k = await Key.findOne();
  if (!k) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    k = await Key.create({
      privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      publicPem: publicKey.export({ type: 'spki', format: 'pem' }),
    });
  }
  keys = { priv: crypto.createPrivateKey(k.privatePem), pub: crypto.createPublicKey(k.publicPem), publicPem: k.publicPem };
}

// Stable JSON: fixed key order so the same data always hashes the same.
const canonical = (c) => JSON.stringify({ student: c.studentEmail, name: c.studentName, title: c.title, issuer: c.issuer, date: c.date, id: c.credId });
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const sign = (hashHex) => crypto.sign(null, Buffer.from(hashHex, 'hex'), keys.priv).toString('base64');
const verifySig = (hashHex, sig) => crypto.verify(null, Buffer.from(hashHex, 'hex'), keys.pub, Buffer.from(sig, 'base64'));

async function issue({ studentEmail, studentName, title, issuer, date }) {
  const c = { credId: 'CV-' + crypto.randomBytes(5).toString('hex').toUpperCase(), studentEmail: studentEmail.toLowerCase(), studentName, title, issuer, date };
  c.hash = sha256(canonical(c));
  c.signature = sign(c.hash);
  return Credential.create(c);
}

// Recompute everything from stored fields: this is what makes tampering detectable.
function check(c) {
  const hashOk = sha256(canonical(c)) === c.hash;
  const sigOk = hashOk && verifySig(c.hash, c.signature);
  return { integrity: hashOk, signature: sigOk, revoked: c.revoked, valid: hashOk && sigOk && !c.revoked };
}
const publicView = (c) => ({ credId: c.credId, studentName: c.studentName, title: c.title, issuer: c.issuer, date: c.date, hash: c.hash, revoked: c.revoked });

/* ---------------- auth ---------------- */
const tokenFor = (u) => jwt.sign({ id: u._id, role: u.role, email: u.email, name: u.name }, JWT_SECRET, { expiresIn: '7d' });
const auth = (role) => (req, res, next) => {
  try {
    req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET);
    if (role && req.user.role !== role) return res.status(403).json({ error: 'Forbidden' });
    next();
  } catch { res.status(401).json({ error: 'Please sign in' }); }
};
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.error(e); res.status(500).json({ error: 'Server error' }); });

/* ---------------- app ---------------- */
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

app.post('/api/auth/register', wrap(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 6) return res.status(400).json({ error: 'Name, email and a 6+ char password are required' });
  if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ error: 'Email already registered' });
  const u = await User.create({ name, email, passwordHash: await bcrypt.hash(password, 10) }); // self-signup is always a student
  res.json({ token: tokenFor(u), user: { name: u.name, email: u.email, role: u.role } });
}));

app.post('/api/auth/login', wrap(async (req, res) => {
  const u = await User.findOne({ email: (req.body.email || '').toLowerCase() });
  if (!u || !(await bcrypt.compare(req.body.password || '', u.passwordHash))) return res.status(401).json({ error: 'Wrong email or password' });
  res.json({ token: tokenFor(u), user: { name: u.name, email: u.email, role: u.role } });
}));

// Student: own wallet
app.get('/api/wallet', auth('student'), wrap(async (req, res) => {
  const list = await Credential.find({ studentEmail: req.user.email }).sort('-createdAt');
  res.json(list.map((c) => ({ ...publicView(c), isPublic: c.isPublic, status: check(c) })));
}));
app.patch('/api/wallet/:id/visibility', auth('student'), wrap(async (req, res) => {
  const c = await Credential.findOneAndUpdate({ credId: req.params.id, studentEmail: req.user.email }, { isPublic: !!req.body.isPublic }, { new: true });
  c ? res.json({ isPublic: c.isPublic }) : res.status(404).json({ error: 'Not found' });
}));

// Admin: issue single / bulk (CSV text: studentEmail,studentName,title,issuer,date), revoke, list
app.post('/api/admin/issue', auth('admin'), wrap(async (req, res) => {
  const { studentEmail, studentName, title, issuer, date } = req.body;
  if (!studentEmail || !title) return res.status(400).json({ error: 'studentEmail and title are required' });
  res.json(publicView(await issue({ studentEmail, studentName: studentName || '', title, issuer: issuer || 'CredVault Institute of Technology', date: date || new Date().toISOString().slice(0, 10) })));
}));
app.post('/api/admin/bulk', auth('admin'), wrap(async (req, res) => {
  const rows = String(req.body.csv || '').split('\n').map((l) => l.trim()).filter(Boolean);
  if (rows[0] && /email/i.test(rows[0])) rows.shift(); // skip header
  const out = [];
  for (const r of rows) {
    const [studentEmail, studentName, title, issuer, date] = r.split(',').map((s) => s.trim());
    if (studentEmail && title) out.push(publicView(await issue({ studentEmail, studentName, title, issuer: issuer || 'CredVault Institute of Technology', date: date || new Date().toISOString().slice(0, 10) })));
  }
  res.json({ issued: out.length, credentials: out });
}));
app.get('/api/admin/credentials', auth('admin'), wrap(async (req, res) => res.json((await Credential.find().sort('-createdAt').limit(200)).map(publicView))));
app.post('/api/admin/revoke/:id', auth('admin'), wrap(async (req, res) => {
  const c = await Credential.findOneAndUpdate({ credId: req.params.id }, { revoked: !!(req.body.revoked ?? true) }, { new: true });
  c ? res.json({ revoked: c.revoked }) : res.status(404).json({ error: 'Not found' });
}));

// Public: recruiter verification + portfolio + institution key
app.get('/api/verify/:idOrHash', wrap(async (req, res) => {
  const q = req.params.idOrHash.trim();
  const c = await Credential.findOne({ $or: [{ credId: q.toUpperCase() }, { hash: q.toLowerCase() }] });
  if (!c) return res.status(404).json({ error: 'No credential found for that ID or hash' });
  res.json({ credential: publicView(c), result: check(c) });
}));
app.get('/api/portfolio/:email', wrap(async (req, res) => {
  const list = await Credential.find({ studentEmail: req.params.email.toLowerCase(), isPublic: true, revoked: false });
  res.json(list.map((c) => ({ ...publicView(c), valid: check(c).valid })));
}));
app.get('/api/public-key', (req, res) => res.type('text/plain').send(keys.publicPem));

/* ---------------- boot ---------------- */
async function seed() {
  if (await User.countDocuments()) return;
  const mk = (name, email, role) => User.create({ name, email, role, passwordHash: bcrypt.hashSync('demo1234', 10) });
  await mk('Demo Student', 'student@credvault.edu', 'student');
  await mk('Demo Admin', 'admin@credvault.edu', 'admin');
  await issue({ studentEmail: 'student@credvault.edu', studentName: 'Demo Student', title: 'Smart India Hackathon 2025 — National Winner', issuer: 'Ministry of Education · SIH', date: '2025-08-19' });
  console.log('Seeded demo accounts (password: demo1234)');
}

mongoose.connect(MONGO_URI).then(loadKeys).then(seed).then(() => app.listen(PORT, () => console.log(`CredVault on http://localhost:${PORT}`)))
  .catch((e) => { console.error('Startup failed:', e.message); process.exit(1); });
