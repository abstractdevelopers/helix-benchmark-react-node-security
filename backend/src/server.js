import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { randomUUID } from 'node:crypto';
import rateLimit from 'express-rate-limit';
import { db } from './db.js';

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';

// Fix: restrict CORS to configured origin
app.use(cors({ origin: process.env.CLIENT_ORIGIN || 'http://localhost:5173', credentials: true }));

app.use(express.json());

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace('Bearer ', '');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// Rate limiter for login endpoint
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  await db.read();
  const existing = db.data.users.find((u) => u.email === email);
  if (existing) return res.status(409).json({ error: 'User exists' });
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = {
    id: randomUUID(),
    email,
    password: hashedPassword,
    role: 'user',
    createdAt: new Date().toISOString(),
  };
  db.data.users.push(user);
  await db.write();
  const token = jwt.sign({ id: user.id, email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
  res.status(201).json({ token, user: { id: user.id, email, role: user.role } });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  await db.read();
  const user = db.data.users.find((u) => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id: user.id, email, role: user.role } });
});

app.get('/api/users', auth, requireAdmin, async (req, res) => {
  await db.read();
  res.json(db.data.users);
});

app.get('/api/notes', auth, async (req, res) => {
  await db.read();
  const notes = db.data.notes.filter((n) => n.userId === req.user.id);
  res.json(notes);
});

// Fixed: IDOR - check ownership
app.get('/api/notes/:id', auth, async (req, res) => {
  await db.read();
  const note = db.data.notes.find((n) => n.id === req.params.id);
  if (!note) return res.status(404).json({ error: 'Not found' });
  if (note.userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  res.json(note);
});

// Fixed: safe search - no eval, only returns current user's notes
app.get('/api/notes/search', auth, async (req, res) => {
  const { q } = req.query;
  await db.read();
  if (typeof q !== 'string' || !q) {
    return res.status(400).json({ error: 'Missing search query' });
  }
  const notes = db.data.notes.filter(
    (n) =>
      n.userId === req.user.id &&
      (n.title.toLowerCase().includes(q.toLowerCase()) || n.content.toLowerCase().includes(q.toLowerCase()))
  );
  res.json(notes);
});

app.post('/api/notes', auth, async (req, res) => {
  const { title, content } = req.body;
  await db.read();
  const note = { id: randomUUID(), userId: req.user.id, title, content, createdAt: new Date().toISOString() };
  db.data.notes.push(note);
  await db.write();
  res.status(201).json(note);
});

app.put('/api/notes/:id', auth, async (req, res) => {
  await db.read();
  const note = db.data.notes.find((n) => n.id === req.params.id);
  if (!note) return res.status(404).json({ error: 'Not found' });
  if (note.userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  const { title, content } = req.body;
  note.title = title ?? note.title;
  note.content = content ?? note.content;
  await db.write();
  res.json(note);
});

app.delete('/api/notes/:id', auth, async (req, res) => {
  await db.read();
  const idx = db.data.notes.findIndex((n) => n.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  if (db.data.notes[idx].userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  db.data.notes.splice(idx, 1);
  await db.write();
  res.status(204).end();
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
}

export { app };
