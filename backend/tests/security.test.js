import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';

describe('security fixes', () => {
  let app;

  beforeEach(async () => {
    process.env.NODE_ENV = 'test';
    process.env.JWT_SECRET = 'a-very-long-random-secret-for-tests-only-do-not-use-in-production';
    process.env.CLIENT_ORIGIN = 'http://localhost:5173';

    const { db } = await import('../src/db.js');
    await db.read();
    db.data = { users: [], notes: [] };
    await db.write();

    const mod = await import('../src/server.js');
    app = mod.app;
  });

  async function registerAndLogin(email, password, role) {
    const register = await request(app)
      .post('/api/auth/register')
      .send({ email, password, role });
    expect(register.status).toBe(201);
    return register.body.token;
  }

  it('rejects forged tokens signed with the weak default secret', async () => {
    const forged = jwt.sign({ id: '1', email: 'attacker@test.com', role: 'admin' }, 'secret');
    const res = await request(app)
      .get('/api/users')
      .set('Authorization', `Bearer ${forged}`);
    expect(res.status).toBe(401);
  });

  it('does not allow privilege escalation through registration', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'admin@test.com', password: 'password123', role: 'admin' });
    expect(res.status).toBe(201);
    expect(res.body.user.role).not.toBe('admin');
  });

  it('stores passwords hashed, not plaintext', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'hash@test.com', password: 'password123' });
    const { db } = await import('../src/db.js');
    const user = db.data.users.find((u) => u.email === 'hash@test.com');
    expect(user.password).not.toBe('password123');
    expect(user.password.startsWith('$2')).toBe(true);
  });

  it('prevents reading notes owned by another user (IDOR)', async () => {
    const tokenA = await registerAndLogin('a@test.com', 'password123');
    const create = await request(app)
      .post('/api/notes')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ title: 'Secret', content: 'Do not share' });
    expect(create.status).toBe(201);

    const tokenB = await registerAndLogin('b@test.com', 'password123');
    const res = await request(app)
      .get(`/api/notes/${create.body.id}`)
      .set('Authorization', `Bearer ${tokenB}`);
    expect(res.status).toBe(403);
  });

  it('prevents updating notes owned by another user', async () => {
    const tokenA = await registerAndLogin('a2@test.com', 'password123');
    const create = await request(app)
      .post('/api/notes')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ title: 'Mine', content: 'Keep' });

    const tokenB = await registerAndLogin('b2@test.com', 'password123');
    const res = await request(app)
      .put(`/api/notes/${create.body.id}`)
      .set('Authorization', `Bearer ${tokenB}`)
      .send({ title: 'Hacked', content: 'Pwned' });
    expect(res.status).toBe(403);
  });

  it('prevents deleting notes owned by another user', async () => {
    const tokenA = await registerAndLogin('a3@test.com', 'password123');
    const create = await request(app)
      .post('/api/notes')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ title: 'Mine', content: 'Keep' });

    const tokenB = await registerAndLogin('b3@test.com', 'password123');
    const res = await request(app)
      .delete(`/api/notes/${create.body.id}`)
      .set('Authorization', `Bearer ${tokenB}`);
    expect(res.status).toBe(403);
  });

  it('restricts CORS to the configured client origin', async () => {
    const res = await request(app)
      .options('/api/auth/login')
      .set('Origin', 'https://evil.com')
      .set('Access-Control-Request-Method', 'POST');
    expect(res.headers['access-control-allow-origin']).not.toBe('*');
    expect(res.headers['access-control-allow-origin']).not.toBe('https://evil.com');
  });

  it('validates search input and does not leak other users notes', async () => {
    const tokenA = await registerAndLogin('search-a@test.com', 'password123');
    await request(app)
      .post('/api/notes')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ title: 'Apple', content: 'Red' });

    const tokenB = await registerAndLogin('search-b@test.com', 'password123');
    const malicious = await request(app)
      .get('/api/notes/search?q=true')
      .set('Authorization', `Bearer ${tokenB}`);
    const leaked = Array.isArray(malicious.body) && malicious.body.some((n) => n.title === 'Apple');
    expect(leaked).toBe(false);
  });

  it('rate-limits login attempts', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'rate@test.com', password: 'password123' });

    let blocked = false;
    for (let i = 0; i < 20; i++) {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'rate@test.com', password: 'wrong' });
      if (res.status === 429) {
        blocked = true;
        break;
      }
    }
    expect(blocked).toBe(true);
  });
});
