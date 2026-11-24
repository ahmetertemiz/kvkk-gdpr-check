import express from 'express';
import bcrypt from 'bcrypt';
import { prisma } from './db.js';
import { notifyUser } from './notify.js';

const app = express();
app.use(express.json());

app.post('/register', async (req, res) => {
  const { email, password, phone } = req.body;
  const passwordHash = await bcrypt.hash(password, 12);
  const user = await prisma.user.create({ data: { email, passwordHash, phone } });
  await notifyUser(email, phone);
  res.json({ id: user.id });
});

app.get('/me', requireAuth, async (req, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.user.id }, select: { email: true, phone: true } });
  res.json(me);
});

app.delete('/me', requireAuth, async (req, res) => {
  await prisma.user.delete({ where: { id: req.user.id } });
  res.json({ ok: true });
});

function requireAuth(req, res, next) {
  next();
}

app.listen(3000);
