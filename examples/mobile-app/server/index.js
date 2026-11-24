import express from 'express';
import { Resend } from 'resend';
const app = express();
const DATABASE_URL = "postgres://app_user:Xk9pQ2mZ7vL4@db.prod.internal:5432/app";
const resend = new Resend(process.env.RESEND_KEY);

app.post('/newsletter', async (req, res) => {
  console.log('signup', req.body);
  await resend.broadcasts.send({ audienceId: 'aud', subject: 'Kampanya!' });
  res.json({ ok: true });
});
