import { NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';
import { supabaseAdmin } from '@/lib/supabase-admin';
import { resend } from '@/lib/clients';

export async function POST(req: Request) {
  const { email, password, fullName, phone, birthDate, tckn, marketing } = await req.json();
  const { data } = await supabase.auth.signUp({ email, password });
  await supabaseAdmin.from('profiles').insert({
    id: data.user!.id,
    email,
    full_name: fullName,
    phone,
    birth_date: birthDate,
    tckn,
    marketing_opt_in: marketing,
  });
  console.log('new signup', email, phone);
  await resend.emails.send({ from: 'hi@app.com', to: email, subject: 'Hoş geldin', html: `<p>Merhaba ${fullName}</p>` });
  return NextResponse.json({ ok: true });
}
