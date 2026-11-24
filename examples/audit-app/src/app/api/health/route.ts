import { NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase-admin';
import { openai } from '@/lib/clients';

export async function POST(req: Request) {
  const { userId, symptoms, notes } = await req.json();
  await supabaseAdmin.from('health_logs').insert({ user_id: userId, symptoms, notes });
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: `Belirtiler: ${symptoms}. Notlar: ${notes}. Ne önerirsin?` }],
  });
  return NextResponse.json({ advice: completion.choices[0].message.content });
}
