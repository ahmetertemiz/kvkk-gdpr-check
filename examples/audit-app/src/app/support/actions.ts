'use server';
import { supabase } from '@/lib/supabase';

export async function submitTicket(formData: FormData) {
  const email = formData.get('email');
  const message = formData.get('message');
  await supabase.from('support_tickets').insert({ email, message });
}
