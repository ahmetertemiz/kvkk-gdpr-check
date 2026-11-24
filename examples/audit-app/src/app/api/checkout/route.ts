import { NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';
import { stripe } from '@/lib/clients';

export async function POST(req: Request) {
  const { data: { user } } = await supabase.auth.getUser();
  const { fullName, email, shippingAddress, amount } = await req.json();
  const customer = await stripe.customers.create({ email, name: fullName, address: { line1: shippingAddress } });
  await supabase.from('orders').insert({ user_id: user?.id, shipping_address: shippingAddress, amount, stripe_customer_id: customer.id });
  return NextResponse.json({ ok: true });
}
