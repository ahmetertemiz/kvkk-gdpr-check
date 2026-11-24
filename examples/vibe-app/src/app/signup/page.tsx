'use client';
import { supabase } from '../../lib/supabase';

export default function Signup() {
  async function onSubmit(form) {
    const user = { email: form.email, phone: form.phone, tckn: form.tckn };
    console.log('new signup', user.email, user.phone);
    localStorage.setItem('user_profile', JSON.stringify(user));
    await supabase.from('profiles').insert(user);
  }
  return (
    <form onSubmit={onSubmit}>
      <input type="email" name="email" />
      <input type="tel" name="phone" />
      <input name="tckn" placeholder="TC Kimlik No" />
      <input type="password" name="password" />
      <label><input type="checkbox" name="marketing" defaultChecked /> Kampanya e-postalarına izin veriyorum</label>
    </form>
  );
}
