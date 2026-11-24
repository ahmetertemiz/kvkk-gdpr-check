'use client';
import { useForm } from 'react-hook-form';

export default function SignupPage() {
  const { register, handleSubmit } = useForm();
  const onSubmit = async (data) => {
    await fetch('/api/signup', { method: 'POST', body: JSON.stringify(data) });
  };
  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register('fullName')} placeholder="Ad Soyad" />
      <input {...register('email')} type="email" />
      <input {...register('phone')} type="tel" />
      <input {...register('birthDate')} type="date" />
      <input {...register('tckn')} placeholder="TC Kimlik No" />
      <input {...register('password')} type="password" />
      <label><input type="checkbox" {...register('marketing')} defaultChecked /> Kampanyalardan haberdar olmak istiyorum</label>
      <button type="submit">Kayıt ol</button>
    </form>
  );
}
