import { submitTicket } from './actions';

export default function SupportPage() {
  return (
    <form action={submitTicket}>
      <input name="email" type="email" />
      <textarea name="message" />
      <button type="submit">Gönder</button>
    </form>
  );
}
