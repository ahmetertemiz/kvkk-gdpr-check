import OpenAI from 'openai';
const openai = new OpenAI();

export async function ask(user, question) {
  return openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: `Kullanıcı ${user.email}, sağlık durumu: ${user.health_notes}. Soru: ${question}` }],
  });
}
