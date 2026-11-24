import { streamText } from 'ai';
import { openai as aiOpenai } from '@ai-sdk/openai';
import { supabase } from '@/lib/supabase';
import { openai } from '@/lib/clients';

export async function POST(req: Request) {
  const { data: { user } } = await supabase.auth.getUser();
  const { messages } = await req.json();
  const last = messages[messages.length - 1].content;
  const emb = await openai.embeddings.create({ model: 'text-embedding-3-small', input: last });
  await supabase.from('chat_messages').insert({ user_id: user?.id, content: last, embedding: emb.data[0].embedding });
  const result = streamText({ model: aiOpenai('gpt-4o'), messages });
  return result.toDataStreamResponse();
}
