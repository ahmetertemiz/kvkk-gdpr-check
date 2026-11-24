import { createClient } from '@supabase/supabase-js';
import OpenAI from 'openai';

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
);

export const openai = new OpenAI();
