-- Profiles: one row per auth user
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  email text not null,
  phone text,
  birth_date date,
  tckn text,
  avatar_url text,
  marketing_opt_in boolean default true,
  created_at timestamptz default now()
);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for all using (auth.uid() = id) with check (auth.uid() = id);

-- Health diary (special category data)
create table public.health_logs (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  symptoms text,
  mood int,
  notes text,
  created_at timestamptz default now()
);
alter table public.health_logs enable row level security;
create policy "read all logs" on public.health_logs for select using (true);

-- Orders
create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid references public.profiles(id),
  shipping_address text,
  amount numeric,
  stripe_customer_id text,
  created_at timestamptz default now()
);

-- Support tickets (no link to the user)
create table public.support_tickets (
  id bigint generated always as identity primary key,
  email text,
  message text,
  created_at timestamptz default now()
);
alter table public.support_tickets enable row level security;

-- AI chat history with embeddings
create table public.chat_messages (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users(id) on delete cascade,
  content text,
  embedding vector(1536),
  created_at timestamptz default now()
);
alter table public.chat_messages enable row level security;
create policy "own messages" on public.chat_messages for select using (auth.uid() = user_id);

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
