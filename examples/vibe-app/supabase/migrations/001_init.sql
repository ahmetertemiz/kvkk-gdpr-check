create table public.profiles (
  id uuid primary key references auth.users,
  email text,
  phone text,
  tckn text,
  health_notes text
);

create table public.posts (
  id bigint generated always as identity primary key,
  body text
);
alter table public.posts enable row level security;
create policy "anyone" on public.posts for select using (true);
