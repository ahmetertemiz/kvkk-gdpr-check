'use client';
import posthog from 'posthog-js';
import { useEffect } from 'react';

export function Analytics({ user }) {
  useEffect(() => {
    posthog.init(process.env.NEXT_PUBLIC_POSTHOG_KEY!, { api_host: 'https://us.i.posthog.com' });
    if (user) posthog.identify(user.id, { email: user.email, phone: user.phone });
  }, [user]);
  return null;
}
