import posthog from 'posthog-js';
import mixpanel from 'mixpanel-browser';
import { hasConsent } from './consent.js';

export function startAnalytics(user) {
  if (hasConsent('analytics')) {
    posthog.init('phc_x', { api_host: 'https://eu.i.posthog.com' });
    posthog.identify(user.id);
  }
}

export function startMixpanel() {
  mixpanel.init('token');
}
