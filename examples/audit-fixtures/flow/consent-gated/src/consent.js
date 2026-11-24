export function hasConsent(category) {
  try {
    return JSON.parse(localStorage.getItem('cookie-consent') || '{}')[category] === true;
  } catch {
    return false;
  }
}
