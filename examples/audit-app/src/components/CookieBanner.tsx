'use client';
export function CookieBanner({ onAccept }) {
  return (
    <div className="cookie-banner">
      Bu site çerez kullanır. <button onClick={onAccept}>Kabul et</button>
    </div>
  );
}
