export default function RootLayout({ children }) {
  return (
    <html lang="tr">
      <head>
        <link href="https://fonts.googleapis.com/css2?family=Inter&display=swap" rel="stylesheet" />
        <script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script>
        <script dangerouslySetInnerHTML={{ __html: `
          gtag('consent', 'default', { analytics_storage: 'granted' });
          gtag('config', 'G-XXXX');
        `}} />
      </head>
      <body>{children}</body>
    </html>
  );
}
