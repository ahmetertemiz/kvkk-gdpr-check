Fixture pages for the live scanner tests (`test/live.test.js`).
Serve this folder with any static server; the tests use a tiny Node server that also
adds `Set-Cookie` headers for `/bad/*` pages.

- `bad/`  — static third parties, no privacy link, pre-ticked marketing box
- `js/`   — local-only page whose JS sets tracking cookies and shows an Accept-only banner (browser mode)
- `good/` — privacy + cookie policy links, consent-managed scripts, full privacy notice
