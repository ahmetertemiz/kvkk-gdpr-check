/** Single-page local UI. All dynamic values are inserted with textContent on the client. */

const STR = {
  tr: {
    title: 'KVKK / GDPR Tarayıcı',
    tagline: 'Uygulamanı yayına almadan önce gizlilik risklerini tara. Her şey bu bilgisayarda çalışır.',
    folder: 'Yerel proje klasörü',
    folderPh: 'C:\\projeler\\uygulamam  veya  /home/ben/app',
    url: 'Canlı site URL\'i',
    urlPh: 'https://ornek.com',
    repo: 'Public GitHub repo',
    repoPh: 'https://github.com/kullanici/repo',
    anyCombo: 'En az birini doldur; birden fazlasını birleştirebilirsin.',
    noBrowser: 'Tarayıcısız hafif tarama (daha hızlı, daha az kapsamlı)',
    scan: 'Tara',
    scanning: 'Taranıyor… Canlı site taraması 30-60 sn sürebilir.',
    score: 'Skor',
    download: 'HTML raporu indir',
    newTab: 'Yeni sekmede aç',
    docsTitle: 'Dokümanları üret',
    docsHint: 'BETA — hukuki danışmanlık değildir; taslakları bir hukukçu incelemeden yayımlama. Tarama sonucuna göre aydınlatma metni, çerez politikası, veri envanteri vb. taslaklar üretilir. Bilmediğin alanları boş bırak.',
    company: 'Şirket / kişi adı',
    app: 'Uygulama adı',
    email: 'KVKK iletişim e-postası',
    website: 'Web sitesi',
    address: 'Adres',
    generate: 'Dokümanları üret',
    generating: 'Üretiliyor…',
    files: 'Üretilen dosyalar',
    disclaimer: 'Sezgisel bir risk taramasıdır, hukuki danışmanlık değildir.',
    error: 'Hata',
  },
  en: {
    title: 'KVKK / GDPR Scanner',
    tagline: 'Scan your app for privacy risks before you launch. Everything runs on this computer.',
    folder: 'Local project folder',
    folderPh: '/home/me/my-app',
    url: 'Live site URL',
    urlPh: 'https://example.com',
    repo: 'Public GitHub repo',
    repoPh: 'https://github.com/user/repo',
    anyCombo: 'Fill at least one; you can combine them.',
    noBrowser: 'Lightweight scan without a browser (faster, less thorough)',
    scan: 'Scan',
    scanning: 'Scanning… a live site scan can take 30–60 s.',
    score: 'Score',
    download: 'Download HTML report',
    newTab: 'Open in new tab',
    docsTitle: 'Generate documents',
    docsHint: 'BETA — not legal advice; do not publish before a lawyer has reviewed the drafts. Drafts a privacy notice, cookie policy, data inventory etc. from the scan. Leave unknown fields empty.',
    company: 'Company / person name',
    app: 'App name',
    email: 'Privacy contact email',
    website: 'Website',
    address: 'Address',
    generate: 'Generate documents',
    generating: 'Generating…',
    files: 'Generated files',
    disclaimer: 'Heuristic risk scan, not legal advice.',
    error: 'Error',
  },
};

export function PAGE(defaultLang = 'tr') {
  return `<!doctype html>
<html lang="${defaultLang === 'en' ? 'en' : 'tr'}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kvkk-gdpr-check</title>
<style>
:root{--bg:#f6f7f9;--surface:#fff;--surface2:#f1f3f6;--text:#14171c;--muted:#5d6673;--border:#e2e6eb;--accent:#4f46e5;--accent-text:#fff;--bad:#dc2626;--good:#16a34a;--warn:#d97706;--shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.08);color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0d1014;--surface:#161a20;--surface2:#1d222a;--text:#e8ebf0;--muted:#98a2b0;--border:#2a313b;--accent:#818cf8;--accent-text:#0d1014;--bad:#f87171;--good:#4ade80;--warn:#fbbf24;--shadow:none;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:28px 16px 48px}
header{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.brand{font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
h1{font-size:26px;margin:6px 0 4px;letter-spacing:-.01em}h2{font-size:17px;margin:0 0 6px}
p{margin:0}.muted{color:var(--muted)}.small{font-size:13px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:20px;box-shadow:var(--shadow);margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
label.f{display:flex;flex-direction:column;gap:6px;font-size:13px;font-weight:600}
input[type=text],input[type=url],input[type=email]{width:100%;border:1px solid var(--border);background:var(--surface);color:var(--text);border-radius:9px;padding:10px 12px;font:inherit;font-weight:400}
input:focus{outline:2px solid var(--accent);outline-offset:0;border-color:transparent}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:14px}
.btn{appearance:none;border:1px solid var(--border);background:var(--surface);color:var(--text);border-radius:9px;padding:9px 14px;font:inherit;font-size:14px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:6px}
.btn:hover{background:var(--surface2)}.btn.primary{background:var(--accent);color:var(--accent-text);border-color:var(--accent);font-weight:600}
.btn[disabled]{opacity:.6;cursor:progress}
.seg{display:inline-flex;border:1px solid var(--border);border-radius:9px;overflow:hidden}.seg button{appearance:none;border:0;background:var(--surface);color:var(--muted);padding:6px 12px;font:inherit;font-size:13px;cursor:pointer}.seg button[aria-pressed=true]{background:var(--text);color:var(--bg)}
.check{display:flex;gap:8px;align-items:center;font-size:13px;color:var(--muted)}
.spinner{width:16px;height:16px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
.status{display:flex;gap:10px;align-items:center;color:var(--muted);font-size:14px}
.error{border:1px solid color-mix(in srgb,var(--bad) 40%,transparent);background:color-mix(in srgb,var(--bad) 8%,transparent);color:var(--bad);border-radius:10px;padding:10px 14px;font-size:14px;white-space:pre-wrap}
.warn{border:1px solid color-mix(in srgb,var(--warn) 40%,transparent);background:color-mix(in srgb,var(--warn) 8%,transparent);border-radius:10px;padding:10px 14px;font-size:13.5px;white-space:pre-wrap;margin-bottom:12px}
.result-bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.score{font-size:22px;font-weight:700}
iframe{width:100%;height:78vh;border:1px solid var(--border);border-radius:14px;background:var(--bg)}
.files{list-style:none;padding:0;margin:12px 0 0}.files li{padding:6px 0;border-bottom:1px dashed var(--border)}.files a{color:var(--accent)}
footer{margin-top:24px;color:var(--muted);font-size:12.5px}
[hidden]{display:none!important}
@media (max-width:760px){.grid{grid-template-columns:1fr}h1{font-size:22px}iframe{height:70vh}}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div><div class="brand">🛡️ kvkk-gdpr-check</div><h1 data-t="title"></h1><p class="muted" data-t="tagline"></p></div>
  <div class="seg" role="group" aria-label="Language"><button type="button" data-lang="tr">TR</button><button type="button" data-lang="en">EN</button></div>
</header>

<form class="card" id="scan-form" novalidate>
  <div class="grid">
    <label class="f"><span data-t="folder"></span><input type="text" name="path" autocomplete="off" data-ph="folderPh"></label>
    <label class="f"><span data-t="url"></span><input type="url" name="url" autocomplete="off" data-ph="urlPh"></label>
    <label class="f"><span data-t="repo"></span><input type="url" name="repo" autocomplete="off" data-ph="repoPh"></label>
  </div>
  <p class="muted small" style="margin-top:8px" data-t="anyCombo"></p>
  <div class="row">
    <button class="btn primary" type="submit" id="scan-btn" data-t="scan"></button>
    <label class="check"><input type="checkbox" name="noBrowser"> <span data-t="noBrowser"></span></label>
    <span class="status" id="scan-status" hidden><span class="spinner"></span><span data-t="scanning"></span></span>
  </div>
  <div class="error" id="scan-error" hidden style="margin-top:12px"></div>
</form>

<section id="result" hidden>
  <div id="warnings"></div>
  <div class="result-bar">
    <span class="muted" data-t="score"></span> <span class="score" id="score"></span>
    <a class="btn" id="download" download="kvkk-report.html" data-t="download"></a>
    <a class="btn" id="newtab" target="_blank" rel="noopener" data-t="newTab"></a>
  </div>
  <iframe id="report" title="report" sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox allow-modals"></iframe>

  <form class="card" id="docs-form" style="margin-top:16px" novalidate>
    <h2 data-t="docsTitle"></h2>
    <p class="muted small" data-t="docsHint"></p>
    <div class="grid" style="margin-top:12px">
      <label class="f"><span data-t="company"></span><input type="text" name="companyName"></label>
      <label class="f"><span data-t="app"></span><input type="text" name="appName"></label>
      <label class="f"><span data-t="email"></span><input type="email" name="email"></label>
      <label class="f"><span data-t="website"></span><input type="url" name="website"></label>
      <label class="f" style="grid-column:span 2"><span data-t="address"></span><input type="text" name="address"></label>
    </div>
    <div class="row">
      <button class="btn primary" type="submit" id="docs-btn" data-t="generate"></button>
      <span class="status" id="docs-status" hidden><span class="spinner"></span><span data-t="generating"></span></span>
    </div>
    <div class="error" id="docs-error" hidden style="margin-top:12px"></div>
    <div id="docs-out" hidden><h2 style="margin-top:16px" data-t="files"></h2><ul class="files" id="docs-files"></ul></div>
  </form>
</section>

<footer>⚖️ <span data-t="disclaimer"></span></footer>
</div>
<script>
(function(){
  var STR=${JSON.stringify(STR).replace(/</g, '\\u003c')};
  var lang=${JSON.stringify(defaultLang === 'en' ? 'en' : 'tr')};
  try{var s=localStorage.getItem('kvkk-ui-lang'); if(s==='tr'||s==='en') lang=s;}catch(e){}
  var $=function(s){return document.querySelector(s)}, $$=function(s){return Array.prototype.slice.call(document.querySelectorAll(s))};
  var scanId=null, blobUrl=null;
  function applyLang(){
    document.documentElement.lang=lang;
    $$('[data-t]').forEach(function(el){el.textContent=STR[lang][el.getAttribute('data-t')]||''});
    $$('[data-ph]').forEach(function(el){el.placeholder=STR[lang][el.getAttribute('data-ph')]||''});
    $$('[data-lang]').forEach(function(b){b.setAttribute('aria-pressed',String(b.dataset.lang===lang))});
    document.title='kvkk-gdpr-check · '+STR[lang].title;
  }
  $$('[data-lang]').forEach(function(b){b.addEventListener('click',function(){lang=b.dataset.lang;try{localStorage.setItem('kvkk-ui-lang',lang)}catch(e){}applyLang()})});
  applyLang();

  function post(url,body){
    return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
      .then(function(r){return r.json().then(function(j){if(!r.ok) throw new Error(j.error||r.statusText); return j})});
  }
  function showErr(el,msg){el.textContent=STR[lang].error+': '+msg; el.hidden=false}

  $('#scan-form').addEventListener('submit',function(e){
    e.preventDefault();
    var f=e.target, err=$('#scan-error'), st=$('#scan-status'), btn=$('#scan-btn');
    err.hidden=true; st.hidden=false; btn.disabled=true;
    post('/api/scan',{path:f.path.value,url:f.url.value,repo:f.repo.value,noBrowser:f.noBrowser.checked,lang:lang})
      .then(function(j){
        scanId=j.scanId;
        $('#score').textContent=j.score+'/100';
        $('#score').style.color=j.score>=75?'var(--good)':j.score>=50?'var(--warn)':'var(--bad)';
        var w=$('#warnings'); w.textContent='';
        (j.warnings||[]).forEach(function(m){var d=document.createElement('div');d.className='warn';d.textContent=m;w.appendChild(d)});
        $('#report').srcdoc=j.html;
        if(blobUrl) URL.revokeObjectURL(blobUrl);
        blobUrl=URL.createObjectURL(new Blob([j.html],{type:'text/html'}));
        $('#download').href=blobUrl; $('#newtab').href=blobUrl;
        $('#docs-out').hidden=true; $('#docs-error').hidden=true;
        $('#result').hidden=false;
        $('#result').scrollIntoView({behavior:'smooth',block:'start'});
      })
      .catch(function(x){showErr(err,x.message)})
      .finally(function(){st.hidden=true; btn.disabled=false});
  });

  $('#docs-form').addEventListener('submit',function(e){
    e.preventDefault();
    var f=e.target, err=$('#docs-error'), st=$('#docs-status'), btn=$('#docs-btn');
    err.hidden=true; st.hidden=false; btn.disabled=true;
    var answers={companyName:f.companyName.value,appName:f.appName.value,email:f.email.value,website:f.website.value,address:f.address.value};
    post('/api/docs',{scanId:scanId,answers:answers,lang:lang})
      .then(function(j){
        var ul=$('#docs-files'); ul.textContent='';
        (j.files||[]).forEach(function(file){
          var li=document.createElement('li'), a=document.createElement('a');
          a.href='/api/file?id='+encodeURIComponent(file.id); a.textContent=file.name; a.setAttribute('download','');
          li.appendChild(a); var s=document.createElement('span'); s.className='muted small'; s.textContent='  '+Math.max(1,Math.round(file.size/1024))+' KB'; li.appendChild(s);
          ul.appendChild(li);
        });
        $('#docs-out').hidden=false;
      })
      .catch(function(x){showErr(err,x.message)})
      .finally(function(){st.hidden=true; btn.disabled=false});
  });
})();
</script>
</body>
</html>`;
}
