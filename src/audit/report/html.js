import { pendingTop, S, L, SEVS, grade, scoreView, coverageNote, coverageNotes, transferFlag, catLabel, dataCatLabel, groupFindings, locWhere, getModel, viewFinding, summaryFindings, isLowConfidence, findingLowConfidence, deletionState, deletionStateLabel, deletionReason, DEL_MARK, dpiaView, usedState, viewResult, layerRows, stackLabels, transferKindLabel, deletionHeader, deletionRowTag, calibrationText, hasCalibration, reviewSummaryText, reviewGroups, reviewRateText, reviewLabel, reviewSuppressedText, NAMED_VENDORS_T } from './common.js';
import { reasonTexts } from '../../score-gate.js';
import { displayRoot } from '../../display-root.js';
import { supportNotice } from '../../support-notice.js';
import { basisNote } from '../../data/legal-basis.js';
import { CONTROLLER_QUESTIONS } from '../legal/knowledge.js';
import { ORG_STATUS, ORG_TEXT } from '../legal/org.js';
import { buildDataMap } from './datamap.js';
import { rulePrecision, precisionText } from '../../precision-note.js';
import { SEVERITY_BASIS_NOTE } from '../../severity-cap.js';

/** Inventory card: vendors named in the code with no traced data flow. */
function namedVendorsCard(m, lang) {
  if (!m.namedVendors?.length) return '';
  const N = NAMED_VENDORS_T[lang] || NAMED_VENDORS_T.tr;
  const items = m.namedVendors.map((v) => `<li><b>${esc(v.vendor)}</b>${v.country ? ` (${esc(v.country)})` : ''} <code>${esc(locWhere(v.evidence[0] || {}))}</code></li>`).join('');
  return `<div class="card"><h2>${esc(N.title)}</h2><p class="small muted">${esc(N.note)}</p><ul>${items}</ul></div>`;
}

/** Measured precision of the finding's rule (real-project set and 84-project set), and the capped level if any. */
function precisionP(f, lang) {
  const raw = f.severityRaw || f.locations.find((l) => l.severityRaw && (l.severity || f.severity) === f.severity)?.severityRaw;
  const cap = raw ? ` · ${esc(SEVERITY_BASIS_NOTE.capped[lang])} (${esc(lang === 'en' ? 'original level' : 'özgün önem')}: ${esc(raw)})` : '';
  return `<p class="refs">${esc(lang === 'en' ? 'Precision' : 'İsabet')}: ${esc(precisionText(rulePrecision('audit', f.rule.id), lang))}${cap}</p>`;
}

export function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const LS = String.fromCharCode(0x2028);
const PS = String.fromCharCode(0x2029);
const json = (x) => JSON.stringify(x).replace(/</g, '\\u003c').split(LS).join('\\u2028').split(PS).join('\\u2029');

const CSS = `
:root{--bg:#f6f7f9;--card:#fff;--fg:#14171c;--muted:#5d6572;--line:#e3e6eb;--accent:#2f6fed;
--crit:#b3261e;--high:#d9480f;--med:#c88a04;--low:#1c7ed6;--info:#6c757d;--ok:#2b8a3e;--special:#c0392b;--specialbg:#fde8e6;--chip:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e8eaee;--muted:#9aa3b0;--line:#2a2f39;--accent:#6c9dff;--chip:#222733;--specialbg:#3a1d1b}}
*{box-sizing:border-box}html,body{margin:0}body{background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:24px 16px 48px}
header.top{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap;margin-bottom:16px}
.brand{font-size:12px;color:var(--muted);letter-spacing:.04em}h1{margin:4px 0 2px;font-size:24px}h2{font-size:17px;margin:0 0 12px}h3{font-size:14px;margin:16px 0 8px}
.meta{color:var(--muted);font-size:13px}.meta span{margin-right:14px}
.btn{border:1px solid var(--line);background:var(--card);color:var(--fg);padding:7px 12px;border-radius:8px;cursor:pointer;font:inherit}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px;min-width:0}
.grid{display:grid;gap:14px}.g3{grid-template-columns:260px 1fr 300px}@media(max-width:900px){.g3{grid-template-columns:1fr}}
.gauge{display:flex;flex-direction:column;align-items:center;gap:6px}.gauge svg{width:170px;height:170px}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}@media(max-width:560px){.tiles{grid-template-columns:repeat(3,1fr)}}
.tile{border-radius:10px;padding:10px;text-align:center;background:var(--chip)}.tile b{display:block;font-size:22px}.tile small{font-size:11px;color:var(--muted)}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low{color:var(--low)}.sev-info{color:var(--info)}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 7px;border-radius:999px;color:#fff;vertical-align:middle}
.b-critical{background:var(--crit)}.b-high{background:var(--high)}.b-medium{background:var(--med)}.b-low{background:var(--low)}.b-info{background:var(--info)}
nav.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 14px}.tab{border:1px solid var(--line);background:var(--card);color:var(--fg);padding:8px 12px;border-radius:999px;cursor:pointer;font:inherit}
.tab[aria-selected=true]{background:var(--accent);border-color:var(--accent);color:#fff}
ul.top{margin:0;padding-left:18px}ul.top li{margin:4px 0}
.heat{display:grid;grid-template-columns:auto repeat(3,1fr);gap:4px;font-size:12px}.heat div{padding:8px;border-radius:6px;text-align:center}
.heat .h{background:none;color:var(--muted)}.heat .c{font-weight:700;color:#fff}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;font-size:12px}
.tablewrap{overflow-x:auto}.muted{color:var(--muted)}.small{font-size:12px}
.special{color:var(--special);font-weight:600}.ok{color:var(--ok);font-weight:700}.bad{color:var(--crit);font-weight:700}
details.f{border:1px solid var(--line);border-radius:10px;margin-bottom:10px;background:var(--card)}details.f>summary{cursor:pointer;padding:12px 14px;list-style:none;display:flex;gap:10px;align-items:center}
details.f>summary::-webkit-details-marker{display:none}details.f .body{padding:0 14px 14px}details.f .id{color:var(--muted);font-size:12px;margin-left:auto;white-space:nowrap}
.loc{border-left:3px solid var(--line);padding:6px 10px;margin:8px 0;background:var(--chip);border-radius:0 8px 8px 0}.loc .w{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--muted)}
.chain{font-size:12px;margin-top:3px}.chain b{color:var(--accent)}code{font-family:ui-monospace,Consolas,monospace;font-size:12px;background:var(--chip);padding:1px 4px;border-radius:4px;word-break:break-all}
.steps{margin:4px 0 0;padding-left:16px;font-size:12px;color:var(--muted)}
.refs{font-size:12px;color:var(--muted)}.catttl{margin:18px 0 8px;font-size:15px}
.mapwrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}#map{display:block}
#map .node rect{fill:var(--chip);stroke:var(--line)}#map .node.special rect{fill:var(--specialbg);stroke:var(--special)}#map .node.abroad rect{stroke:var(--med)}#map .node.unknown rect{stroke:var(--med);stroke-dasharray:4 3}
.lowc{display:inline-block;font-size:11px;padding:1px 6px;border-radius:999px;border:1px dashed var(--med);color:var(--med);margin-left:6px}.soft{color:var(--med);font-weight:700}.covnotes{margin:0 0 14px;padding-left:18px;font-size:12px;color:var(--muted)}
.warnbox{border:1px solid var(--med);border-left-width:4px;background:var(--chip);border-radius:10px;padding:10px 14px;margin-bottom:14px}.warnbox b{color:var(--med)}
#map .node text{fill:var(--fg);font-size:12px}#map .node text.sub{fill:var(--muted);font-size:10px}#map .node{cursor:pointer}
#map path{fill:none;stroke:var(--muted);stroke-opacity:.45;stroke-width:1.3}#map path.special{stroke:var(--special);stroke-opacity:.8;stroke-width:2}
#map .dim{opacity:.12}#map .hl rect{stroke:var(--accent);stroke-width:2}#map path.hl{stroke:var(--accent);stroke-opacity:1;stroke-width:2.2}
#map .colttl{fill:var(--muted);font-size:12px;font-weight:600}
footer{color:var(--muted);font-size:12px;margin-top:24px;border-top:1px solid var(--line);padding-top:12px}
@media print{nav.tabs,.btn{display:none}.panel{display:block!important}details.f{break-inside:avoid}details.f .body{display:block}body{background:#fff}}
`;

const JS = `
(function(){
var tabs=document.querySelectorAll('.tab'),panels=document.querySelectorAll('.panel');
tabs.forEach(function(t){t.addEventListener('click',function(){tabs.forEach(function(x){x.setAttribute('aria-selected',x===t?'true':'false')});panels.forEach(function(p){p.hidden=p.dataset.panel!==t.dataset.tab});if(t.dataset.tab==='map')draw();});});
var pb=document.getElementById('print');if(pb)pb.addEventListener('click',function(){document.querySelectorAll('details.f').forEach(function(d){d.open=true});window.print();});
var M=JSON.parse(document.getElementById('mapdata').textContent),drawn=false;
function draw(){if(drawn)return;drawn=true;var svg=document.getElementById('map');if(!svg)return;var NS='http://www.w3.org/2000/svg';
var CW=220,GAP=110,NH=36,NG=10,TOP=34,PAD=12;var pos={};var maxRows=Math.max(1,Math.max.apply(null,M.columns.map(function(c){return c.length})));
var W=PAD*2+4*CW+3*GAP,H=TOP+maxRows*(NH+NG)+PAD;svg.setAttribute('viewBox','0 0 '+W+' '+H);svg.setAttribute('width',W);svg.setAttribute('height',H);
var gl=document.createElementNS(NS,'g'),gn=document.createElementNS(NS,'g');svg.appendChild(gl);svg.appendChild(gn);
M.titles.forEach(function(tt,i){var t=document.createElementNS(NS,'text');t.setAttribute('x',PAD+i*(CW+GAP));t.setAttribute('y',18);t.setAttribute('class','colttl');t.textContent=tt+' ('+M.columns[i].length+')';gn.appendChild(t);});
M.columns.forEach(function(col,ci){var off=(maxRows-col.length)*(NH+NG)/2;col.forEach(function(n,ri){var x=PAD+ci*(CW+GAP),y=TOP+off+ri*(NH+NG);pos[n.id]={x:x,y:y};
var g=document.createElementNS(NS,'g');g.setAttribute('class','node'+(n.special?' special':'')+(n.abroad?' abroad':'')+(n.locationUnknown?' unknown':''));g.dataset.id=n.id;
var r=document.createElementNS(NS,'rect');r.setAttribute('x',x);r.setAttribute('y',y);r.setAttribute('width',CW);r.setAttribute('height',NH);r.setAttribute('rx',7);g.appendChild(r);
var t=document.createElementNS(NS,'text');t.setAttribute('x',x+9);t.setAttribute('y',y+(n.sub?15:22));t.textContent=(n.label.length>30?n.label.slice(0,29)+'…':n.label);g.appendChild(t);
if(n.sub){var s=document.createElementNS(NS,'text');s.setAttribute('x',x+9);s.setAttribute('y',y+29);s.setAttribute('class','sub');s.textContent=n.sub.slice(0,38);g.appendChild(s);}
var ti=document.createElementNS(NS,'title');ti.textContent=n.label+(n.sub?' — '+n.sub:'');g.appendChild(ti);
g.addEventListener('click',function(e){e.stopPropagation();focus(n.id)});gn.appendChild(g);});});
M.links.forEach(function(l){var a=pos[l.from],b=pos[l.to];if(!a||!b)return;var x1=a.x+CW,y1=a.y+NH/2,x2=b.x,y2=b.y+NH/2,mx=(x1+x2)/2;
var p=document.createElementNS(NS,'path');p.setAttribute('d','M'+x1+','+y1+' C'+mx+','+y1+' '+mx+','+y2+' '+x2+','+y2);if(l.special)p.setAttribute('class','special');p.dataset.from=l.from;p.dataset.to=l.to;gl.appendChild(p);});
svg.addEventListener('click',function(){focus(null)});}
function focus(id){var svg=document.getElementById('map');var nodes=svg.querySelectorAll('.node'),paths=svg.querySelectorAll('path');
if(!id){nodes.forEach(function(n){n.classList.remove('dim','hl')});paths.forEach(function(p){p.classList.remove('dim','hl')});return;}
var data=M.columns[1].map(function(n){return n.id});var keep={};keep[id]=1;var seeds=[id];
if(data.indexOf(id)<0){M.links.forEach(function(l){if(l.from===id&&data.indexOf(l.to)>=0)seeds.push(l.to);if(l.to===id&&data.indexOf(l.from)>=0)seeds.push(l.from);});}
var on={};seeds.forEach(function(s){keep[s]=1;M.links.forEach(function(l){if(l.from===s||l.to===s){keep[l.from]=1;keep[l.to]=1;on[l.from+'>'+l.to]=1;}});});
nodes.forEach(function(n){var k=keep[n.dataset.id];n.classList.toggle('dim',!k);n.classList.toggle('hl',n.dataset.id===id)});
paths.forEach(function(p){var k=on[p.dataset.from+'>'+p.dataset.to];p.classList.toggle('dim',!k);p.classList.toggle('hl',!!k)});}
})();
`;

function gauge(score, t) {
  const r = 70;
  if (typeof score !== 'number') {
    return `<div class="gauge"><svg viewBox="0 0 170 170" role="img" aria-label="${esc(t.score)} ${esc(t.scoreNA)}"><circle cx="85" cy="85" r="${r}" fill="none" stroke="var(--chip)" stroke-width="14" stroke-dasharray="6 6"/><text x="85" y="86" text-anchor="middle" font-size="34" font-weight="700" fill="currentColor">${esc(t.scoreNA)}</text><text x="85" y="112" text-anchor="middle" font-size="12" fill="currentColor" opacity=".65">${esc(t.scoreNAHint)}</text></svg><b>${esc(t.score)}</b></div>`;
  }
  const cfull = 2 * Math.PI * r;
  const col = score >= 75 ? 'var(--ok)' : score >= 50 ? 'var(--med)' : 'var(--crit)';
  return `<div class="gauge"><svg viewBox="0 0 170 170" role="img" aria-label="${esc(t.score)} ${score}/100"><circle cx="85" cy="85" r="${r}" fill="none" stroke="var(--chip)" stroke-width="14"/><circle cx="85" cy="85" r="${r}" fill="none" stroke="${col}" stroke-width="14" stroke-linecap="round" stroke-dasharray="${(cfull * score) / 100} ${cfull}" transform="rotate(-90 85 85)"/><text x="85" y="86" text-anchor="middle" font-size="38" font-weight="700" fill="currentColor">${score}</text><text x="85" y="112" text-anchor="middle" font-size="13" fill="currentColor" opacity=".65">/100 · ${grade(score)}</text></svg><b>${esc(t.score)}</b></div>`;
}

function trCell(r, t) {
  const f = transferFlag(r);
  if (f === 'abroad') return '<span class="bad">✓</span>';
  if (f === 'tr') return '— <span class="small muted">(TR)</span>';
  if (f === 'self') return `— <span class="small muted">(${esc(t.selfHosted)})</span>`;
  return `<span class="sev-medium">?</span> <span class="small muted">${esc(t.locUnknown)}</span>`;
}

function heatmap(findings, t) {
  const cells = {};
  for (const f of findings) for (const l of f.locations) if (l.risk) cells[`${l.risk.likelihood}-${l.risk.impact}`] = (cells[`${l.risk.likelihood}-${l.risk.impact}`] || 0) + 1;
  const colorFor = (p) => (p >= 9 ? 'var(--crit)' : p >= 6 ? 'var(--high)' : p >= 3 ? 'var(--med)' : 'var(--low)');
  let h = `<div class="heat"><div class="h"></div><div class="h">${esc(t.sens.normal)}</div><div class="h">${esc(t.sens.high)}</div><div class="h">${esc(t.sens.special)}</div>`;
  const rowsL = ['3', '2', '1'];
  const rowLabel = { 3: '●●●', 2: '●●', 1: '●' };
  for (const li of rowsL) {
    h += `<div class="h">${rowLabel[li]}</div>`;
    for (const im of [1, 2, 3]) {
      const n = cells[`${li}-${im}`] || 0;
      h += `<div class="c" style="background:${colorFor(li * im)};opacity:${n ? 1 : 0.18}">${n || ''}</div>`;
    }
  }
  return `${h}</div><p class="small muted">↑ ${esc(t.likelihood)} · → ${esc(t.impact)}</p>`;
}

function locHtml(l, t, lang, lowF = false) {
  const w = locWhere(l);
  const steps = (l.steps || []).filter((s) => s.file || s.note).slice(0, 6);
  const conf = typeof l.confidence === 'number' ? `${esc(t.confidence)} ${Math.round(l.confidence * 100)}%` : '';
  const cal = calibrationText(l, t, lang);
  return `<div class="loc">${l.severity && t.sev[l.severity] ? `<span class="badge b-${esc(l.severity)}">${esc(t.sev[l.severity])}</span> ` : ''}${esc(L(l.label, lang))}${isLowConfidence(l) && !lowF ? `<span class="lowc">${esc(t.lowConf)}</span>` : ''}
${w ? `<div class="w">${esc(w)}</div>` : ''}${l.snippet ? `<div><code>${esc(l.snippet)}</code></div>` : ''}
${l.chain ? `<div class="chain"><b>${esc(t.chain)}:</b> ${esc(l.chain)}</div>` : ''}
${steps.length ? `<ul class="steps">${steps.map((s) => `<li>${s.file ? `<span class="w">${esc(s.file)}${s.line ? ':' + esc(s.line) : ''}</span> ` : ''}${s.snippet ? `<code>${esc(s.snippet)}</code>` : esc(s.note || '')}</li>`).join('')}</ul>` : ''}
${l.risk?.explain || conf ? `<div class="small muted">${[l.risk?.explain ? esc(L(l.risk.explain, lang)) : '', conf].filter(Boolean).join(' · ')}</div>` : ''}${cal ? `<div class="small muted cal"><b>${esc(t.calLbl)}:</b> ${esc(cal)}</div>` : ''}</div>`;
}

/** Organisational audit card: answers are user input and are escaped like everything else. */
function orgHtml(org, lang) {
  if (!org?.provided) return '';
  const cls = { action: 'bad', open: 'sev-medium', ok: 'muted', na: 'muted' };
  return `<div class="card"><h2>${esc(L(ORG_TEXT.title, lang))} (${org.answered}/${org.total})</h2><p class="muted">${esc(L(ORG_TEXT.hint, lang))}</p>${org.dpia.changed ? `<p class="bad">● ${esc(L(ORG_TEXT.dpiaChanged, lang))}</p>` : ''}<ul>${org.items.map((x) => `<li><b class="${cls[x.status]}">${esc(L(ORG_STATUS[x.status], lang))}</b> ${esc(L(x.title, lang))}<br><span class="small muted">${esc(L(x.detail, lang))} (${esc(x.refs.join(', '))})${basisNote(x, lang) ? ` ⚠ ${esc(basisNote(x, lang))}` : ''}</span></li>`).join('')}</ul></div>`;
}

export function auditHtml(result, { lang = 'tr' } = {}) {
  result = viewResult(result);
  const t = S[lang];
  const m = getModel(result, lang);
  const map = buildDataMap(result.graph, lang);
  const c = result.counts || {};
  const date = new Date().toISOString().slice(0, 10);

  const tiles = SEVS.map((s) => `<div class="tile"><b class="sev-${s}">${c[s] || 0}</b><small>${esc(t.sev[s])}</small></div>`).join('');
  const sum = summaryFindings(result.findings, 8);
  const pend = pendingTop(result);
  const pendHtml = pend.items.length ? `<h3>${esc(t.pendingTop)}</h3><ul>${pend.items.map(({ f, l, sev }) => `<li><b>${esc(t.sev[sev] || sev)}</b> ${esc(f.rule.id)}${l.file ? ` <code>${esc(`${l.file}:${l.line ?? ''}`)}</code>` : ''} ${esc(L(l.label, lang))}</li>`).join('')}${pend.total > pend.items.length ? `<li class="muted">${esc(t.pendingMore(pend.total - pend.items.length))}</li>` : ''}</ul>` : '';
  const topHtml = sum.mode === 'none' ? `<p class="muted">✅ ${esc(t.noFindings)}</p>` : `${sum.mode === 'lower' ? `<p class="small muted">${esc(t.noTopRisks(sum.items.length))}</p>` : ''}<ul class="top">${sum.items.map((f) => `<li><span class="badge b-${esc(f.severity)}">${esc(t.sev[f.severity] || f.severity)}</span> <b>${esc(L(f.rule.title, lang))}</b>${findingLowConfidence(f) ? `<span class="lowc">${esc(t.lowConf)}</span>` : ''}<div class="small muted">${esc(L(f.locations?.[0]?.label, lang))}</div></li>`).join('')}</ul>`;

  const findingsHtml = groupFindings(result.findings).map(([cat, list]) => `<h3 class="catttl">${esc(catLabel(cat, lang))}</h3>${list.map(viewFinding).map((f, i) => `
<details class="f"${['critical', 'high'].includes(f.severity) && i < 3 ? ' open' : ''}><summary><span class="badge b-${esc(f.severity)}">${esc(t.sev[f.severity])}</span><b>${esc(L(f.rule.title, lang))}</b>${findingLowConfidence(f) ? `<span class="lowc">${esc(t.lowConfFinding)}</span>` : ''}<span class="id">${esc(f.rule.id)} · ${f.locations.length}</span></summary>
<div class="body">${precisionP(f, lang)}${f.locations.slice(0, 30).map((l) => locHtml(l, t, lang, findingLowConfidence(f))).join('')}
<p><b>${esc(t.why)}:</b> ${esc(L(f.rule.desc, lang))}</p><p><b>${esc(t.fix)}:</b> ${esc(L(f.rule.fix, lang))}</p><p class="refs">${esc(t.refs)}: ${esc((f.rule.refs || []).join(' · '))}</p>${basisNote(f.rule, lang) ? `<p class="refs">⚠ ${esc(basisNote(f.rule, lang))}</p>` : ''}</div></details>`).join('')}`).join('') || `<div class="card">✅ ${esc(t.noFindings)}</div>`;

  const inv = `<div class="tablewrap"><table><thead><tr><th>${esc(t.element)}</th><th>${esc(t.category)}</th><th>${esc(t.sensitivity)}</th><th>${esc(t.sources)}</th><th>${esc(t.stores)}</th><th>${esc(t.sinks)}</th><th>${esc(t.used)}</th></tr></thead><tbody>${m.inventory.map((e) => `<tr><td><b${e.sensitivity === 'special' ? ' class="special"' : ''}>${esc(L(e.label, lang))}</b></td><td>${esc(dataCatLabel(e.category, lang))}</td><td>${esc(t.sens[e.sensitivity] || e.sensitivity)}</td><td>${esc(e.sources.join(', ') || '—')}</td><td>${esc(e.stores.join(', ') || '—')}</td><td>${esc(e.sinks.join(', ') || '—')}</td><td>${usedState(e) === 'yes' ? '<span class="ok">✓</span>' : usedState(e) === 'no' ? `<span class="sev-medium" title="${esc(t.unusedNotDetected)}">⚠</span> <span class="small muted">${esc(t.unusedNotDetected)}</span>` : '?'}</td></tr>`).join('')}</tbody></table></div>`;

  const ropa = `<div class="tablewrap"><table><thead><tr><th>${esc(t.purpose)}</th><th>${esc(t.legalBasis)}</th><th>${esc(t.data)}</th><th>${esc(t.recipients)}</th><th>${esc(t.retention)}</th><th>${esc(t.transfer)}</th></tr></thead><tbody>${m.activities.map((a) => `<tr><td><b>${esc(L(a.purpose, lang))}</b><div class="small muted">${esc(L(a.rationale, lang))}</div></td><td>${a.legalBasis.map((b) => `${esc(L(b.label, lang))}<div class="small muted">${esc(b.kvkk)} · ${esc(b.gdpr)}</div>`).join('')}</td><td>${esc(a.elements.join(', ') || '—')}</td><td>${esc(a.recipients.join(', ') || '—')}</td><td>${a.retention === 'found' ? '<span class="ok">✓</span>' : a.retention === 'missing' ? '<span class="bad">✗</span>' : '—'}</td><td>${a.transferAbroad ? '<span class="bad">✓</span>' : '—'}</td></tr>`).join('') || `<tr><td colspan="6" class="muted">—</td></tr>`}</tbody></table></div>`;

  const transfers = `<div class="tablewrap"><table><thead><tr><th>${esc(t.vendor)}</th><th>${esc(t.country)}</th><th>${esc(t.abroad)}</th><th>${esc(t.third)}</th><th>${esc(t.data)}</th></tr></thead><tbody>${m.transfers.map((r) => `<tr><td><b>${esc(r.vendor)}</b>${transferKindLabel(r, t) ? `<div class="small muted">${esc(transferKindLabel(r, t))}</div>` : ''}</td><td>${esc(r.country)}</td><td>${trCell(r, t)}</td><td>${r.thirdCountryGdpr === true ? '✓' : r.thirdCountryGdpr === false ? '—' : '?'}</td><td${r.special ? ' class="special"' : ''}>${esc(r.elements.map((e) => L(e.label, lang) || e.name).join(', '))}</td></tr>`).join('') || `<tr><td colspan="5" class="muted">—</td></tr>`}</tbody></table></div>`;

  const dh = deletionHeader(m.deletionMatrix, t, lang);
  const deletion = `${dh.state === 'ok' ? '' : dh.state === 'unanalysed' ? `<p class="sev-medium">? ${esc(dh.text)}</p>` : `<p class="bad">✗ ${esc(dh.text)}</p>`}<div class="tablewrap"><table><thead><tr><th>${esc(t.target)}</th><th>${esc(t.data)}</th><th>${esc(t.covered)}</th><th>${esc(t.reason)}</th></tr></thead><tbody>${m.deletionMatrix.rows.map((r) => `<tr><td><b>${esc(r.label)}</b>${deletionRowTag(r, t) ? ` <span class="small muted">(${esc(deletionRowTag(r, t))})</span>` : ''}</td><td>${esc((r.elements || []).join(', '))}</td><td>${((st) => st === 'yes' ? '<span class="ok">✓</span>' : st === 'na' ? '–' : st === 'no' ? '<span class="bad">✗</span>' : `<span class="soft">${DEL_MARK[st]}</span> <span class="small muted">${esc(deletionStateLabel(st, t))}</span>`)(deletionState(r))}</td><td>${esc(deletionReason(r, t, lang))}</td></tr>`).join('') || `<tr><td colspan="4" class="muted">—</td></tr>`}</tbody></table></div>`;

  const dv = dpiaView(m.dpia, t, lang);
  const dpia = `<p class="${dv.state === 'required' ? 'bad' : dv.state === 'below' ? 'sev-medium' : 'muted'}">${dv.state === 'required' ? '● ' : ''}${esc(dv.head)}</p>${dv.labels.length ? `<ul>${dv.labels.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}`;
  const meta = [result.root ? `<span>${esc(t.project)}: <b>${esc(displayRoot(result.root))}</b></span>` : '', result.url ? `<span>${esc(t.site)}: <b>${esc(result.url)}</b></span>` : '', `<span>${esc(t.date)}: ${date}</span>`, `<span>${esc(result.filesScanned || 0)} ${esc(t.files)}</span>`].join('');
  const sv = scoreView(result);
  const cov = coverageNote(result, t);
  const warns = result.warnings || [];
  const notes = coverageNotes(result, t, m);
  const notice = supportNotice(result, lang);
  const banner = (notice ? `<div class="warnbox" role="alert"><b>⚠ ${esc(notice.text)}</b></div>` : '') + (cov ? `<div class="warnbox" role="alert"><b>⚠ ${esc(cov)}</b></div>` : '') + (notes.length ? `<ul class="covnotes" aria-label="${esc(t.coverageNotes)}">${notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>` : '');
  const lr = layerRows(result, t);
  const stl = stackLabels(result);
  const layerCls = (r) => (r.kind === 'found' ? 'ok' : r.kind === 'none' ? 'muted' : 'sev-medium');
  const layerMark = (r) => (r.kind === 'found' ? '✓' : r.kind === 'none' ? '–' : '⚠');
  const layersHtml = lr.length
    ? `<div class="card"><h2>${esc(t.layers)}</h2>${stl.length ? `<p class="small muted">${esc(t.stackLbl)}: ${esc(stl.join(', '))}</p>` : ''}<div class="tablewrap"><table><thead><tr><th>${esc(t.layerCol)}</th><th>${esc(t.layerStatus)}</th><th>${esc(t.layerCount)}</th><th>${esc(t.layerGaps)}</th></tr></thead><tbody>${lr.map((r) => `<tr><td>${esc(r.name)}</td><td class="${layerCls(r)}">${layerMark(r)} ${esc(r.label)}</td><td>${esc(r.countText ?? '—')}</td><td class="small">${esc(r.gaps.join(', ') || '—')}</td></tr>`).join('')}</tbody></table></div></div>`
    : '';
  const reviewLoc = (l) => locHtml({ ...l, label: reviewLabel(l, t, lang) }, t, lang, true) + (reviewRateText(l, t) ? `<p class="small muted rrate">≈ ${esc(reviewRateText(l, t))}</p>` : '') + (l.reviewReason ? `<p class="small"><b>${esc(t.reviewWhy)}:</b> ${esc(L(l.reviewReason, lang))}</p>` : '');
  const reviewHtml = result.review.length
    ? `<h3 class="catttl">${esc(t.review)}</h3><p class="small muted">${esc(t.reviewHint)}</p>${reviewSummaryText(result, t) ? `<p class="small"><b>${result.review.reduce((n, f) => n + f.locations.length, 0)}:</b> ${esc(reviewSummaryText(result, t))}</p>` : ''}${reviewGroups(result, t).map((g) => `${g.band ? `<h4 class="rband rband-${g.band}">${esc(g.label)} (${g.count})</h4>` : ''}${g.entries.map((f) => `<details class="f"><summary><span class="lowc">?</span><b>${esc(L(f.rule.title, lang))}</b><span class="id">${esc(f.rule.id)} · ${f.locations.length}</span></summary><div class="body">${f.locations.map(reviewLoc).join('')}${basisNote(f.rule, lang) ? `<p class="refs">⚠ ${esc(basisNote(f.rule, lang))}</p>` : ''}</div></details>`).join('')}`).join('')}`
    : '';
  const supTxt = reviewSuppressedText(result, t, lang);
  const suppressedHtml = supTxt ? `<p class="small muted">${esc(supTxt)}</p>` : '';
  const warnHtml = warns.length ? `<div class="card"><h2>${esc(t.warnings)}</h2><ul class="small">${warns.map((w) => `<li>${esc(w)}</li>`).join('')}</ul></div>` : '';
  const mapData = { columns: map.columns, links: map.links, titles: [t.colSources, t.colData, t.colStores, t.colSinks] };

  return `<!doctype html>
<html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>${esc(t.title)}</title><style>${CSS}</style></head>
<body><div class="wrap">
<header class="top"><div><div class="brand">🛡️ kvkk-gdpr-check · audit</div><h1>${esc(t.title)}</h1><div class="meta">${meta}</div></div><button type="button" class="btn" id="print">${esc(t.print)}</button></header>
<nav class="tabs" role="tablist">${Object.entries(t.tabs).map(([k, v], i) => `<button type="button" class="tab" role="tab" data-tab="${k}" aria-selected="${i === 0}">${esc(v)}${k === 'findings' ? ` (${result.findings.length})` : ''}</button>`).join('')}</nav>

<section class="panel" data-panel="overview">${banner}
<div class="grid g3"><div class="card">${gauge(sv.score, t)}${reasonTexts(result, lang).map((x) => `<p class="small muted">${esc(t.scoreWhy)}: ${esc(x)}</p>`).join('')}</div>
<div class="card"><h2>${esc(t.summary)}</h2><div class="tiles">${tiles}</div><h3>${esc(t.topRisks)}</h3>${topHtml}${pendHtml}</div>
<div class="card"><h2>${esc(t.heatmap)}</h2>${heatmap(result.findings, t)}<h3>${esc(t.dpia)}</h3>${dpia}</div></div>
${layersHtml}<div class="card"><h2>${esc(t.inventory)} (${m.inventory.length})</h2><p class="small muted">${esc(lang === 'en' ? 'What is listed is mostly right, but the list is not complete: data or recipients may be missing.' : 'Listelenenler büyük oranda doğrudur, ama liste tam değildir: eksik veri ya da alıcı olabilir.')}</p>${inv}</div>${warnHtml}
</section>

<section class="panel" data-panel="map" hidden><div class="card"><h2>${esc(t.datamap)}</h2><p class="small muted">${esc(t.datamapHint)}</p><div class="mapwrap"><svg id="map" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${esc(t.datamap)}"></svg></div></div></section>

<section class="panel" data-panel="findings" hidden>${hasCalibration(result) ? `<p class="small muted calnote">${esc(t.calNote)}</p>` : ''}${findingsHtml}${reviewHtml}${suppressedHtml}</section>

<section class="panel" data-panel="ropa" hidden><div class="card"><h2>${esc(t.activities)}</h2>${ropa}</div><div class="card"><h2>${esc(t.transfers)}</h2>${transfers}</div>${namedVendorsCard(m, lang)}</section>

<section class="panel" data-panel="deletion" hidden><div class="card"><h2>${esc(t.deletion)}</h2>${deletion}</div></section>

<section class="panel" data-panel="questions" hidden><div class="card"><h2>${esc(t.questions)}</h2><p class="muted">${esc(t.questionsHint)}</p><ol>${(result.organization?.provided ? result.organization.unanswered : CONTROLLER_QUESTIONS).map((q) => `<li>${esc(L(q, lang))}</li>`).join('')}</ol><p class="small muted">${esc(L(ORG_TEXT.how, lang))}</p></div>${orgHtml(result.organization, lang)}</section>

<footer>⚖️ ${esc(t.disclaimer)}<br>${esc(t.generated)} · ${date}</footer>
</div>
<script type="application/json" id="mapdata">${json(mapData)}</script>
<script>${JS}</script>
</body></html>
`;
}
