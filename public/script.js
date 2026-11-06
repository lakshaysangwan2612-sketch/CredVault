
const $ = (q) => document.querySelector(q);
const home = $('#home'), signin = $('#signin'), appEl = $('#app'), view = $('#view');
let session = JSON.parse(localStorage.getItem('cv') || 'null');
const esc = (t) => String(t ?? '').replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

async function api(path, method = 'GET', body) {
  const r = await fetch('/api' + path, { method, headers: { 'Content-Type': 'application/json', ...(session ? { Authorization: 'Bearer ' + session.token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || 'Request failed');
  return d;
}

/* ---------- router ---------- */
function show(which){ home.style.display = which==='home'?'block':'none'; signin.style.display = which==='signin'?'block':'none'; appEl.style.display = which==='app'?'block':'none'; }
async function route(){
  const h = location.hash;
  if (h === '#signin') return show(session ? (location.hash = '#dash', 'app') : 'signin');
  if (h === '#dash' || h === '#verify-page') {
    if (h === '#dash' && !session) return location.hash = '#signin';
    show('app'); $('#who').textContent = session ? session.user.name + ' · ' + session.user.role : '';
    return h === '#dash' ? (session.user.role === 'admin' ? adminView() : studentView()) : verifyView();
  }
  show('home');
}
addEventListener('hashchange', route); route();
$('#logout').onclick = () => { localStorage.removeItem('cv'); session = null; location.hash = ''; };

/* ---------- landing: live verify of a real credential ---------- */
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
$('#runBtn').onclick = async () => {
  const c1=$('#c1'), c2=$('#c2'), out=$('#result');
  [c1,c2].forEach((c)=>c.className='check'); out.textContent='';
  c1.classList.add('run'); await wait(500);
  try {
    // Landing page demo uses the seeded demo credential via the public portfolio endpoint
    const list = await api('/portfolio/student@credvault.edu');
    if (!list.length) throw new Error('no demo credential');
    const v = await api('/verify/' + list[0].credId);
    $('#hash').textContent = 'sha256 ' + v.credential.hash.slice(0, 24) + '…';
    c1.className = 'check ' + (v.result.integrity ? 'ok' : '');
    c2.classList.add('run'); await wait(500);
    c2.className = 'check ' + (v.result.signature ? 'ok' : '');
    out.textContent = v.result.valid ? '✓ Credential verified · not revoked' : '✗ Verification failed';
  } catch (e) { c1.className='check'; out.textContent = 'Backend not reachable: ' + e.message; }
};

/* ---------- sign in / up ---------- */
let mode = 'in';
document.querySelectorAll('.tabs button').forEach((b) => b.onclick = () => {
  mode = b.dataset.t;
  document.querySelectorAll('.tabs button').forEach((x) => x.classList.toggle('on', x === b));
  $('#submit').textContent = mode === 'in' ? '🛡 Sign in' : '🛡 Create account';
});
async function auth(path, body){
  const msg = $('#msg'); msg.style.color = ''; msg.textContent = '…';
  try { session = await api(path, 'POST', body); localStorage.setItem('cv', JSON.stringify(session)); location.hash = '#dash'; route(); }
  catch (e) { msg.style.color = '#ff6b6b'; msg.textContent = e.message; }
}
$('#form').onsubmit = (e) => {
  e.preventDefault();
  const email = $('#email').value, password = $('#pw').value;
  mode === 'in' ? auth('/auth/login', { email, password }) : auth('/auth/register', { name: email.split('@')[0], email, password });
};
document.querySelectorAll('[data-demo]').forEach((b) => b.onclick = () => auth('/auth/login', { email: b.dataset.demo + '@credvault.edu', password: 'demo1234' }));

/* ---------- student wallet ---------- */
async function studentView(){
  view.innerHTML = '<h2>My wallet</h2><p class="sub">Your institution-signed credentials. Public ones appear on your portfolio link.</p><div id="list">Loading…</div>';
  const list = await api('/wallet');
  const link = location.origin + '/#portfolio=' + session.user.email;
  $('#list').innerHTML = `<p class="sub">Portfolio link: <a style="color:var(--cyan)" href="${esc(link)}" target="_blank">${esc(link)}</a></p>` + (list.map((c) => `
    <div class="row"><div><h3>${esc(c.title)}</h3><small>${esc(c.issuer)} · ${esc(c.date)} · ${esc(c.credId)}</small><br>
      <small class="${c.status.valid ? 'good' : 'bad'}">${c.status.valid ? '✓ verified' : c.revoked ? '✗ revoked' : '✗ failed'}</small></div>
      <button class="btn btn-g btn-sm" data-vis="${esc(c.credId)}" data-pub="${c.isPublic}">${c.isPublic ? 'Public' : 'Private'}</button></div>`).join('') || 'No credentials yet.');
  document.querySelectorAll('[data-vis]').forEach((b) => b.onclick = async () => { await api(`/wallet/${b.dataset.vis}/visibility`, 'PATCH', { isPublic: b.dataset.pub !== 'true' }); studentView(); });
}

/* ---------- admin ---------- */
async function adminView(){
  view.innerHTML = `<h2>Issue credentials</h2><p class="sub">Signed with the institution Ed25519 key.</p>
    <div class="f2"><div><label>Student email</label><input id="ie"></div><div><label>Student name</label><input id="in"></div>
    <div><label>Title</label><input id="it"></div><div><label>Date</label><input id="id" type="date"></div></div>
    <button class="btn btn-p" style="margin:14px 0" id="issue">Issue</button>
    <label>Bulk CSV (email,name,title,issuer,date)</label><textarea id="csv"></textarea>
    <button class="btn btn-g" style="margin:10px 0 24px" id="bulk">Bulk issue</button><div id="am" class="sub"></div>
    <h2 style="font-size:18px;margin-bottom:12px">Recent credentials</h2><div id="all"></div>`;
  const load = async () => {
    const all = await api('/admin/credentials');
    $('#all').innerHTML = all.map((c) => `<div class="row"><div><h3>${esc(c.title)}</h3><small>${esc(c.studentName)} · ${esc(c.credId)}</small></div>
      <button class="btn btn-g btn-sm" data-rev="${esc(c.credId)}" data-r="${c.revoked}">${c.revoked ? 'Un-revoke' : 'Revoke'}</button></div>`).join('') || 'None yet.';
    document.querySelectorAll('[data-rev]').forEach((b) => b.onclick = async () => { await api('/admin/revoke/' + b.dataset.rev, 'POST', { revoked: b.dataset.r !== 'true' }); load(); });
  };
  const say = (t, bad) => { $('#am').style.color = bad ? '#ff6b6b' : 'var(--green)'; $('#am').textContent = t; };
  $('#issue').onclick = async () => { try { const c = await api('/admin/issue', 'POST', { studentEmail: $('#ie').value, studentName: $('#in').value, title: $('#it').value, date: $('#id').value }); say('Issued ' + c.credId); load(); } catch (e) { say(e.message, 1); } };
  $('#bulk').onclick = async () => { try { const r = await api('/admin/bulk', 'POST', { csv: $('#csv').value }); say('Issued ' + r.issued + ' credentials'); load(); } catch (e) { say(e.message, 1); } };
  load();
}

/* ---------- recruiter verification ---------- */
function verifyView(){
  view.innerHTML = `<h2>Verify a credential</h2><p class="sub">Paste a credential ID (CV-XXXXXXXXXX) or its SHA-256 hash.</p>
    <input id="vq" placeholder="CV-…"><button class="btn btn-p" style="margin:14px 0" id="vgo">⌗ Verify</button><div id="vout"></div>`;
  $('#vgo').onclick = async () => {
    try {
      const { credential: c, result: r } = await api('/verify/' + encodeURIComponent($('#vq').value));
      const t = (ok) => `<span class="${ok ? 'good' : 'bad'}">${ok ? '✓ pass' : '✗ fail'}</span>`;
      $('#vout').innerHTML = `<div class="row" style="display:block"><h3>${esc(c.title)}</h3><small>${esc(c.studentName)} · ${esc(c.issuer)} · ${esc(c.date)}</small>
        <p style="margin-top:12px;font-size:13px">SHA-256 integrity: ${t(r.integrity)}<br>Ed25519 signature: ${t(r.signature)}<br>Not revoked: ${t(!r.revoked)}</p>
        <h3 class="${r.valid ? 'good' : 'bad'}" style="margin-top:8px">${r.valid ? 'VALID CREDENTIAL' : 'NOT VALID'}</h3></div>`;
    } catch (e) { $('#vout').innerHTML = `<p class="bad">${esc(e.message)}</p>`; }
  };
}

/* ---------- public portfolio: /#portfolio=email ---------- */
if (location.hash.startsWith('#portfolio=')) {
  const email = decodeURIComponent(location.hash.slice(11));
  show('app'); $('#who').textContent = 'Public portfolio';
  api('/portfolio/' + encodeURIComponent(email)).then((l) => view.innerHTML = `<h2>${esc(email)}</h2><p class="sub">Verified public credentials</p>` +
    (l.map((c) => `<div class="row"><div><h3>${esc(c.title)}</h3><small>${esc(c.issuer)} · ${esc(c.date)} · ${esc(c.credId)}</small></div><span class="${c.valid ? 'good' : 'bad'}">${c.valid ? '✓ verified' : '✗'}</span></div>`).join('') || 'Nothing public yet.'));
}