/* Tela de senha. Nada daqui revela o conteúdo: tudo está criptografado (AES-256-GCM, chave derivada da senha com PBKDF2). */
(() => {
const M = window.__META, te = new TextEncoder();
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const MIME = { jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", webp: "image/webp", gif: "image/gif", mp4: "video/mp4", mov: "video/mp4", mp3: "audio/mpeg", m4a: "audio/mp4" };
const GZ = p => /\.(js|css|html)$/i.test(p);
let KEY = null;
const urlOf = p => (p.startsWith("audio/") ? M.baseB + "a/" + p.slice(6) : M.baseA + "c/" + p) + ".e" + (GZ(p) ? "?v=" + M.v : "");   // ?v= evita código/dados velhos em cache depois de uma atualização
const decrypt = async buf => new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12) }, KEY, buf.slice(12)));
async function raw(p) { const r = await fetch(urlOf(p)); if (!r.ok) throw new Error(p + " " + r.status); return decrypt(new Uint8Array(await r.arrayBuffer())); }
async function gunzip(u8) { return new Response(new Blob([u8]).stream().pipeThrough(new DecompressionStream("gzip"))).arrayBuffer(); }
async function text(p) { let u = await raw(p); if (GZ(p)) u = new Uint8Array(await gunzip(u)); return new TextDecoder().decode(u); }
const cache = new Map();
function url(p) {
  if (!cache.has(p)) cache.set(p, raw(p).then(u => URL.createObjectURL(new Blob([u], { type: MIME[p.split(".").pop().toLowerCase()] || "application/octet-stream" }))));
  return cache.get(p);
}
async function script(p) { const t = await text(p), s = document.createElement("script"); s.textContent = t; document.head.appendChild(s); }

function watch() {
  const io = new IntersectionObserver(es => es.forEach(e => { if (!e.isIntersecting) return; io.unobserve(e.target); const el = e.target; url(el.dataset.enc).then(u => { el.src = u; }).catch(() => {}); }), { rootMargin: "900px" });
  const add = n => { if (n.nodeType !== 1) return; if (n.dataset && n.dataset.enc && !n.src) io.observe(n); n.querySelectorAll && n.querySelectorAll("[data-enc]").forEach(x => { if (!x.src) io.observe(x); }); };
  new MutationObserver(ms => ms.forEach(m => m.addedNodes.forEach(add))).observe(document.body, { childList: true, subtree: true });
  add(document.body);
}

function pepper() {
  let k = ""; const m = /[#&]k=([\w-]+)/.exec(location.hash); try { if (m) { localStorage.setItem("k", m[1]); history.replaceState(null, "", location.pathname + location.search); } k = localStorage.getItem("k") || ""; } catch (e) { if (m) k = m[1]; }
  return k;
}
async function derive(pw) {
  const k = await crypto.subtle.importKey("raw", te.encode(pw + "\u0000" + pepper()), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(M.salt), iterations: M.iter, hash: "SHA-256" }, k, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}
async function unlock(pw) {
  if (typeof DecompressionStream === "undefined") throw new Error("ios");
  KEY = await derive(pw);
  const c = await (await fetch(M.baseA + "c/check.e?v=" + M.v)).arrayBuffer();
  const ok = new TextDecoder().decode(await decrypt(new Uint8Array(c)));   // lança erro se a senha estiver errada
  if (ok !== "ok") throw new Error("senha");
  window.DEC = { url, text, script };
  const html = await text("app.html");
  const css = (await text("css/style.css")) + "\n" + (await text("css/extra.css"));
  document.getElementById("gatecss").remove();
  const st = document.createElement("style"); st.textContent = css; document.head.appendChild(st);
  document.title = "Nossa história";
  document.body.innerHTML = html;
  watch();
  for (const p of ["data/months.js", "data/stats.js", "data/moments.js", "data/feitos.js", "data/fotos.js", "data/vozes.js", "data/palavras.js", "js/app.js", "js/extra.js", "js/story.js"]) await script(p);
}

const form = document.getElementById("gf"), pw = document.getElementById("gpw"), btn = document.getElementById("gbtn"), err = document.getElementById("gerr");
async function tryPw(v, silent) {
  btn.disabled = true; err.textContent = silent ? "" : "Abrindo…";
  try { await unlock(v); try { sessionStorage.setItem("p", v); } catch (e) {} }
  catch (e) { btn.disabled = false; err.textContent = silent ? "" : (String(e).includes("ios") ? "Seu navegador é antigo. Atualize o iPhone/navegador e tente de novo." : (e && /senha|operation|decrypt/i.test(String(e)) || e.name === "OperationError" ? "Senha incorreta." : "Não consegui abrir. Tente de novo.")); pw.select(); }
}
form.addEventListener("submit", e => { e.preventDefault(); if (!pepper()) { err.textContent = "Abra pelo link completo que foi enviado."; return; } if (pw.value) tryPw(pw.value, false); });
try { const s = sessionStorage.getItem("p"); if (s) tryPw(s, true); } catch (e) {}
})();
