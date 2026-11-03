// Headless-Chrome check of the actual page: serves the repo root, drives index.html
// over CDP (no puppeteer), feeds it an APK through the file input, and asserts the
// four panels rendered. Also takes a screenshot for eyeballing.
//
//   node browser_check.mjs APK [screenshot.png]
//
// Needs google-chrome on PATH and node ≥ 22 (global WebSocket).
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { argv } from "node:process";

const ROOT = resolve(new URL("..", import.meta.url).pathname);
const APK = resolve(argv[2]);
const SHOT = argv[3];
const base = APK.split("/").pop().replace(/\.apk$/, "");
const MIME = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm", ".png": "image/png" };

const server = createServer(async (req, res) => {
  const p = join(ROOT, decodeURIComponent(req.url.split("?")[0]).replace(/^\/$/, "/index.html"));
  try { const b = await readFile(p); res.writeHead(200, { "content-type": MIME[extname(p)] || "application/octet-stream" }); res.end(b); }
  catch { res.writeHead(404); res.end(); }
}).listen(0);
const port = server.address().port;

const chrome = spawn("google-chrome", ["--headless=new", "--remote-debugging-port=0", "--no-first-run", "--no-sandbox", "--window-size=1400,1000", "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
const wsUrl = await new Promise((res, rej) => {
  let buf = ""; chrome.stderr.on("data", d => { buf += d; const m = buf.match(/DevTools listening on (ws:\/\/\S+)/); if (m) res(m[1]); });
  setTimeout(() => rej(new Error("chrome did not start")), 15000);
});
const ws = new WebSocket(wsUrl);
await new Promise(r => ws.onopen = r);
let id = 0; const waiting = new Map(); const events = [];
ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); } else events.push(m); };
const send = (method, params = {}, sessionId) => new Promise(r => { const i = ++id; waiting.set(i, r); ws.send(JSON.stringify({ id: i, method, params, sessionId })); });

const { result: { targetId } } = await send("Target.createTarget", { url: "about:blank" });
const { result: { sessionId } } = await send("Target.attachToTarget", { targetId, flatten: true });
const S = (m, p) => send(m, p, sessionId);
await S("Runtime.enable"); await S("Log.enable"); await S("DOM.enable");
const consoleErrors = [];
ws.addEventListener("message", e => { const m = JSON.parse(e.data); if (m.method === "Runtime.exceptionThrown") consoleErrors.push(m.params.exceptionDetails.text + " " + (m.params.exceptionDetails.exception?.description || "")); if (m.method === "Log.entryAdded" && m.params.entry.level === "error") consoleErrors.push(m.params.entry.text); });
const evalJs = async (expr) => { const r = await S("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true }); if (r.result.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails)); return r.result.result.value; };
// Page.navigate returns before the new document exists, so an early poll can still see
// about:blank (#status === null → TypeError). Treat a throwing poll as "not yet".
const waitFor = async (expr, ms = 30000) => {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    try { if (await evalJs(expr)) return; } catch (_) { /* document not ready yet */ }
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error("timeout waiting for " + expr);
};

let failures = 0;
const fail = (m) => { failures++; console.log("  FAIL:", m); };
try {
  await S("Page.enable");
  await S("Page.navigate", { url: `http://127.0.0.1:${port}/index.html` });
  await waitFor(`document.querySelector("#status").textContent.includes("engine ready")`);
  console.log("engine ready in page");
  const { result: { root } } = await S("DOM.getDocument");
  const { result: { nodeId } } = await S("DOM.querySelector", { nodeId: root.nodeId, selector: "#file" });
  await S("DOM.setFileInputFiles", { files: [APK], nodeId });
  await waitFor(`document.querySelector("#app").classList.contains("on") || document.querySelector("#status").textContent.includes("failed")`);
  const st = await evalJs(`document.querySelector("#status").textContent`);
  console.log("status:", st);
  if (st.includes("failed")) fail("load failed");
  const state = await evalJs(`JSON.stringify({
    pills: document.querySelector("#fpills").textContent.trim(),
    gateRows: document.querySelectorAll("#gate-table tbody tr").length,
    gateChecks: document.querySelectorAll("#gate-checks li").length,
    verdict: document.querySelector("#gate-verdict").textContent.replace(/\\s+/g," ").slice(0,160),
    contentRows: document.querySelectorAll("#content-table tbody tr").length,
    contentChecks: document.querySelectorAll("#content-checks li").length,
    tamperRows: document.querySelectorAll("#tamper-table tbody tr").length,
    tamperChecks: document.querySelectorAll("#tamper-checks li").length,
    findings: document.querySelectorAll("#tamper-findings .finding").length,
    signing: document.querySelector("#signing-body").textContent.replace(/\\s+/g," ").slice(0,120),
  })`);
  console.log(state);
  const s = JSON.parse(state);
  const gateOpened = !s.verdict.includes("refused");
  if (gateOpened && (s.gateRows === 0 || s.gateChecks !== 4)) fail("gate panel empty");
  if (gateOpened && s.contentRows === 0) fail("content panel empty");
  if (s.tamperChecks !== 2 && !s.signing.includes("not a ZIP")) fail("tamper checks missing");
  // tab badges follow the panel verdicts: a refused container is a red "refused", never blank
  const badges = JSON.parse(await evalJs(`JSON.stringify(Object.fromEntries(["gate","extract","content","tamper","signing"].map(k => { const el = document.querySelector("#n-" + k); return [k, { t: el.textContent, alert: el.classList.contains("alert") }]; })))`));
  console.log("badges:", JSON.stringify(badges));
  for (const [k, b] of Object.entries(badges)) if (!b.t) fail(`tab badge ${k} is blank`);
  if (!gateOpened && !(badges.gate.t === "refused" && badges.gate.alert)) fail("refused container not flagged on the Install gate badge");
  if (gateOpened && badges.gate.t !== String(s.gateRows)) fail(`gate badge ${badges.gate.t} ≠ ${s.gateRows} entries`);
  // flip a manifest input and make sure the gate re-runs
  await evalJs(`(async()=>{const s=document.querySelector("#in-enl"); s.value="false"; s.dispatchEvent(new Event("change")); await new Promise(r=>setTimeout(r,800));})()`);
  const echoed = await evalJs(`document.querySelector("#gate-verdict").textContent`);
  if (gateOpened && !echoed.includes("extractNativeLibs=false")) fail("gate did not re-run on input change: " + echoed.slice(0, 200));
  // content hex view on first row
  await evalJs(`(()=>{const tr=document.querySelector("#content-table tbody tr"); if(tr) tr.click(); return true;})()`);
  const hexLen = await evalJs(`(document.querySelector("#content-hex pre")||{textContent:""}).textContent.length`);
  if (gateOpened && hexLen === 0) fail("hex view empty");
  // Extract tab: plan rows, then "extract all" → capture the zip blob instead of downloading
  // it, and check it against the plan inside the page (paths sanitized, every entry either
  // a file or a recorded reader rejection, CRC of each stored file).
  if (gateOpened) {
    const xs = JSON.parse(await evalJs(`(async()=>{
      document.querySelector('[data-tab="extract"]').click();
      const rows = document.querySelectorAll("#extract-table tbody tr").length;
      const plan = report.gate.extract;
      let blob = null; const orig = window.saveBlob; window.saveBlob = (b, n) => { blob = b; window.__xname = n; };
      document.querySelector("#x-all").click();
      for (let t = 0; t < 600 && !blob; t++) await new Promise(r => setTimeout(r, 100));
      window.saveBlob = orig;
      if (!blob) return JSON.stringify({ rows, err: "no blob: " + document.querySelector("#x-status").textContent });
      const b = new Uint8Array(await blob.arrayBuffer()), dv = new DataView(b.buffer);
      const eocd = b.length - 22, n = dv.getUint16(eocd + 10, true); let p = dv.getUint32(eocd + 16, true);
      const td = new TextDecoder(), files = {}; let crcBad = 0;
      const crc = (d) => { let c = ~0; for (const x of d) { c ^= x; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; } return ~c >>> 0; };
      for (let i = 0; i < n; i++) {
        const nl = dv.getUint16(p + 28, true), off = dv.getUint32(p + 42, true), size = dv.getUint32(p + 24, true), c = dv.getUint32(p + 16, true);
        const name = td.decode(b.subarray(p + 46, p + 46 + nl)); p += 46 + nl;
        const lnl = dv.getUint16(off + 26, true), data = b.subarray(off + 30 + lnl, off + 30 + lnl + size);
        if (size < 1 << 20 && crc(data) !== c) crcBad++;
        files[name] = data;
      }
      const man = JSON.parse(td.decode(files["apkllm-extract.json"]));
      const bad = Object.keys(files).filter(f => f !== "apkllm-extract.json" && (!/^(files|collisions)\\//.test(f) || f.replace(/\\/$/, "").split("/").some(s => s === ".." || s === "." || s === "")));
      const missing = man.entries.filter(e => e.kind === "file" && !(e.path in files)).length;
      const unique = plan.entries.length;   // one manifest row per gate entry
      const sorted = (xs) => JSON.stringify([...xs].sort());
      const rejected = man.entries.filter(e => e.failure === "reader_rejected").map(e => e.name);
      // four-reader rule: reader_rejected is exactly the plan's undeliverable set, minus entries
      // the by-name lookup never reaches (name_unaddressable takes precedence)
      const unaddressable = new Set(man.entries.filter(e => e.failure === "name_unaddressable").map(e => e.index));
      const undeliverable = plan.entries.map((e, i) => ({ e, i })).filter(({ e, i }) => !e.deliverable && !unaddressable.has(i)).map(({ e }) => e.name);
      const keyClash = Object.keys(files).length !== new Set(Object.keys(files).map(f => f.normalize("NFC").toLowerCase())).size;
      const longSeg = Object.keys(files).some(f => f.split("/").some(sg => new TextEncoder().encode(sg).length > 255));
      return JSON.stringify({ rows, zipEntries: n, counts: man.counts, total: man.entries.length, unique, bad, missing, crcBad, keyClash, longSeg,
        rejectedOk: sorted(rejected) === sorted(undeliverable), uncaused: man.entries.filter(e => !e.ok && !e.failure).length,
        failedNames: man.entries.filter(e => !e.ok).map(e => e.name + ":" + e.failure), status: document.querySelector("#x-status").textContent, fname: window.__xname });
    })()`, 90000));
    console.log("extract:", JSON.stringify(xs).slice(0, 400));
    if (xs.err) fail(xs.err);
    else {
      if (xs.rows === 0) fail("extract table empty");
      const c = xs.counts, covered = c.files + c.directories + c.reader_rejected + c.name_unaddressable + c.extract_failed;
      // zip holds files + directory records + the manifest
      if (xs.total !== xs.unique || covered !== xs.unique) fail(`bundle covers ${covered} (${xs.total} rows) of ${xs.unique} entries`);
      if (xs.zipEntries !== c.files + c.directories + 1) fail("zip entry count ≠ files + directories + manifest");
      if (xs.bad.length) fail("unsanitized output paths: " + xs.bad.join(", "));
      if (xs.missing || xs.crcBad) fail(`manifest paths missing ${xs.missing} / crc mismatches ${xs.crcBad}`);
      if (xs.keyClash) fail("two output paths collide on a case-insensitive filesystem");
      if (xs.longSeg) fail("an output path segment exceeds 255 bytes");
      if (!xs.rejectedOk) fail("reader_rejected set ≠ the plan's undeliverable set (four-reader rule)");
      if (xs.uncaused) fail(`${xs.uncaused} failed rows without a failure cause`);
    }
  }
  // double-click an Extract row → that entry through its own reader → a download whose bytes
  // equal extractEntry's; a reader-rejected row reports its reason and downloads nothing; the
  // gate "bytes" button resolves names by index (a CR name survives).
  if (gateOpened) {
    const dc = JSON.parse(await evalJs(`(async()=>{
      document.querySelector('[data-tab="extract"]').click();
      $("#extract-filter").value = ""; xReaderOn = new Set(READER_ORDER); renderExtract();
      const plan = report.gate.extract.entries, saved = [];
      const orig = window.saveBlob; window.saveBlob = (b, n) => saved.push({ b, n });
      window.__alerts = []; window.alert = (m) => window.__alerts.push(String(m));   // a modal would hang CDP
      const settle = async () => { for (let t = 0; t < 100 && extracting.size; t++) await new Promise(r => setTimeout(r, 50)); await new Promise(r => setTimeout(r, 30)); };
      const dbl = async (i) => { const tr = document.querySelector('#extract-table tbody tr[data-i="' + i + '"]');
        tr.querySelector("td.name").dispatchEvent(new MouseEvent("dblclick", { bubbles: true, detail: 2 })); await new Promise(r => setTimeout(r, 10)); await settle(); };
      const same = (a, b) => a.length === b.length && a.every((x, k) => x === b[k]);
      const out = {};
      const okI = plan.findIndex(e => e.deliverable && !e.name.endsWith("/") && !/[\\u0080-\\uffff]/.test(e.name) ? true : false);
      if (okI >= 0) {
        const n = saved.length; await dbl(okI);
        const want = await wcall({ type: "extract", name: plan[okI].name });
        out.ok = saved.length === n + 1 && want.ok && same(new Uint8Array(await saved[saved.length - 1].b.arrayBuffer()), want.data);
        out.okName = saved[saved.length - 1]?.n;
      }
      const badI = plan.findIndex(e => !e.deliverable);
      if (badI >= 0) { const n = saved.length; await dbl(badI); out.rejectedNoDownload = saved.length === n; out.rejectedStatus = $("#x-status").textContent; }
      const crI = report.gate.entries.findIndex(e => e.name.includes("\\r"));
      if (crI >= 0) {
        document.querySelector('[data-tab="gate"]').click();
        $("#gate-filter").value = ""; gateClassOn = new Set(CLASS_ORDER); renderGate();
        const b = document.querySelector('#gate-table button[data-i="' + crI + '"]'); const n = saved.length;
        b.click(); await new Promise(r => setTimeout(r, 10)); await settle();
        out.crBytes = saved.length === n + 1;
        document.querySelector('[data-tab="extract"]').click();
      }
      // a result that lands after another APK was loaded is dropped (no stale download / status)
      if (okI >= 0) { const n = saved.length; const tr = document.querySelector('#extract-table tbody tr[data-i="' + okI + '"]');
        tr.dispatchEvent(new MouseEvent("dblclick", { bubbles: true, detail: 2 })); loadGen++; await settle(); loadGen--;
        out.staleDropped = saved.length === n; }
      out.found = { okI, badI, crI }; out.alerts = window.__alerts;
      window.__saved = saved;   // the real-mouse test below keeps counting
      return JSON.stringify(out);
    })()`));
    // REAL mouse double-clicks (CDP input, two clicks with detail 1 then 2): on a name → one
    // download and no clipboard write; on a "bytes" button → exactly one download
    const realDbl = async (selector) => {
      const r = JSON.parse(await evalJs(`(()=>{ const el = document.querySelector(${JSON.stringify(selector)}); el.scrollIntoView({ block: "center" }); const b = el.getBoundingClientRect(); return JSON.stringify({ x: b.x + Math.min(8, b.width / 2), y: b.y + b.height / 2 }); })()`));
      for (const clickCount of [1, 2]) for (const type of ["mousePressed", "mouseReleased"])
        await S("Input.dispatchMouseEvent", { type, x: r.x, y: r.y, button: "left", clickCount });
      await evalJs(`(async()=>{ await new Promise(r => setTimeout(r, 450)); for (let t = 0; t < 100 && extracting.size; t++) await new Promise(r => setTimeout(r, 50)); return true; })()`);
    };
    if (dc.found?.okI >= 0) {
      await evalJs(`window.__copied = []; Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (t) => { window.__copied.push(t); } } }); window.__n0 = window.__saved.length; true`);
      await realDbl(`#extract-table tbody tr[data-i="${dc.found.okI}"] .copyable`);
      const a = JSON.parse(await evalJs(`JSON.stringify({ dl: window.__saved.length - window.__n0, copied: window.__copied.length })`));
      dc.realName = a; if (a.dl !== 1 || a.copied !== 0) fail("real double-click on a name: " + JSON.stringify(a));
      await evalJs(`window.__n0 = window.__saved.length; true`);
      await realDbl(`#extract-table tbody tr[data-i="${dc.found.okI}"] button[data-i]`);
      const b = JSON.parse(await evalJs(`JSON.stringify({ dl: window.__saved.length - window.__n0 })`));
      dc.realBytes = b; if (b.dl !== 1) fail("real double-click on bytes downloaded " + b.dl + " times");
      // a real SINGLE click on an Extract name still copies it (after the double-click window)
      const r1 = JSON.parse(await evalJs(`(()=>{ const el = document.querySelector('#extract-table tbody tr[data-i="${dc.found.okI}"] .copyable'); const b = el.getBoundingClientRect(); window.__copied = []; window.__n0 = window.__saved.length; return JSON.stringify({ x: b.x + Math.min(8, b.width / 2), y: b.y + b.height / 2 }); })()`));
      for (const type of ["mousePressed", "mouseReleased"]) await S("Input.dispatchMouseEvent", { type, x: r1.x, y: r1.y, button: "left", clickCount: 1 });
      const c = JSON.parse(await evalJs(`(async()=>{ await new Promise(r => setTimeout(r, 500)); return JSON.stringify({ copied: window.__copied, dl: window.__saved.length - window.__n0, want: report.gate.extract.entries[${dc.found.okI}].name }); })()`));
      dc.realClick = { copied: c.copied.length, dl: c.dl };
      if (c.copied.length !== 1 || c.copied[0] !== c.want || c.dl !== 0) fail("real single click on an Extract name: " + JSON.stringify(c));
    }
    await evalJs(`window.saveBlob = (b, n) => {}; true`);
    console.log("dblclick:", JSON.stringify(dc).slice(0, 300));
    if (dc.ok === false) fail("double-click download ≠ extractEntry bytes");
    if (dc.rejectedNoDownload === false) fail("a reader-rejected row downloaded something");
    if (dc.rejectedStatus !== undefined && !/strict reader rejects/.test(dc.rejectedStatus)) fail("rejected row did not report its reader's reason: " + dc.rejectedStatus);
    if (dc.crBytes === false) fail("gate bytes button lost a CR-named entry");
    if (dc.staleDropped === false) fail("an extract that finished after a new load still downloaded");
    if (dc.alerts?.length) fail("unexpected alert: " + dc.alerts.join(" | "));
    if (base === "readers" && (dc.found.okI < 0 || dc.found.badI < 0 || dc.found.crI < 0)) fail("readers.apk lost its dblclick fixtures " + JSON.stringify(dc.found));
  }
  // copy (dexllm-web "⧉ copy"): every card button yields "# apkllm-web …" text; entry tables
  // are one TSV row per entry with a uniform column count whatever the names contain; hostile
  // names come out escaped; clicking a name copies the REPORT's name byte-exact.
  const cp = JSON.parse(await evalJs(`(async()=>{
    const got = [];
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (t) => { got.push(t); } } });
    const out = {};
    for (const b of document.querySelectorAll("button.copybtn")) {
      const n = got.length; b.click(); await new Promise(r => setTimeout(r, 30));
      out[b.dataset.copy] = got.length > n ? got[got.length - 1] : null;
    }
    const shape = (k) => { if (out[k] == null) return null; const ls = out[k].split("\\n").slice(1); const w = ls[0].split("\\t").length;
      return { rows: ls.length - 1, uniform: ls.every(l => l.split("\\t").length === w) }; };
    // click-to-copy on every hostile name present, compared against the report data
    const hostile = /[\\t\\n\\r"]|^[=+@-]/;
    const clicks = [];
    for (const el of document.querySelectorAll("#gate-table .copyable, #tamper-table .copyable")) {
      const src = el.dataset.src, i = Number(el.dataset.i);
      const want = src === "gate" ? report.gate.entries[i].name : report.tamper.entries[i].name;
      if (!hostile.test(want)) continue;
      const n = got.length; el.click(); await new Promise(r => setTimeout(r, 30));
      clicks.push({ want, ok: got.length > n && got[got.length - 1] === want });
    }
    const gateTsv = out["gate-entries"] || "";
    return JSON.stringify({ keys: Object.keys(out), nulls: Object.entries(out).filter(([k, v]) => v === null).map(([k]) => k),
      noHeader: Object.entries(out).filter(([k, v]) => v !== null && !v.startsWith("# apkllm-web")).map(([k]) => k),
      gate: shape("gate-entries"), extract: shape("extract-entries"), content: shape("content-entries"), tamper: shape("tamper-entries"),
      gateN: report.gate.ok ? report.gate.entries.length : null, extractN: report.gate.ok ? report.gate.extract.entries.length : null,
      contentN: report.content.ok ? report.content.entries.length : null, tamperN: report.tamper.ok ? report.tamper.entries.length : null,
      hostileNames: report.gate.ok ? report.gate.entries.filter(e => hostile.test(e.name)).length : 0,
      escapedTab: gateTsv.includes("assets/tab\\\\there\\\\nnewline.txt"), escapedCr: gateTsv.includes("assets/cr\\\\rname.txt"),
      quoted: gateTsv.includes('\\t\\\\"lead.txt\\t'), formula: gateTsv.includes("\\t'=HYPERLINK(1)\\t"), clicks });
  })()`));
  console.log("copy:", JSON.stringify({ ...cp, keys: cp.keys.length }).slice(0, 400));
  if (cp.keys.length < 14) fail(`only ${cp.keys.length} copy buttons`);
  if (cp.nulls.length) fail("copy buttons that copied nothing: " + cp.nulls.join(", "));
  if (cp.noHeader.length) fail("copy text without header: " + cp.noHeader.join(", "));
  for (const [k, n] of [["gate", cp.gateN], ["extract", cp.extractN], ["content", cp.contentN], ["tamper", cp.tamperN]])
    if (n !== null && (!cp[k] || cp[k].rows !== n || !cp[k].uniform)) fail(`${k} TSV ${JSON.stringify(cp[k])} for ${n} entries`);
  if (cp.hostileNames && base === "readers" && !(cp.escapedTab && cp.escapedCr && cp.quoted && cp.formula)) fail("hostile names not escaped in the TSV: " + JSON.stringify(cp));
  if (base === "readers" && cp.hostileNames < 4) fail("readers.apk lost its hostile-name fixtures");
  for (const c of cp.clicks) if (!c.ok) fail("click-copy not byte-exact for " + JSON.stringify(c.want));
  if (SHOT) {   // SHOT = the Tamper scan tab, SHOT with "-extract" before .png = the Extract tab
    for (const [tab, file] of [["tamper", SHOT], ["extract", SHOT.replace(/(\.png)?$/, "-extract.png")]]) {
      await evalJs(`document.querySelector('[data-tab="${tab}"]').click(); true`);
      const { result: { data } } = await S("Page.captureScreenshot", { format: "png" });
      writeFileSync(file, Buffer.from(data, "base64")); console.log("screenshot:", file);
    }
  }
  // libziparchive's own ALOGW lines (stderr → console.error, "W tag: Zip: …") are
  // expected on tampered input and are not page errors.
  const real = consoleErrors.filter(x => !/^[VDIWEF] \S+: /.test(x));
  if (real.length) { console.log("console errors:", real); fail("console errors"); }
} catch (e) { fail(String(e)); }
finally { ws.close(); chrome.kill(); server.close(); }
if (failures) { console.error(failures, "failure(s)"); process.exit(1); }
console.log("BROWSER OK");
