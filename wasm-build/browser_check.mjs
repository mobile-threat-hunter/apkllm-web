// Headless-Chrome check of the actual page: serves the repo root, drives index.html
// over CDP (no puppeteer), feeds it an APK through the file input, and asserts the
// four panels rendered. Also takes a screenshot for eyeballing.
//
//   node browser_check.mjs APK [screenshot.png]
//
// Needs google-chrome on PATH and node ≥ 22 (global WebSocket).
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { argv } from "node:process";

const ROOT = resolve(new URL("..", import.meta.url).pathname);
const APK = resolve(argv[2]);
const SHOT = argv[3];
const base = APK.split("/").pop().replace(/\.apk$/, "");
const md5 = (b) => createHash("md5").update(b).digest("hex");
const sha256 = (b) => createHash("sha256").update(b).digest("hex");
// the page's zips are STORED; parse via the central directory (names → bytes)
function unzipStored(buf) {
  const eocd = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const n = buf.readUInt16LE(eocd + 10); let p = buf.readUInt32LE(eocd + 16); const out = new Map();
  for (let i = 0; i < n; i++) {
    const method = buf.readUInt16LE(p + 10), csize = buf.readUInt32LE(p + 20), nl = buf.readUInt16LE(p + 28), el = buf.readUInt16LE(p + 30), cl = buf.readUInt16LE(p + 32), off = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nl).toString("utf8"); p += 46 + nl + el + cl;
    const lnl = buf.readUInt16LE(off + 26), lel = buf.readUInt16LE(off + 28), raw = buf.subarray(off + 30 + lnl + lel, off + 30 + lnl + lel + csize);
    out.set(name, method === 8 ? inflateRawSync(raw) : Buffer.from(raw));
  }
  return out;
}
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
  const badges = JSON.parse(await evalJs(`JSON.stringify(Object.fromEntries(["gate","extract","content","images","tamper","signing"].map(k => { const el = document.querySelector("#n-" + k); return [k, { t: el.textContent, alert: el.classList.contains("alert") }]; })))`));
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
  // it and check it HERE in node, hashes by node:crypto (independent of the page's md5): apkllm
  // naming — every file is {md5}.bin of its content ({md5}.{sha256}.bin on a collision), the
  // report is {input md5}.json, nothing is named after an entry; every entry is a file, a
  // directory or a recorded reader rejection; the four-reader rule holds.
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
      const u8 = new Uint8Array(await blob.arrayBuffer()); let bin = "";
      for (let k = 0; k < u8.length; k += 0x8000) bin += String.fromCharCode.apply(null, u8.subarray(k, k + 0x8000));
      return JSON.stringify({ rows, b64: btoa(bin), fname: window.__xname, status: document.querySelector("#x-status").textContent,
        plan: plan.entries.map(e => ({ name: e.name, deliverable: e.deliverable })) });
    })()`, 120000));
    if (xs.err) fail(xs.err);
    else {
      const zipFiles = unzipStored(Buffer.from(xs.b64, "base64"));
      const inputMd5 = md5(readFileSync(APK));
      const names = [...zipFiles.keys()];
      const reportName = `${inputMd5}.json`;
      const rep = zipFiles.has(reportName) ? JSON.parse(zipFiles.get(reportName).toString("utf8")) : null;
      const badNames = names.filter(n => n !== reportName && !/^[0-9a-f]{32}(\.[0-9a-f]{64})?\.bin$/.test(n));
      const hashBad = names.filter(n => n !== reportName).filter(n => { const d = zipFiles.get(n), [m, sh] = n.replace(/\.bin$/, "").split(".");
        return md5(d) !== m || (sh && sha256(d) !== sh); });
      console.log("extract:", JSON.stringify({ rows: xs.rows, zipEntries: names.length, fname: xs.fname, counts: rep?.counts, status: xs.status }).slice(0, 400));
      if (xs.rows === 0) fail("extract table empty");
      if (!rep) fail(`report ${reportName} (input md5) missing; zip has ${names.slice(0, 5).join(", ")}`);
      else {
        const c = rep.counts, total = xs.plan.length;
        if (rep.input.md5 !== inputMd5) fail("report input.md5 ≠ md5 of the APK");
        if (xs.fname !== `${inputMd5}.extracted.zip`) fail("bundle download name " + xs.fname);
        if (badNames.length) fail("output names not {md5}.bin: " + badNames.slice(0, 5).join(", "));
        if (hashBad.length) fail("file content does not hash to its name: " + hashBad.slice(0, 5).join(", "));
        if (rep.entries.length !== total || c.extracted + c.directories + c.reader_rejected + c.name_unaddressable + c.extract_failed !== total) fail(`report covers ${rep.entries.length} rows / counts ${JSON.stringify(c)} of ${total} entries`);
        if (names.length !== c.files + 1) fail(`zip has ${names.length} entries for ${c.files} files + report`);
        if (c.extracted !== c.files + c.same_content) fail("extracted ≠ files + same_content");
        for (const e of rep.entries.filter(e => e.kind === "file")) {
          const d = zipFiles.get(e.file);
          if (!d) { fail(`${JSON.stringify(e.name)} → ${e.file} not in the zip`); break; }
          if (md5(d) !== e.md5 || sha256(d) !== e.sha256 || d.length !== e.size) { fail(`${JSON.stringify(e.name)} hashes/size ≠ its file`); break; }
        }
        // four-reader rule: reader_rejected is exactly the plan's undeliverable set, minus entries
        // the by-name lookup never reaches (name_unaddressable takes precedence)
        const unaddr = new Set(rep.entries.filter(e => e.failure === "name_unaddressable").map(e => e.index));
        const sorted = (xs) => JSON.stringify([...xs].sort());
        if (sorted(rep.entries.filter(e => e.failure === "reader_rejected").map(e => e.name)) !== sorted(xs.plan.filter((e, i) => !e.deliverable && !unaddr.has(i)).map(e => e.name)))
          fail("reader_rejected set ≠ the plan's undeliverable set (four-reader rule)");
        if (rep.entries.some(e => !e.ok && !e.failure)) fail("failed rows without a failure cause");
        if (rep.entries.some(e => !e.ok && e.file) || rep.entries.some(e => e.kind === "directory" && e.file)) fail("a failed / directory row carries a file");
        if (rep.input.sha256 !== sha256(readFileSync(APK)) || rep.input.size !== readFileSync(APK).length) fail("report input sha256/size ≠ the APK");
        // single downloads must name a file exactly as the bundle did, and identical-content
        // entries must produce the same file AND the same JSON (unzipping both never loses a mapping)
        const probe = rep.entries.filter(e => e.kind === "file" && /^assets\/(coll_[ab]|twin[12])\.bin$/.test(e.name));
        if (base === "readers") {
          if (c.md5_collisions < 1 || c.same_content < 1) fail("readers.apk: md5 collision / identical-content fixtures not exercised " + JSON.stringify(c));
          const ca = probe.find(e => e.name === "assets/coll_a.bin"), cb = probe.find(e => e.name === "assets/coll_b.bin");
          if (!ca || !cb || ca.md5 !== cb.md5 || ca.sha256 === cb.sha256 || ca.file === cb.file
              || ![ca.file, cb.file].includes(`${ca.md5}.bin`) || ![ca.file, cb.file].includes(`${cb.md5}.${(ca.file === `${ca.md5}.bin` ? cb : ca).sha256}.bin`)) fail("md5 collision not split into {md5}.bin + {md5}.{sha256}.bin: " + JSON.stringify([ca?.file, cb?.file]));
          const t1 = probe.find(e => e.name === "assets/twin1.bin"), t2 = probe.find(e => e.name === "assets/twin2.bin");
          if (!t1 || !t2 || t1.file !== t2.file) fail("identical content not one file");
        }
        if (probe.length) {
          const sg = JSON.parse(await evalJs(`(async()=>{ const out = [];
            for (const i of ${JSON.stringify(probe.map(e => e.index))}) { const r = await wcall({ type: "single", index: i, source: report.file, params: gateParams() });
              const u8 = new Uint8Array(await r.blob.arrayBuffer()), dv = new DataView(u8.buffer), eo = u8.length - 22, n = dv.getUint16(eo + 10, true); let p = dv.getUint32(eo + 16, true); const m = {};
              for (let k = 0; k < n; k++) { const nl = dv.getUint16(p + 28, true), off = dv.getUint32(p + 42, true), sz = dv.getUint32(p + 24, true); const nm = new TextDecoder().decode(u8.subarray(p + 46, p + 46 + nl)); p += 46 + nl; const lnl = dv.getUint16(off + 26, true); m[nm] = new TextDecoder().decode(u8.subarray(off + 30 + lnl, off + 30 + lnl + sz)); }
              out.push({ i, base: r.base, names: Object.keys(m).sort(), json: m[r.base + ".json"] ?? null }); }
            return JSON.stringify(out); })()`));
          for (const x of sg) {
            const e = rep.entries.find(r => r.index === x.i);
            if (x.base + ".bin" !== e.file || JSON.stringify(x.names) !== JSON.stringify([x.base + ".bin", x.base + ".json"].sort())) fail(`single ${JSON.stringify(e.name)} named ${x.base} but the bundle says ${e.file}`);
            const j = x.json && JSON.parse(x.json);
            if (!j || !j.entries.some(r => r.index === x.i) || j.file !== e.file) fail(`single ${JSON.stringify(e.name)} JSON does not map it`);
          }
          const tw = sg.filter(x => /twin[12]/.test(rep.entries.find(r => r.index === x.i).name));
          if (tw.length === 2 && tw[0].json !== tw[1].json) fail("two downloads of identical content produced different JSON (one mapping would be lost on unzip)");
          if (tw.length === 2 && JSON.parse(tw[0].json).entries.length !== 2) fail("identical-content JSON does not list both entries");
        }
      }
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
      // the single download is {md5}.zip = {md5}.bin + {md5}.json (STORED)
      const unz = (u8) => { const dv = new DataView(u8.buffer), eo = u8.length - 22, n = dv.getUint16(eo + 10, true); let p = dv.getUint32(eo + 16, true); const m = {};
        for (let k = 0; k < n; k++) { const nl = dv.getUint16(p + 28, true), off = dv.getUint32(p + 42, true), sz = dv.getUint32(p + 24, true);
          const nm = new TextDecoder().decode(u8.subarray(p + 46, p + 46 + nl)); p += 46 + nl; const lnl = dv.getUint16(off + 26, true); m[nm] = u8.subarray(off + 30 + lnl, off + 30 + lnl + sz); } return m; };
      const b64 = (u8) => { let s = ""; for (let k = 0; k < u8.length; k += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(k, k + 0x8000)); return btoa(s); };
      const out = {};
      const okI = plan.findIndex(e => e.deliverable && !e.name.endsWith("/") && !/[\\u0080-\\uffff]/.test(e.name) ? true : false);
      if (okI >= 0) {
        const n = saved.length; await dbl(okI);
        const want = await wcall({ type: "extract", name: plan[okI].name });
        const z = saved.length === n + 1 ? unz(new Uint8Array(await saved[saved.length - 1].b.arrayBuffer())) : {};
        const md = (saved[saved.length - 1]?.n || "").replace(/\.zip$/, "");
        const rep = z[md + ".json"] ? JSON.parse(new TextDecoder().decode(z[md + ".json"])) : null;
        const ent = rep?.entries?.find(r => r.index === okI);
        out.ok = !!(want.ok && z[md + ".bin"] && same(z[md + ".bin"], want.data) && ent?.name === plan[okI].name && rep.file === md + ".bin" && ent.file === md + ".bin" && Object.keys(z).length === 2);
        out.okName = saved[saved.length - 1]?.n; out.single = { md, b64: z[md + ".bin"] ? b64(z[md + ".bin"]) : "", sha: rep?.sha256, inputMd5: rep?.input?.md5 };
      }
      const badI = plan.findIndex(e => !e.deliverable);
      if (badI >= 0) { const n = saved.length; await dbl(badI); out.rejectedNoDownload = saved.length === n; out.rejectedStatus = $("#x-status").textContent; out.rejectedName = plan[badI].name; }
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
    // aim at the first line box: a wrapped name's union-box centre can fall between its lines
    const realDbl = async (selector) => {
      const r = JSON.parse(await evalJs(`(()=>{ const el = document.querySelector(${JSON.stringify(selector)}); el.scrollIntoView({ block: "center" }); const b = el.getClientRects()[0]; return JSON.stringify({ x: b.x + Math.min(8, b.width / 2), y: b.y + b.height / 2 }); })()`));
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
      const r1 = JSON.parse(await evalJs(`(()=>{ const el = document.querySelector('#extract-table tbody tr[data-i="${dc.found.okI}"] .copyable'); const b = el.getClientRects()[0]; window.__copied = []; window.__n0 = window.__saved.length; return JSON.stringify({ x: b.x + Math.min(8, b.width / 2), y: b.y + b.height / 2 }); })()`));
      for (const type of ["mousePressed", "mouseReleased"]) await S("Input.dispatchMouseEvent", { type, x: r1.x, y: r1.y, button: "left", clickCount: 1 });
      const c = JSON.parse(await evalJs(`(async()=>{ await new Promise(r => setTimeout(r, 500)); return JSON.stringify({ copied: window.__copied, dl: window.__saved.length - window.__n0, want: report.gate.extract.entries[${dc.found.okI}].name }); })()`));
      dc.realClick = { copied: c.copied.length, dl: c.dl };
      if (c.copied.length !== 1 || c.copied[0] !== c.want || c.dl !== 0) fail("real single click on an Extract name: " + JSON.stringify(c));
    }
    console.log("real mouse:", JSON.stringify({ name: dc.realName, bytes: dc.realBytes, click: dc.realClick }));
    await evalJs(`window.saveBlob = (b, n) => {}; true`);
    console.log("dblclick:", JSON.stringify(dc).slice(0, 300));
    if (dc.ok === false) fail("double-click download ≠ extractEntry bytes");
    if (dc.single) {   // node:crypto, independent of the page's md5
      const d = Buffer.from(dc.single.b64, "base64");
      const [nm, nsh] = dc.single.md.split(".");   // {md5} or {md5}.{sha256}
      if (md5(d) !== nm || sha256(d) !== dc.single.sha || (nsh && nsh !== dc.single.sha)) fail(`single download ${dc.okName}: content md5/sha256 ≠ name/report`);
      if (dc.single.inputMd5 !== md5(readFileSync(APK))) fail("single report input.md5 ≠ md5 of the APK");
      if (!/^[0-9a-f]{32}(\.[0-9a-f]{64})?\.zip$/.test(dc.okName)) fail("single download is not {md5}[.{sha256}].zip: " + dc.okName);
    }
    if (dc.rejectedNoDownload === false) fail("a reader-rejected row downloaded something");
    // an undeliverable entry whose NAME cannot be looked up (invalid UTF-8) reports that miss instead
    // the reason must be the reader's — unless the NAME itself cannot be looked up (U+FFFD-decoded)
    if (dc.rejectedStatus !== undefined && !(/\uFFFD/.test(dc.rejectedName) ? /FindEntry: Entry not found|decode to this same name/ : /strict reader rejects/).test(dc.rejectedStatus)) fail("rejected row did not report its reason: " + dc.rejectedStatus);
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
  // images gallery: open the tab, let the visible thumbnails load, open the viewer on one
  await evalJs(`document.querySelector('[data-tab="images"]').click(); true`);
  const imgTotal = await evalJs(`document.querySelectorAll("#images-grid .itile").length`);
  const imgExpected = await evalJs(`imgItems.length`);
  if (s.contentRows && imgTotal !== imgExpected) fail(`images grid ${imgTotal} tiles vs ${imgExpected} items`);
  if (imgTotal) {
    // a renderable tile in view must actually be fetched: wait for a finished fetch, not just any non-idle state
    const wantFetch = await evalJs(`imgItems.some(it => ["idle", "queued", "loading"].includes(it.state))`);
    // ok / undecodable / err / huge only arise from a fetch; any fetch also sets .read or .err
    await waitFor(`!imgItems.some(it => it.state === "queued" || it.state === "loading") && (!${wantFetch} || imgItems.some(it => it.read !== null || it.err))`, 30000);
    const im = JSON.parse(await evalJs(`JSON.stringify((() => { const st = {}; for (const it of imgItems) st[it.state] = (st[it.state] ?? 0) + 1;
      return { st, imgs: document.querySelectorAll("#images-grid img").length, badge: document.querySelector("#n-images").textContent }; })())`));
    console.log("images:", JSON.stringify(im));
    if (im.st.err) fail("image extraction errors: " + im.st.err);
    if ((im.st.ok ?? 0) !== im.imgs) fail("loaded images not rendered");
    await evalJs(`document.querySelector("#images-grid .itile").click(); true`);
    const iv = await evalJs(`document.querySelector("#imgview").classList.contains("on") && document.querySelector("#iv-card dl.kv") !== null`);
    if (!iv) fail("image viewer did not open");
    await evalJs(`document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" })); true`);
    if (await evalJs(`document.querySelector("#imgview").classList.contains("on")`)) fail("image viewer did not close on Escape");
    // a "huge" entry (header over the pixel cap) is never decoded by the gallery, only on request
    const hk = await evalJs(`imgItems.findIndex(it => it.state === "huge")`);
    if (hk >= 0) {
      // close mid-decode, reopen, decode again: nothing stale may survive, and the second decode
      // must not be refused because the first one's bitmap is still held (Chrome frees it lazily)
      await evalJs(`openImage(${hk}); document.querySelector("#iv-decode").click(); true`);
      await new Promise(r => setTimeout(r, 30));
      await evalJs(`closeImage(); true`);
      if (await evalJs(`ivImg !== null || ivUrl !== null || ivDecoding`)) fail("closing mid-decode left viewer state behind");
      await evalJs(`openImage(${hk}); document.querySelector("#iv-decode").click(); true`);
      await waitFor(`!ivDecoding`, 60000);
      const hd = await evalJs(`JSON.stringify({ img: !!ivImg, shown: !!document.querySelector("#iv-body .bigthumb img"), status: document.querySelector("#iv-dstatus").textContent, tileState: imgItems[${hk}].state, px: imgItems[${hk}].w * imgItems[${hk}].h })`);
      console.log("huge decode:", hd);
      const h = JSON.parse(hd);
      // up to 64 Mpx Chrome decodes a valid bitmap: it must be SHOWN, a refusal there is a bug;
      // beyond that a refusal is fine but must be explained
      if (h.px <= 64 * 1024 * 1024 ? !(h.img && h.shown) : !(h.img && h.shown) && !/could not decode/.test(h.status)) fail("decode-on-request failed: " + hd);
      if (h.tileState !== "huge") fail("decode-on-request changed the tile state");
      await evalJs(`closeImage(); true`);
      if (await evalJs(`ivImg !== null || ivUrl !== null`)) fail("decoded picture not released on close");
    }
    // a new drop with the viewer open must close it at once — its "bytes" would otherwise
    // extract from the NEW /input.apk under the old report's name (review P1)
    await evalJs(`document.querySelector("#images-grid .itile").click(); true`);
    const { result: { root: r2 } } = await S("DOM.getDocument");
    const { result: { nodeId: n2 } } = await S("DOM.querySelector", { nodeId: r2.nodeId, selector: "#file" });
    await S("DOM.setFileInputFiles", { files: [APK], nodeId: n2 });
    await waitFor(`loadGen > reportGen || document.querySelector("#app").classList.contains("on")`, 5000);
    if (await evalJs(`document.querySelector("#imgview").classList.contains("on")`)) fail("image viewer stayed open during a new load");
    await waitFor(`reportGen === loadGen && document.querySelector("#app").classList.contains("on")`);
  }
  if (SHOT) {   // SHOT = the Tamper scan tab; "-extract" / "-images" before .png = the Extract / Images tab
    for (const [tab, file] of [["tamper", SHOT], ["extract", SHOT.replace(/(\.png)?$/, "-extract.png")], ["images", SHOT.replace(/(\.png)?$/, "-images.png")]]) {
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
