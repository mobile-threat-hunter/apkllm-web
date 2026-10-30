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
const MIME = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm" };

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
  // flip a manifest input and make sure the gate re-runs
  await evalJs(`(async()=>{const s=document.querySelector("#in-enl"); s.value="false"; s.dispatchEvent(new Event("change")); await new Promise(r=>setTimeout(r,800));})()`);
  const echoed = await evalJs(`document.querySelector("#gate-verdict").textContent`);
  if (gateOpened && !echoed.includes("extractNativeLibs=false")) fail("gate did not re-run on input change: " + echoed.slice(0, 200));
  // content hex view on first row
  await evalJs(`(()=>{const tr=document.querySelector("#content-table tbody tr"); if(tr) tr.click(); return true;})()`);
  const hexLen = await evalJs(`(document.querySelector("#content-hex pre")||{textContent:""}).textContent.length`);
  if (gateOpened && hexLen === 0) fail("hex view empty");
  if (SHOT) {
    await evalJs(`document.querySelector('[data-tab="tamper"]').click(); true`);
    const { result: { data } } = await S("Page.captureScreenshot", { format: "png" });
    writeFileSync(SHOT, Buffer.from(data, "base64")); console.log("screenshot:", SHOT);
  }
  // libziparchive's own ALOGW lines (stderr → console.error, "W tag: Zip: …") are
  // expected on tampered input and are not page errors.
  const real = consoleErrors.filter(x => !/^[VDIWEF] \S+: /.test(x));
  if (real.length) { console.log("console errors:", real); fail("console errors"); }
} catch (e) { fail(String(e)); }
finally { ws.close(); chrome.kill(); server.close(); }
if (failures) { console.error(failures, "failure(s)"); process.exit(1); }
console.log("BROWSER OK");
