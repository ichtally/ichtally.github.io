// node bluesky-handle-checker/test.js  (offline: all network calls go to a fake)
const assert = require("assert");
const H = require("./check.js");
let n = 0, pending = [];
const t = (name, fn) => { const r = fn(); if (r && r.then) pending.push(r.then(() => { n++; console.log("ok", name); }));
  else { n++; console.log("ok", name); } };

const A = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", B = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";

// Fake world: dns = {name: [cloudflare-style data strings]}, wk = {handle: body | null (CORS fail)},
// docs = {did: alsoKnownAs[]}, profiles = {did: handle}, resolve = {handle: did}
function world(w) {
  const json = (status, j) => Promise.resolve({ status, json: () => Promise.resolve(j), text: () => Promise.resolve(JSON.stringify(j)) });
  return (url) => {
    const u = new URL(url), q = u.searchParams;
    if (u.host === "cloudflare-dns.com") {
      const recs = (w.dns || {})[q.get("name")];
      return json(200, recs ? { Status: 0, Answer: recs.map((d) => ({ type: 16, data: d })) } : { Status: 3 });
    }
    if (u.pathname === "/.well-known/atproto-did") {
      const body = (w.wk || {})[u.host];
      if (body === undefined || body === null) return Promise.reject(new TypeError("Failed to fetch"));
      return Promise.resolve({ status: 200, text: () => Promise.resolve(body) });
    }
    if (u.host === "plc.directory") {
      const did = u.pathname.slice(1), aka = (w.docs || {})[did];
      return aka ? json(200, { id: did, alsoKnownAs: aka.map((h) => "at://" + h),
        service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: "https://pds.example.net" }] }) : json(404, {});
    }
    if (u.pathname.endsWith("resolveHandle")) {
      const did = (w.resolve || {})[q.get("handle")];
      return did ? json(200, { did }) : json(400, { error: "InvalidRequest", message: "Unable to resolve handle" });
    }
    if (u.pathname.endsWith("getProfile")) {
      const h = (w.profiles || {})[q.get("actor")];
      return h ? json(200, { did: q.get("actor"), handle: h }) : json(400, { message: "Profile not found" });
    }
    return Promise.reject(new Error("unexpected " + url));
  };
}
const run = (h, w, ex) => H.check(h, ex || "", world(w));

// ---- pure parts ----
t("input cleanup", () => {
  assert.strictEqual(H.normalizeInput(" @Alice.Example.COM ").handle, "alice.example.com");
  assert.strictEqual(H.normalizeInput("https://alice.example.com/profile?x=1").handle, "alice.example.com");
  assert.strictEqual(H.normalizeInput("example.com.").handle, "example.com");
});
t("IDN becomes punycode", () => {
  const r = H.normalizeInput("café.fr");
  assert.strictEqual(r.handle, "xn--caf-dma.fr"); assert.strictEqual(r.notes.length, 1);
});
t("syntax rules match @atproto/syntax", () => {
  assert.strictEqual(H.validateHandle("example.com"), null);
  assert.strictEqual(H.validateHandle("4chan.org"), null);
  assert.ok(H.validateHandle("localhost"));          // one part
  assert.ok(H.validateHandle("a..b.com"));           // empty part
  assert.ok(H.validateHandle("-a.com"));             // leading hyphen
  assert.ok(H.validateHandle("a.123"));              // TLD starts with digit
  assert.ok(H.validateHandle("me.local"));           // disallowed TLD
  assert.ok(H.validateHandle("a_b.com"));            // underscore
  assert.ok(H.validateHandle("a".repeat(64) + ".com"));
  assert.strictEqual(H.validateHandle("me.test"), null); // .test is allowed
});
t("TXT data parsing (Cloudflare quoted chunks, Google unquoted)", () => {
  assert.strictEqual(H.parseTxtData('"did=' + A + '"'), "did=" + A);
  assert.strictEqual(H.parseTxtData('"did=did:plc:aaaa" "aaaa"'), "did=did:plc:aaaaaaaa");
  assert.strictEqual(H.parseTxtData('"a\\"b\\032c"'), 'a"b c');
  assert.strictEqual(H.parseTxtData("did=" + A), "did=" + A);
});
t("pickDid: exactly one did= record", () => {
  assert.strictEqual(H.pickDid(["v=spf1 -all", "did=" + A]).did, A);
});
t("pickDid: two identical records = no answer", () => {
  const p = H.pickDid(["did=" + A, "did=" + A]);
  assert.strictEqual(p.did, null); assert.match(p.notes[0], /identical/);
});
t("pickDid: near misses explained", () => {
  assert.match(H.pickDid([A]).notes[0], /missing the "did=" prefix/);
  assert.match(H.pickDid(["DID=" + A]).notes[0], /lower-case/);
  assert.match(H.pickDid([" did=" + A]).notes[0], /spaces before/);
  assert.match(H.pickDid(["atproto did=" + A]).notes[0], /START/);
  const p = H.pickDid(["did=" + A + " "]);
  assert.strictEqual(p.valid, false); assert.match(p.notes[0], /spaces/);
});
t("well-known parsing", () => {
  assert.strictEqual(H.parseWellKnown(A + "\n").did, A);
  assert.strictEqual(H.parseWellKnown("  " + A + "  \nmore").did, A);
  assert.match(H.parseWellKnown("<!doctype html><html>").note, /HTML/);
});
t("host field for DNS panels", () => {
  assert.strictEqual(H.hostField("example.com", "example.com"), "_atproto");
  assert.strictEqual(H.hostField("alice.example.com", "example.com"), "_atproto.alice");
});

// ---- whole flow ----
t("ok via DNS", () => run("alice.example.com", { dns: { "_atproto.alice.example.com": ['"did=' + A + '"'] },
  docs: { [A]: ["alice.example.com"] }, profiles: { [A]: "alice.example.com" }, resolve: { "alice.example.com": A } })
  .then((r) => { assert.strictEqual(r.verdict.level, "ok"); assert.strictEqual(r.didSource, "dns"); assert.strictEqual(r.pds, "https://pds.example.net");
    assert.ok(!r.verdict.steps.some((s) => /well-known file only/.test(s)));
    assert.ok(r.verdict.steps.some((s) => /Still seeing "Invalid Handle".*Update to alice\.example\.com/.test(s))); }));
t("ok via well-known", () => run("bob.example.org", { wk: { "bob.example.org": A + "\n" },
  docs: { [A]: ["bob.example.org"] }, profiles: { [A]: "bob.example.org" } })
  .then((r) => { assert.strictEqual(r.verdict.level, "ok"); assert.strictEqual(r.didSource, "http");
    assert.ok(r.verdict.steps.some((s) => s.indexOf("well-known file only") >= 0 && s.indexOf("did=" + A) >= 0)); }));
t("well-known blocked by CORS, Bluesky resolves it: still ok", () => run("bob.example.org", {
  resolve: { "bob.example.org": A }, docs: { [A]: ["bob.example.org"] }, profiles: { [A]: "bob.example.org" } })
  .then((r) => { assert.strictEqual(r.verdict.level, "ok"); assert.strictEqual(r.didSource, "appview"); }));
t("nothing anywhere", () => run("nobody.example.com", {}).then((r) => {
  assert.strictEqual(r.verdict.level, "bad"); assert.match(r.verdict.steps.join(" "), /_atproto\.nobody/);
}));
t("doubled name (zone appended twice)", () => run("example.com", { dns: { "_atproto.example.com.example.com": ['"did=' + A + '"'] } })
  .then((r) => { assert.strictEqual(r.verdict.level, "bad"); assert.match(r.verdict.steps.join(" "), /just "_atproto"/); }));
t("doubled name on a subdomain", () => run("alice.example.com", { dns: { "_atproto.alice.example.com.example.com": ['"did=' + A + '"'] } })
  .then((r) => assert.match(r.verdict.steps.join(" "), /just "_atproto\.alice"/)));
t("record put on the domain itself", () => run("example.com", { dns: { "example.com": ['"v=spf1 -all"', '"did=' + A + '"'] } })
  .then((r) => assert.match(r.verdict.steps.join(" "), /must be on _atproto\.example\.com/)));
t("two did= records", () => run("example.com", { dns: { "_atproto.example.com": ['"did=' + A + '"', '"did=' + B + '"'] } })
  .then((r) => { assert.strictEqual(r.verdict.level, "bad"); assert.match(r.verdict.steps.join(" "), /ambiguous/); }));
t("DNS wins over well-known, conflict reported", () => run("example.com", {
  dns: { "_atproto.example.com": ['"did=' + A + '"'] }, wk: { "example.com": B },
  docs: { [A]: ["example.com"] }, profiles: { [A]: "example.com" } })
  .then((r) => { assert.strictEqual(r.did, A); assert.match(r.verdict.steps.join(" "), /DNS wins/); }));
t("points to a different account than expected", () => run("example.com", {
  dns: { "_atproto.example.com": ['"did=' + A + '"'] }, resolve: { "me.bsky.social": B } }, "@me.bsky.social")
  .then((r) => { assert.strictEqual(r.verdict.level, "bad"); assert.match(r.verdict.steps[0], new RegExp("did=" + B)); }));
t("expected given as a DID", () => run("example.com", {
  dns: { "_atproto.example.com": ['"did=' + A + '"'] }, docs: { [A]: ["example.com"] }, profiles: { [A]: "example.com" } }, A)
  .then((r) => assert.strictEqual(r.verdict.level, "ok")));
t("DNS done, handle not switched yet", () => run("example.com", {
  dns: { "_atproto.example.com": ['"did=' + A + '"'] }, docs: { [A]: ["me.bsky.social"] }, profiles: { [A]: "me.bsky.social" } })
  .then((r) => { assert.strictEqual(r.verdict.level, "wait"); assert.match(r.verdict.title, /Half done/); }));
t("records right, Bluesky still shows handle.invalid", () => run("example.com", {
  dns: { "_atproto.example.com": ['"did=' + A + '"'] }, docs: { [A]: ["example.com"] }, profiles: { [A]: "handle.invalid" } })
  .then((r) => { assert.strictEqual(r.verdict.level, "wait"); assert.match(r.verdict.title, /handle\.invalid/); }));
t("bad syntax stops early", () => run("me.local", {}).then((r) => {
  assert.strictEqual(r.verdict.level, "bad"); assert.strictEqual(r.dns, undefined);
}));
t("empty input", () => run("  ", {}).then((r) => assert.strictEqual(r.verdict.level, "bad")));

Promise.all(pending).then(() => console.log("\n" + n + " tests passed"), (e) => { console.error(e); process.exit(1); });
