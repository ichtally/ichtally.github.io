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
      const name = q.get("name"), recs = (w.dns || {})[name];
      // w.nx = domains that do not exist (NXDOMAIN for them and everything below); other names exist, maybe empty.
      if ((w.nx || []).some((z) => name === z || name.endsWith("." + z))) return json(200, { Status: 3 });
      // w.servfail = registered domains whose nameservers don't answer (SERVFAIL for them and everything below).
      if ((w.servfail || []).some((z) => name === z || name.endsWith("." + z))) return json(200, { Status: 2 });
      // w.ns = {domain: [nameservers]} (answers type=NS), w.cname = {name: target}, w.wildcard = {zone: target}
      // (*.zone CNAME target, for names with no records of their own). A CNAME answer also carries the target's TXT.
      if (q.get("type") === "NS") {
        const ns = (w.ns || {})[name];
        return json(200, ns ? { Status: 0, Answer: ns.map((d) => ({ name, type: 2, data: d + "." })) } : { Status: 0 });
      }
      const wz = Object.keys(w.wildcard || {}).find((z) => name.endsWith("." + z));
      const target = (w.cname || {})[name] || (!recs && wz ? w.wildcard[wz] : null);
      if (target) {
        const tt = ((w.dns || {})[target] || []).map((d) => ({ name: target, type: 16, data: d }));
        return json(200, { Status: 0, Answer: [{ name, type: 5, data: target + "." }].concat(tt) });
      }
      return json(200, recs ? { Status: 0, Answer: recs.map((d) => ({ type: 16, data: d })) } : { Status: 0 });
    }
    if (u.pathname === "/.well-known/atproto-did") {
      const body = (w.wk || {})[u.host];
      // w.wk404 = hosts whose site answers this path with a 404 HTML error page.
      if ((w.wk404 || []).includes(u.host)) return Promise.resolve({ status: 404, text: () => Promise.resolve("<!doctype html><h1>Not found</h1>") });
      if (body === undefined || body === null) return Promise.reject(new TypeError("Failed to fetch"));
      return Promise.resolve({ status: 200, text: () => Promise.resolve(body) });
    }
    // w.plcLog = {did: [[createdAt, [handles], pdsUrl], ...]} answers /<did>/log/audit (oldest first, like the real one).
    if (u.host === "plc.directory" && u.pathname.endsWith("/log/audit")) {
      const lg = (w.plcLog || {})[u.pathname.split("/")[1]];
      return lg ? json(200, lg.map(([createdAt, aka, pds]) => ({ createdAt, nullified: false, operation: { type: "plc_operation",
        alsoKnownAs: aka.map((h) => "at://" + h), services: { atproto_pds: { type: "AtprotoPersonalDataServer", endpoint: pds } } } })))
        : json(404, { message: "DID not registered" });
    }
    if (u.host === "plc.directory") {
      const did = u.pathname.slice(1), aka = (w.docs || {})[did];
      return aka ? json(200, { id: did, alsoKnownAs: aka.map((h) => "at://" + h),
        service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer",
          serviceEndpoint: (w.pds || {})[did] || "https://pds.example.net" }] }) : json(404, {});
    }
    // w.hosts = {host: availableUserDomains} for hosting services (PDS); other hosts' describeServer fails.
    if (u.pathname.endsWith("describeServer")) {
      const d = (w.hosts || {})[u.host];
      return d ? json(200, { did: "did:web:" + u.host, availableUserDomains: d }) : Promise.reject(new TypeError("Failed to fetch"));
    }
    // w.relay = {host: accountCount}: hosts the Bluesky relay knows as PDSes (status "offline" even if up, like the real one).
    if (u.pathname.endsWith("getHostStatus")) {
      const hn = q.get("hostname"), n = (w.relay || {})[hn];
      return n !== undefined ? json(200, { hostname: hn, accountCount: n, seq: 1, status: "offline" }) :
        json(404, { error: "HostNotFound", message: "host not found" });
    }
    if (u.pathname.endsWith("resolveHandle")) {
      const did = (w.resolve || {})[q.get("handle")];
      return did ? json(200, { did }) : json(400, { error: "InvalidRequest", message: "Unable to resolve handle" });
    }
    if (u.pathname.endsWith("getProfile")) {
      const h = (w.profiles || {})[q.get("actor")];
      // w.profileErrors = {did: "AccountTakedown" | "AccountDeactivated"} (same shape as the real AppView's 400 answer)
      const pe = (w.profileErrors || {})[q.get("actor")];
      if (pe) return json(400, { error: pe, message: pe === "AccountTakedown" ? "Account has been suspended" : "Account is deactivated" });
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
t("hostedSuffix", () => {
  assert.strictEqual(H.hostedSuffix("alice.bsky.social", [".bsky.social"]), ".bsky.social");
  assert.strictEqual(H.hostedSuffix("alice.bsky.social", ["bsky.social"]), ".bsky.social");
  assert.strictEqual(H.hostedSuffix("bsky.social", [".bsky.social"]), null);
  assert.strictEqual(H.hostedSuffix("alice.notbsky.social", [".bsky.social"]), null);
  assert.strictEqual(H.hostedSuffix("alice.bsky.social", null), null);
  assert.strictEqual(H.hostedSuffix("alice.bsky.social", ["."]), null);
});
// Real case 2026-11-09: aurorashelf.northsky.social showed Invalid Handle; works via the host's .well-known.
t("hosted handle (PDS subdomain), ok: no DNS advice, re-save the name part", () => run("aurora.pds.example.net", {
  wk: { "aurora.pds.example.net": A }, docs: { [A]: ["aurora.pds.example.net"] }, profiles: { [A]: "aurora.pds.example.net" },
  hosts: { "pds.example.net": [".pds.example.net"] } })
  .then((r) => { assert.strictEqual(r.verdict.level, "ok"); assert.deepStrictEqual(r.hosted, { pds: "pds.example.net", suffix: ".pds.example.net" });
    const s = r.verdict.steps.join(" ");
    assert.match(s, /hosting service, which hands out names ending in \.pds\.example\.net \(your account lives on pds\.example\.net\)/); assert.match(s, /type aurora as the new handle/);
    assert.ok(!/well-known file only|I have my own domain|TXT/.test(s)); assert.match(s, /status\.bsky\.app/); }));
t("own domain on a PDS that hands out other names: normal advice", () => run("bob.example.org", { wk: { "bob.example.org": A + "\n" },
  docs: { [A]: ["bob.example.org"] }, profiles: { [A]: "bob.example.org" }, hosts: { "pds.example.net": [".pds.example.net"] } })
  .then((r) => { assert.strictEqual(r.hosted, null); const s = r.verdict.steps.join(" ");
    assert.match(s, /I have my own domain/); assert.match(s, /status\.bsky\.app/); }));
t("hosted name nobody uses: says renamed/moved, not 'add a TXT record'", () => run("gone.host.example.net", {
  hosts: { "host.example.net": [".host.example.net"] } })
  .then((r) => { assert.strictEqual(r.verdict.level, "bad"); assert.match(r.verdict.title, /No account uses gone\.host\.example\.net on host\.example\.net/);
    assert.ok(!/Add one: type TXT/.test(r.verdict.steps.join(" "))); }));
// Real hosts 2026-11-09: tweet.pub (Cloudflare 521), gonnakms.lol (no connection) are PDSes the relay knows, not answering.
t("hosting service down: says so, not 'add a TXT record'", () => run("amy.down.example.net", { relay: { "down.example.net": 19 } })
  .then((r) => { assert.strictEqual(r.verdict.level, "bad"); assert.match(r.verdict.title, /hosting service down\.example\.net is not answering/);
    const s = r.verdict.steps.join(" ");
    assert.match(s, /seen 19 accounts there/); assert.match(s, /no DNS record for you to add/);
    assert.ok(!/Add one: type TXT/.test(s)); }));
t("host answers but hands out other names: relay not asked, not 'down'", () => run("amy.up.example.net", {
  hosts: { "up.example.net": [".other.example"] }, relay: { "up.example.net": 5 } })
  .then((r) => { assert.strictEqual(r.parentHost, null); assert.doesNotMatch(r.verdict.title, /not answering/); }));
t("parent unknown to the relay: normal advice", () => run("amy.site.example.com", {})
  .then((r) => { assert.strictEqual(r.parentHost, null); assert.match(r.verdict.steps.join(" "), /Add one: type TXT/); }));
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
t("two records, one is a sibling account: keep the right one, move the other", () => run("news.com", {
  dns: { "_atproto.news.com": ['"did=' + A + '"', '"did=' + B + '"'] },
  docs: { [A]: ["news.com"], [B]: ["sports.news.com"] }, profiles: { [A]: "handle.invalid", [B]: "sports.news.com" } })
  .then((r) => { assert.strictEqual(r.verdict.level, "bad"); const s = r.verdict.steps.join(" | ");
    assert.match(s, new RegExp("Keep did=" + A)); assert.match(s, new RegExp("Remove did=" + B + ".*sports\\.news\\.com"));
    assert.match(s, /host\/name "_atproto\.sports" in the DNS panel for news\.com/); }));
// Real case 2026-11-11: the same two did= records also on the apex, and a wildcard *.news.com CNAME news.com (common on
// WordPress hosting) made _atproto.news.com.news.com "have" them too. That is not a typed-twice record.
t("two records + wildcard CNAME to apex: no 'typed twice' false alarm, apex copy is a harmless leftover", () => run("news.com", {
  dns: { "_atproto.news.com": ['"did=' + A + '"', '"did=' + B + '"'], "news.com": ['"v=spf1 -all"', '"did=' + A + '"', '"did=' + B + '"'],
    "_atproto.sports.news.com": ['"did=' + B + '"'] },
  wildcard: { "news.com": "news.com" },
  docs: { [A]: ["news.com"], [B]: ["sports.news.com"] } })
  .then((r) => { const s = r.verdict.steps.join(" | ");
    assert.ok(!/typed into a DNS panel/.test(s), s); assert.match(s, /also a did= record on news\.com itself.*does nothing/);
    assert.match(s, /already has its own record at _atproto\.sports\.news\.com/); assert.ok(!/host\/name "_atproto\.sports"/.test(s)); }));
t("sibling's own name only matches via the wildcard: still told where its record goes", () => run("news.com", {
  dns: { "_atproto.news.com": ['"did=' + A + '"', '"did=' + B + '"'], "news.com": ['"did=' + B + '"'] },
  wildcard: { "news.com": "news.com" }, docs: { [A]: ["news.com"], [B]: ["sports.news.com"] } })
  .then((r) => assert.match(r.verdict.steps.join(" "), /host\/name "_atproto\.sports" in the DNS panel for news\.com/)));
t("record on the apex only (none at _atproto): still told to move it", () => run("example.com", {
  dns: { "example.com": ['"did=' + A + '"'] } })
  .then((r) => assert.match(r.verdict.steps.join(" "), /It must be on _atproto\.example\.com/)));
t("two records on a subdomain handle: host field is relative to the registered domain", () => run("eu.news.com", {
  dns: { "_atproto.eu.news.com": ['"did=' + A + '"', '"did=' + B + '"'] },
  docs: { [A]: ["eu.news.com"], [B]: ["fr.eu.news.com"] } })
  .then((r) => assert.match(r.verdict.steps.join(" "), /host\/name "_atproto\.fr\.eu" in the DNS panel for news\.com/)));
t("two records, neither claims the handle: no guess", () => run("news.com", {
  dns: { "_atproto.news.com": ['"did=' + A + '"', '"did=' + B + '"'] }, docs: { [A]: ["a.bsky.social"], [B]: ["b.bsky.social"] } })
  .then((r) => { const s = r.verdict.steps.join(" "); assert.ok(!/Keep did=/.test(s)); assert.match(s, /can not say which to keep/); }));
// Real case 2026-11-12: the right record plus a mistyped copy ("did:plcL…", L where ":" should be).
t("good record + mistyped copy: delete the typo, keep the real one", () => {
  const typo = A.replace("did:plc:", "did:plcL");
  return run("news.com", { dns: { "_atproto.news.com": ['"did=' + A + '"', '"did=' + typo + '"'] }, docs: { [A]: ["news.com"] } })
    .then((r) => { const s = r.verdict.steps.join(" | ");
      assert.match(s, new RegExp("Delete did=" + typo + ".*mistyped copy of did=" + A));
      assert.match(s, new RegExp("Keep did=" + A + ".*claims news\\.com")); });
});
t("good record + broken one, good one claims something else: no 'keep'", () => run("news.com", {
  dns: { "_atproto.news.com": ['"did=' + A + '"', '"did=nonsense"'] }, docs: { [A]: ["other.bsky.social"] } })
  .then((r) => { const s = r.verdict.steps.join(" | "); assert.match(s, /Delete did=nonsense: that is not a valid DID\.$|Delete did=nonsense: that is not a valid DID, so it can never match an account\./);
    assert.ok(!/Keep did=/.test(s), s); assert.match(s, /claims other\.bsky\.social, not news\.com/); }));
t("two identical records: no per-DID lookup", () => run("news.com", {
  dns: { "_atproto.news.com": ['"did=' + A + '"', '"did=' + A + '"'] }, docs: { [A]: ["news.com"] } })
  .then((r) => { assert.strictEqual(r.dupes, null); assert.match(r.verdict.steps.join(" "), /identical/); }));
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
  .then((r) => { assert.strictEqual(r.verdict.level, "wait"); assert.match(r.verdict.title, /Half done/);
    assert.ok(!/bot check/.test(r.verdict.steps.join(" "))); }));
// Real case 2026-11-13: an itch.io subdomain handle; the browser reads .well-known, but the user's PDS got a Cloudflare challenge.
t("well-known only, not switched yet: warns that the server (not the browser) fetches it", () => run("me.games.example.org", {
  wk: { "me.games.example.org": A }, docs: { [A]: ["me.bsky.social"] }, profiles: { [A]: "me.bsky.social" } })
  .then((r) => { assert.strictEqual(r.verdict.level, "wait"); assert.strictEqual(r.didSource, "http");
    const s = r.verdict.steps.join(" ");
    assert.match(s, /your account's server \(pds\.example\.net\) that fetches it/); assert.match(s, /bot check/);
    assert.match(s, new RegExp('host/name "_atproto\\.me\\.games", value did=' + A)); }));
t("records right, Bluesky still shows handle.invalid", () => run("example.com", {
  dns: { "_atproto.example.com": ['"did=' + A + '"'] }, docs: { [A]: ["example.com"] }, profiles: { [A]: "handle.invalid" } })
  .then((r) => { assert.strictEqual(r.verdict.level, "wait"); assert.match(r.verdict.title, /handle\.invalid/); }));
// Real case 2026-11-10: a Bridgy Fed account got a new DID that took over the handle; Bluesky suspended the new one, so the
// old one (with the followers) showed "Invalid Handle" while both directions of the new one checked out.
t("records right but account suspended (bridged): says so, not 'wait'", () => run("band.music-host.net", {
  wk: { "band.music-host.net": B }, docs: { [B]: ["band.music-host.net"] }, profileErrors: { [B]: "AccountTakedown" },
  resolve: { "band.music-host.net": B } })
  .then((r) => { assert.strictEqual(r.verdict.level, "bad"); assert.match(r.verdict.title, /suspended/);
    const s = r.verdict.steps.join(" ");
    assert.match(s, /AccountTakedown/); assert.match(s, /older account/); assert.ok(!/Bridgy/.test(s)); }));
t("bridged + suspended mentions Bridgy Fed", () => run("band.music-host.net", {
  wk: { "band.music-host.net": B }, docs: { [B]: ["band.music-host.net"] }, profileErrors: { [B]: "AccountTakedown" },
  pds: { [B]: "https://atproto.brid.gy" } })
  .then((r) => { assert.strictEqual(r.pds, "https://atproto.brid.gy"); assert.match(r.verdict.steps.join(" "), /Bridgy Fed/); }));
t("records right but account deactivated", () => run("example.com", {
  dns: { "_atproto.example.com": ['"did=' + A + '"'] }, docs: { [A]: ["example.com"] }, profileErrors: { [A]: "AccountDeactivated" } })
  .then((r) => { assert.strictEqual(r.verdict.level, "bad"); assert.match(r.verdict.title, /deactivated/);
    assert.match(r.verdict.steps.join(" "), /Logging in to it again/); }));
t("profile simply missing: still the old 'wait' verdict", () => run("example.com", {
  dns: { "_atproto.example.com": ['"did=' + A + '"'] }, docs: { [A]: ["example.com"] } })
  .then((r) => { assert.strictEqual(r.verdict.level, "wait"); assert.strictEqual(r.profileError, null); }));
t("domain does not exist (expired): says renew, not 'add a record'", () => run("alice.gone-domain.net", { nx: ["gone-domain.net"] })
  .then((r) => { assert.strictEqual(r.verdict.level, "bad"); assert.match(r.verdict.title, /gone-domain\.net does not exist/);
    const s = r.verdict.steps.join(" ");
    assert.match(s, /expired/); assert.match(s, /host\/name "_atproto\.alice"/); assert.ok(!/No TXT record found/.test(s));
    assert.match(s, /If gone-domain\.net is not your own domain/); assert.match(s, /Settings, Account, Handle/); }));
// Real case 2026-11-19: lloolly.sysky.club, a name under a shared domain that went NXDOMAIN. Apex handles get no "not yours" step.
t("expired domain, handle IS the domain: no 'not your own domain' step", () => run("gone-domain.net", { nx: ["gone-domain.net"] })
  .then((r) => { assert.match(r.verdict.title, /does not exist/); assert.ok(!/not your own domain/.test(r.verdict.steps.join(" "))); }));
t("domain exists, no record: no expiry hint", () => run("nobody.example.com", {})
  .then((r) => { assert.ok(!/expired|does not exist/.test(r.verdict.title + r.verdict.steps.join(" "))); }));
// 2026-11-21: registered domain from the Public Suffix List, so co.uk / com.br / co.jp names are domains of their own.
t("regDomain knows two-label country suffixes", () => {
  assert.strictEqual(H.regDomain("alice.example.com"), "example.com");
  assert.strictEqual(H.regDomain("example.com"), "example.com");
  assert.strictEqual(H.regDomain("maria.com.br"), "maria.com.br");
  assert.strictEqual(H.regDomain("alice.maria.com.br"), "maria.com.br");
  assert.strictEqual(H.regDomain("shop.co.uk"), "shop.co.uk");
  assert.strictEqual(H.regDomain("a.b.example.co.jp"), "example.co.jp");
  assert.strictEqual(H.regDomain("me.example.com.au"), "example.com.au");
  assert.strictEqual(H.regDomain("alice.bsky.social"), "bsky.social");
  assert.strictEqual(H.regDomain("alice.github.io"), "github.io");  // private-section suffixes are left out on purpose
});
t("expired co.uk domain: names the domain itself, not co.uk", () => run("me.co.uk", { nx: ["me.co.uk"] })
  .then((r) => { assert.match(r.verdict.title, /me\.co\.uk does not exist/);
    const s = r.verdict.steps.join(" ");
    assert.match(s, /host\/name "_atproto"/); assert.ok(!/not your own domain/.test(s)); }));
t("com.br domain, no record: host/name _atproto, no 'not your own domain' step", () => run("maria.com.br", {})
  .then((r) => { const s = r.verdict.steps.join(" ");
    assert.match(s, /No TXT record found/); assert.match(s, /host\/name "_atproto",/);
    assert.ok(!/com\.br is not your own|panel is com\.br/.test(s)); assert.ok(!/not your own domain/.test(s)); }));
t("name under a com.br domain: zone is the domain, not com.br", () => run("blog.maria.com.br", {})
  .then((r) => { const s = r.verdict.steps.join(" ");
    assert.match(s, /host\/name "_atproto\.blog" \(if the domain in your DNS panel is maria\.com\.br\)/);
    assert.match(s, /If maria\.com\.br is not your own domain/); }));
t("record typed with the full name into a co.uk panel is found", () => run("shop.co.uk", {
  dns: { "_atproto.shop.co.uk.shop.co.uk": ['"did=' + A + '"'] } })
  .then((r) => { assert.strictEqual(r.misplaced.length, 1); assert.match(r.verdict.steps.join(" "), /host\/name field to just "_atproto"/); }));
t("expired domain but Bluesky still resolves it from cache: no expiry verdict", () => run("old-domain.net", { nx: ["old-domain.net"],
  resolve: { "old-domain.net": A } })
  .then((r) => { assert.strictEqual(r.didSource, "appview"); assert.ok(!/does not exist/.test(r.verdict.title)); }));
// Real case 2026-11-09: domain lapsed, now on a parking service's nameservers (exists, so no NXDOMAIN).
t("parked domain: says parked/expired, not 'add a record'", () => run("asunder.net", {
  ns: { "asunder.net": ["ns1.lander.d.parity.domains", "ns2.lander.d.parity.domains"] } })
  .then((r) => { assert.match(r.verdict.title, /asunder\.net looks parked/);
    const s = r.verdict.steps.join(" ");
    assert.match(s, /Parity/); assert.match(s, /host\/name "_atproto"/); assert.ok(!/No TXT record found/.test(s));
    assert.ok(!/not your own domain/.test(s)); }));
t("GoDaddy pending-deletion nameservers count as parked", () => run("me.old-site.com", {
  ns: { "old-site.com": ["NS1.PENDINGRENEWALDELETION.COM", "ns2.pendingrenewaldeletion.com"] } })
  .then((r) => { assert.match(r.verdict.title, /old-site\.com looks parked/); assert.match(r.verdict.steps[1], /"_atproto\.me"/);
    assert.match(r.verdict.steps.join(" "), /If old-site\.com is not your own domain/); }));
t("normal nameservers: normal advice, and lookalike names don't match", () => run("me.example.com", {
  ns: { "example.com": ["ns1.notdan.com", "a.iana-servers.net"] } })
  .then((r) => { assert.ok(!/parked/.test(r.verdict.title)); assert.match(r.verdict.steps.join(" "), /No TXT record found/); }));
// Real case 2026-11-22: mattckrause.com is registered (renewed 11-16) but its nameservers don't answer: SERVFAIL, not NXDOMAIN.
t("nameservers not answering (SERVFAIL): says DNS hosting, not 'add a record'", () => run("dead-dns.com", { servfail: ["dead-dns.com"] })
  .then((r) => { assert.strictEqual(r.verdict.level, "bad"); assert.match(r.verdict.title, /DNS servers for dead-dns\.com are not answering/);
    const s = r.verdict.steps.join(" ");
    assert.match(s, /SERVFAIL/); assert.match(s, /DNSSEC/); assert.match(s, /host\/name "_atproto"/);
    assert.ok(!/No TXT record found/.test(s)); assert.ok(!/not your own domain/.test(s)); }));
t("SERVFAIL on a shared domain: 'not your own domain' step", () => run("me.dead-dns.com", { servfail: ["dead-dns.com"] })
  .then((r) => { assert.match(r.verdict.title, /dead-dns\.com are not answering/);
    assert.match(r.verdict.steps.join(" "), /If dead-dns\.com is not your own domain/); }));
t("SERVFAIL but Bluesky still resolves it from cache: no SERVFAIL verdict", () => run("dead-dns.com", { servfail: ["dead-dns.com"],
  resolve: { "dead-dns.com": A } })
  .then((r) => { assert.strictEqual(r.didSource, "appview"); assert.ok(!/not answering/.test(r.verdict.title)); }));
t("well-known 404 with an HTML error page: 'no file here', not 'site builder sends home page'", () => run("example.com", {
  wk404: ["example.com"] })
  .then((r) => { assert.strictEqual(r.http.status, 404); assert.match(r.http.note, /no file at this address/);
    assert.ok(!/site builders/.test(r.http.note)); }));
t("well-known 404 on a GitHub Pages handle: no 'TXT record' wording", () => run("me.github.io", { wk404: ["me.github.io"] })
  .then((r) => { const s = r.verdict.steps.join(" ");
    assert.match(s, /HTTP 404, the file is not there \(yet\)/); assert.ok(!/fine if you use the TXT/.test(s)); }));
// Real case 2026-11-21: name under a live community domain, member's _atproto record gone.
t("no record on a subdomain of a live domain: says the owner manages it", () => run("me.example.com", {})
  .then((r) => { const s = r.verdict.steps.join(" ");
    assert.match(s, /No TXT record found/); assert.match(s, /If example\.com is not your own domain/); assert.match(s, /may have been removed/); }));
t("no record on an apex domain: no 'not your own domain' step", () => run("example.com", {})
  .then((r) => { const s = r.verdict.steps.join(" ");
    assert.match(s, /No TXT record found/); assert.ok(!/not your own domain/.test(s)); }));
// Real case 2026-11-23: digi.no / tu.no broke after a move to a new IT provider: no TXT, .well-known now 404s, DID doc still lists it.
t("no TXT + file 404: 'neither method', 'worked before' hint, no 'fine if you use TXT'", () => run("example.com", { wk404: ["example.com"] })
  .then((r) => { const s = r.verdict.steps.join(" ");
    assert.match(s, /No TXT record found/); assert.match(s, /neither method points to an account/);
    assert.match(s, /rebuilding the website or moving it to a new host/); assert.ok(!/fine if you use the TXT/.test(s));
    assert.ok(!/still lists/.test(s)); }));
t("no TXT + file 404 + DID given that still lists the handle: 'this worked before'", () => run("example.com",
  { wk404: ["example.com"], docs: { [A]: ["example.com"] } }, A)
  .then((r) => { assert.deepStrictEqual(r.expectedAka, ["example.com"]);
    assert.match(r.verdict.steps.join(" "), new RegExp("\\(" + A + "\\) still lists example\\.com")); }));
t("DID given that lists another handle: no 'still lists'", () => run("example.com", { docs: { [A]: ["me.bsky.social"] } }, A)
  .then((r) => { assert.ok(!/still lists/.test(r.verdict.steps.join(" "))); }));
t("TXT present but wrong: no 'neither method' / 'worked before' text", () => run("example.com",
  { dns: { "_atproto.example.com": ['"v=spf1 -all"'] }, wk404: ["example.com"] })
  .then((r) => { const s = r.verdict.steps.join(" ");
    assert.match(s, /none starts with "did="/); assert.ok(!/neither method|worked before/.test(s)); }));
// Real case 2026-11-21: armettebriard.neocities.org works through .well-known only; site hosts give no DNS access.
t("siteHost: known website hosts only, not their own apex", () => {
  assert.deepStrictEqual(H.siteHost("me.github.io"), { zone: "github.io", name: "GitHub Pages" });
  assert.strictEqual(H.siteHost("me.neocities.org").name, "Neocities");
  assert.strictEqual(H.siteHost("github.io"), null);
  assert.strictEqual(H.siteHost("me.example.com"), null);
});
t("github.io, no record: file method + .nojekyll, no TXT or 'owner' advice", () => run("me.github.io", {})
  .then((r) => { const s = r.verdict.steps.join(" ");
    assert.match(s, /GitHub Pages address/); assert.match(s, /No DNS Panel/); assert.match(s, /https:\/\/me\.github\.io\/\.well-known\/atproto-did/);
    assert.match(s, /include: \["\.well-known"\] to _config\.yml/); assert.ok(s.indexOf("_config.yml") < s.indexOf(".nojekyll"));
    assert.match(s, /\.nojekyll switches the build off/); assert.ok(!/No TXT record found|not your own domain|host\/name/.test(s)); }));
t("neocities, no record: file method, no GitHub-only step", () => run("me.neocities.org", {})
  .then((r) => { const s = r.verdict.steps.join(" ");
    assert.match(s, /Neocities address/); assert.ok(!/nojekyll|No TXT record found|not your own domain/.test(s)); }));
t("neocities, ok via well-known: file is the only option, no TXT advice", () => run("me.neocities.org", { wk: { "me.neocities.org": A },
  docs: { [A]: ["me.neocities.org"] }, profiles: { [A]: "me.neocities.org" } })
  .then((r) => { assert.strictEqual(r.verdict.level, "ok"); const s = r.verdict.steps.join(" ");
    assert.match(s, /On Neocities the file is the only option/); assert.ok(!/did=/.test(s)); }));
t("github.io, file there but not switched yet: no 'add a TXT record' fallback", () => run("me.github.io", { wk: { "me.github.io": A },
  docs: { [A]: ["me.bsky.social"] }, profiles: { [A]: "me.bsky.social" } })
  .then((r) => { const s = r.verdict.steps.join(" ");
    assert.match(s, /let \/\.well-known\/atproto-did through\./); assert.ok(!/add a TXT record/.test(s)); }));
t("parked domain but the handle still resolves: no parked verdict", () => run("cached.net", {
  ns: { "cached.net": ["ns1.sedoparking.com"] }, resolve: { "cached.net": A } })
  .then((r) => { assert.ok(!/parked/.test(r.verdict.title)); }));
// Real case 2026-11-09: *.fluffy.monster CNAME pixie.porkbun.com (registrar parking) swallowed _atproto.yuri.fluffy.monster.
t("wildcard CNAME on _atproto: explains it, exact TXT overrides it", () => run("yuri.fluffy.net", {
  wildcard: { "fluffy.net": "pixie.registrar.example" } })
  .then((r) => { assert.strictEqual(r.dns.cname, "pixie.registrar.example"); assert.strictEqual(r.dns.wildcard, true);
    const s = r.verdict.steps.join(" ");
    assert.match(s, /wildcard/); assert.match(s, /takes priority/); assert.match(s, /host\/name "_atproto\.yuri"/);
    assert.match(s, /fluffy\.net is not your own domain/); assert.ok(!/No TXT record found/.test(s)); }));
t("explicit CNAME on _atproto (no wildcard): says delete it", () => run("example.com", {
  cname: { "_atproto.example.com": "elsewhere.example.net" } })
  .then((r) => { assert.strictEqual(r.dns.wildcard, false);
    const s = r.verdict.steps.join(" ");
    assert.match(s, /Delete the CNAME/); assert.ok(!/wildcard/.test(s)); assert.ok(!/not your own domain/.test(s)); }));
t("CNAME to a name that has the did= record: resolves fine", () => run("example.com", {
  cname: { "_atproto.example.com": "_atproto.other.example" }, dns: { "_atproto.other.example": ['"did=' + A + '"'] },
  docs: { [A]: ["example.com"] }, profiles: { [A]: "example.com" }, resolve: { "example.com": A } })
  .then((r) => { assert.strictEqual(r.did, A); assert.strictEqual(r.verdict.level, "ok"); }));
t("bad syntax stops early", () => run("me.local", {}).then((r) => {
  assert.strictEqual(r.verdict.level, "bad"); assert.strictEqual(r.dns, undefined);
}));
t("empty input", () => run("  ", {}).then((r) => assert.strictEqual(r.verdict.level, "bad")));
t("underscore / space get named", () => {
  assert.match(H.validateHandle("my_brand.bsky.social"), /Underscores/);
  assert.match(H.validateHandle("my brand.bsky.social"), /Spaces/);
  assert.match(H.validateHandle("a&b.com"), /"&" is not/);
});
t("bsky.social 3-18 rule is a note, not an error", () => {
  assert.strictEqual(H.serviceNameNote("alice.bsky.social"), null);
  assert.strictEqual(H.serviceNameNote("abc.bsky.social"), null);            // 3 ok
  assert.strictEqual(H.serviceNameNote("a".repeat(18) + ".bsky.social"), null); // 18 ok
  assert.match(H.serviceNameNote("jo.bsky.social"), /only 2 characters/);
  assert.match(H.serviceNameNote("a".repeat(19) + ".bsky.social"), /19 characters/);
  assert.match(H.serviceNameNote("my.name.bsky.social"), /dot/);
  assert.strictEqual(H.serviceNameNote("bsky.social"), null);
  assert.strictEqual(H.serviceNameNote("jo.example.com"), null);
});
t("short bsky.social name still runs the live checks", () => run("jo.bsky.social", {}).then((r) => {
  assert.ok(r.dns !== undefined); assert.ok(r.inputNotes.some((s) => /3 to 18/.test(s)));
}));

// ---- account moved to another server (real case 2026-11-22: Blacksky move, "Invalid Handle" 7 minutes later) ----
t("plcHistory: last move, former handle; Bluesky-internal host changes are not a move", () => {
  const op = (at, aka, pds) => ({ createdAt: at, operation: { type: "plc_operation", alsoKnownAs: aka.map((x) => "at://" + x),
    services: { atproto_pds: { endpoint: pds } } } });
  const log = [op("2023-10-01T00:00:00Z", ["me.bsky.social"], "https://bsky.social"),
    op("2023-11-13T00:00:00Z", ["me.bsky.social"], "https://lionsmane.us-east.host.bsky.network"),
    op("2026-11-22T16:18:59Z", ["me.blacksky.app"], "https://blacksky.app")];
  const p = H.plcHistory(log, "me.bsky.social");
  assert.strictEqual(p.lastMove, "2026-11-22T16:18:59Z"); assert.strictEqual(p.former.until, "2026-11-22T16:18:59Z");
  assert.strictEqual(H.plcHistory(log.slice(0, 2), "me.bsky.social").lastMove, null);   // bsky.social -> lionsmane: Bluesky's own move
  assert.strictEqual(H.plcHistory(log, "me.blacksky.app").former, null);                // current handle is not "former"
  // legacy "create" op shape + nullified ops are handled
  assert.strictEqual(H.plcHistory([{ createdAt: "2023-01-01T00:00:00Z", operation: { type: "create", handle: "old.bsky.social",
    service: "https://bsky.social" } }, { createdAt: "2023-02-01T00:00:00Z", nullified: true, operation: { type: "plc_operation",
    alsoKnownAs: ["at://x.com"], services: { atproto_pds: { endpoint: "https://x.com" } } } }], "old.bsky.social").former, null);
});
const movedWorld = (extra) => Object.assign({
  wk: { "me.bsky.social": A }, docs: { [A]: ["me.blacksky.app"] }, pds: { [A]: "https://blacksky.app" },
  profiles: { [A]: "me.blacksky.app" }, hosts: { "blacksky.app": [".blacksky.app"] },
  plcLog: { [A]: [["2024-11-09T06:20:30Z", ["me.bsky.social"], "https://ganoderma.us-west.host.bsky.network"],
    ["2026-07-29T20:34:14Z", ["me.blacksky.app"], "https://blacksky.app"]] } }, extra || {});
t("old .bsky.social name after moving: 'old handle', no TXT / own-domain steps", () => run("me.bsky.social", movedWorld())
  .then((r) => { assert.strictEqual(r.verdict.level, "ok"); assert.match(r.verdict.title, /old handle.*me\.blacksky\.app/);
    const s = r.verdict.steps.join(" ");
    assert.match(s, /until 2026-07-29/); assert.match(s, /blacksky\.app/); assert.match(s, /does not take the name along/);
    assert.ok(!/TXT record/.test(s)); assert.ok(!/Half done/.test(r.verdict.title)); }));
t("old OWN domain after moving: explains how to take it back", () => run("me.example.com", movedWorld({
  wk: {}, dns: { "_atproto.me.example.com": ['"did=' + A + '"'] },
  plcLog: { [A]: [["2025-01-01T00:00:00Z", ["me.example.com"], "https://bsky.social"],
    ["2026-07-29T20:34:14Z", ["me.blacksky.app"], "https://blacksky.app"]] } }))
  .then((r) => { assert.match(r.verdict.title, /old handle/); assert.match(r.verdict.steps.join(" "), /want it back/); }));
t("switched away from own domain WITHOUT moving: still 'Half done', plus the history line", () => run("example.com", {
  dns: { "_atproto.example.com": ['"did=' + A + '"'] }, docs: { [A]: ["me.bsky.social"] }, profiles: { [A]: "me.bsky.social" },
  pds: { [A]: "https://lionsmane.us-east.host.bsky.network" },
  plcLog: { [A]: [["2024-01-01T00:00:00Z", ["example.com"], "https://bsky.social"],
    ["2026-01-01T00:00:00Z", ["me.bsky.social"], "https://lionsmane.us-east.host.bsky.network"]] } })
  .then((r) => { assert.match(r.verdict.title, /Half done/); assert.match(r.verdict.steps.join(" "), /used example\.com until 2026-01-01/); }));
t("new handle minutes after a move: 'moved N minutes ago' note", () => {
  const at = new Date(Date.now() - 7 * 60000).toISOString();
  return run("me.blacksky.app", movedWorld({ wk: { "me.blacksky.app": A },
    plcLog: { [A]: [["2024-11-09T06:20:30Z", ["me.bsky.social"], "https://bsky.social"], [at, ["me.blacksky.app"], "https://blacksky.app"]] } }))
    .then((r) => { assert.strictEqual(r.verdict.level, "ok"); assert.match(r.verdict.steps.join(" "), /moved to blacksky\.app 7 minutes ago/); });
});
t("new handle, move long ago: no move note", () => run("me.blacksky.app", movedWorld({ wk: { "me.blacksky.app": A } }))
  .then((r) => { assert.strictEqual(r.verdict.level, "ok"); assert.ok(!/moved to/.test(r.verdict.steps.join(" "))); }));
t("AppView still shows handle.invalid right after a move: wait + move note", () => {
  const at = new Date(Date.now() - 3 * 3600000).toISOString();
  return run("me.blacksky.app", movedWorld({ wk: { "me.blacksky.app": A }, profiles: { [A]: "handle.invalid" },
    plcLog: { [A]: [["2024-11-09T06:20:30Z", ["me.bsky.social"], "https://bsky.social"], [at, ["me.blacksky.app"], "https://blacksky.app"]] } }))
    .then((r) => { assert.strictEqual(r.verdict.level, "wait"); assert.match(r.verdict.steps.join(" "), /3 hours ago/); });
});

Promise.all(pending).then(() => console.log("\n" + n + " tests passed"), (e) => { console.error(e); process.exit(1); });
