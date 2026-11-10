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
      if (body === undefined || body === null) return Promise.reject(new TypeError("Failed to fetch"));
      return Promise.resolve({ status: 200, text: () => Promise.resolve(body) });
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
    assert.ok(!/well-known file only|I have my own domain|TXT/.test(s)); }));
t("own domain on a PDS that hands out other names: normal advice", () => run("bob.example.org", { wk: { "bob.example.org": A + "\n" },
  docs: { [A]: ["bob.example.org"] }, profiles: { [A]: "bob.example.org" }, hosts: { "pds.example.net": [".pds.example.net"] } })
  .then((r) => { assert.strictEqual(r.hosted, null); assert.match(r.verdict.steps.join(" "), /I have my own domain/); }));
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
t("two records on a subdomain handle: host field is relative to the registered domain", () => run("eu.news.com", {
  dns: { "_atproto.eu.news.com": ['"did=' + A + '"', '"did=' + B + '"'] },
  docs: { [A]: ["eu.news.com"], [B]: ["fr.eu.news.com"] } })
  .then((r) => assert.match(r.verdict.steps.join(" "), /host\/name "_atproto\.fr\.eu" in the DNS panel for news\.com/)));
t("two records, neither claims the handle: no guess", () => run("news.com", {
  dns: { "_atproto.news.com": ['"did=' + A + '"', '"did=' + B + '"'] }, docs: { [A]: ["a.bsky.social"], [B]: ["b.bsky.social"] } })
  .then((r) => { const s = r.verdict.steps.join(" "); assert.ok(!/Keep did=/.test(s)); assert.match(s, /can not say which to keep/); }));
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
  .then((r) => { assert.strictEqual(r.verdict.level, "wait"); assert.match(r.verdict.title, /Half done/); }));
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
    assert.match(s, /expired/); assert.match(s, /host\/name "_atproto\.alice"/); assert.ok(!/No TXT record found/.test(s)); }));
t("domain exists, no record: no expiry hint", () => run("nobody.example.com", {})
  .then((r) => { assert.ok(!/expired|does not exist/.test(r.verdict.title + r.verdict.steps.join(" "))); }));
t("co.uk-style name: apex guess exists, falls back to the normal advice", () => run("me.co.uk", { nx: ["me.co.uk"] })
  .then((r) => { assert.strictEqual(r.verdict.level, "bad"); assert.ok(!/expired/.test(r.verdict.steps.join(" "))); }));
t("expired domain but Bluesky still resolves it from cache: no expiry verdict", () => run("old-domain.net", { nx: ["old-domain.net"],
  resolve: { "old-domain.net": A } })
  .then((r) => { assert.strictEqual(r.didSource, "appview"); assert.ok(!/does not exist/.test(r.verdict.title)); }));
// Real case 2026-11-09: domain lapsed, now on a parking service's nameservers (exists, so no NXDOMAIN).
t("parked domain: says parked/expired, not 'add a record'", () => run("asunder.net", {
  ns: { "asunder.net": ["ns1.lander.d.parity.domains", "ns2.lander.d.parity.domains"] } })
  .then((r) => { assert.match(r.verdict.title, /asunder\.net looks parked/);
    const s = r.verdict.steps.join(" ");
    assert.match(s, /Parity/); assert.match(s, /host\/name "_atproto"/); assert.ok(!/No TXT record found/.test(s)); }));
t("GoDaddy pending-deletion nameservers count as parked", () => run("me.old-site.com", {
  ns: { "old-site.com": ["NS1.PENDINGRENEWALDELETION.COM", "ns2.pendingrenewaldeletion.com"] } })
  .then((r) => { assert.match(r.verdict.title, /old-site\.com looks parked/); assert.match(r.verdict.steps[1], /"_atproto\.me"/); }));
t("normal nameservers: normal advice, and lookalike names don't match", () => run("me.example.com", {
  ns: { "example.com": ["ns1.notdan.com", "a.iana-servers.net"] } })
  .then((r) => { assert.ok(!/parked/.test(r.verdict.title)); assert.match(r.verdict.steps.join(" "), /No TXT record found/); }));
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

Promise.all(pending).then(() => console.log("\n" + n + " tests passed"), (e) => { console.error(e); process.exit(1); });
