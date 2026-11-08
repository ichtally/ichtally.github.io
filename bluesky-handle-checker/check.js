// Bluesky custom-domain handle checker. Runs in the browser (and in node for tests).
// Resolution rules follow @atproto/identity HandleResolver (packages/identity/src/handle/index.ts):
//   DNS TXT at _atproto.<handle>: join each record's chunks, keep those starting with "did=",
//   exactly one must remain (two or more = ambiguous = no answer). DNS wins over HTTP.
//   HTTPS GET https://<handle>/.well-known/atproto-did: first line, trimmed, must start with "did:".
// Syntax rules follow @atproto/syntax handle.ts (ensureValidHandle + DISALLOWED_TLDS) and did.ts.
// Made by Tally (an AI agent). MIT.
(function (root) {
  'use strict';

  var DISALLOWED_TLDS = ['.local', '.arpa', '.invalid', '.localhost', '.internal', '.example', '.alt', '.onion'];
  var DID_REGEX = /^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$/;

  function isValidDid(s) { return typeof s === 'string' && s.length <= 2048 && DID_REGEX.test(s); }

  // Turn what people paste ("@Alice.Example.com", "https://alice.example.com/") into a handle.
  function normalizeInput(raw) {
    var s = String(raw || '').trim();
    s = s.replace(/^@/, '').replace(/^[a-z]+:\/\//i, '').replace(/[\/?#].*$/, '').replace(/\.$/, '');
    s = s.toLowerCase();
    var notes = [];
    if (/[^\x00-\x7f]/.test(s)) {
      try {
        var puny = new URL('http://' + s).hostname;
        if (puny && puny !== s) { notes.push('Non-ASCII domain: handles use the punycode form, ' + puny + '.'); s = puny; }
      } catch (e) { /* leave as is; validation will explain */ }
    }
    return { handle: s, notes: notes };
  }

  // Same checks and order as ensureValidHandle, plus the registration-time TLD block list.
  function validateHandle(h) {
    if (!/^[a-zA-Z0-9.-]*$/.test(h)) return 'Only ASCII letters, digits, dashes and dots are allowed in a handle.';
    if (h.length > 253) return 'Too long (253 characters max).';
    var labels = h.split('.');
    if (labels.length < 2) return 'A handle needs at least two parts, like example.com.';
    for (var i = 0; i < labels.length; i++) {
      var l = labels[i];
      if (l.length < 1) return 'Empty part (two dots in a row, or a dot at the start).';
      if (l.length > 63) return 'One part is longer than 63 characters.';
      if (l[0] === '-' || l[l.length - 1] === '-') return 'Parts can not start or end with a hyphen ("' + l + '").';
      if (i + 1 === labels.length && !/^[a-zA-Z]/.test(l)) return 'The last part (TLD) must start with a letter.';
    }
    for (var j = 0; j < DISALLOWED_TLDS.length; j++) {
      if (h.endsWith(DISALLOWED_TLDS[j])) return DISALLOWED_TLDS[j] + ' domains can not be used as Bluesky handles.';
    }
    return null;
  }

  // DoH JSON "data" for TXT. Cloudflare: "\"did=...\"" (quoted chunks, maybe several: "a" "b").
  // Google: unquoted. Returns the record as the resolver sees it (chunks joined).
  function parseTxtData(data) {
    data = String(data);
    if (data[0] !== '"') return data;
    var out = '', i = 0, inQ = false;
    while (i < data.length) {
      var c = data[i];
      if (!inQ) { if (c === '"') inQ = true; i++; continue; }
      if (c === '"') { inQ = false; i++; continue; }
      if (c === '\\' && i + 1 < data.length) {
        var m = /^\d{3}/.exec(data.slice(i + 1));
        if (m) { out += String.fromCharCode(parseInt(m[0], 10)); i += 4; continue; }
        out += data[i + 1]; i += 2; continue;
      }
      out += c; i++;
    }
    return out;
  }

  // Exactly what HandleResolver.parseDnsResult does, plus reasons when it gives no answer.
  function pickDid(records) {
    var found = records.filter(function (r) { return r.indexOf('did=') === 0; });
    var notes = [];
    if (found.length === 1) {
      var did = found[0].slice(4);
      if (!isValidDid(did)) {
        notes.push('The record is "' + found[0] + '", but "' + did + '" is not a valid DID' +
          (did !== did.trim() ? ' (it has spaces around it; remove them).' :
            /^did:/.test(did) ? '.' : ' (it should look like did:plc:abc123...).'));
      }
      return { did: did, valid: isValidDid(did), notes: notes };
    }
    if (found.length > 1) {
      var same = found.every(function (r) { return r === found[0]; });
      notes.push('There are ' + found.length + ' "did=" records. Bluesky treats that as ambiguous and ignores ALL of them' +
        (same ? ' (even though they are identical).' : '.') + ' Delete all but one.');
      var all = [];
      found.forEach(function (r) { var d = r.slice(4); if (all.indexOf(d) < 0) all.push(d); });
      return { did: null, valid: false, notes: notes, all: all };
    }
    records.forEach(function (r) {
      var t = r.trim();
      if (t.indexOf('did=') === 0) notes.push('"' + r + '" has spaces before "did=". Remove them.');
      else if (/^did\s*=/i.test(t)) notes.push('"' + r + '": the prefix must be exactly lower-case "did=" with no spaces.');
      else if (/^did:/.test(t)) notes.push('"' + r + '" is missing the "did=" prefix. The value must be did=' + t + '.');
      else if (t.indexOf('did=') > 0) notes.push('"' + r + '" must START with "did=". Remove what comes before it.');
    });
    return { did: null, valid: false, notes: notes };
  }

  // What the resolver does with the body of /.well-known/atproto-did.
  function parseWellKnown(text) {
    var first = String(text).split('\n')[0].trim();
    if (first.indexOf('did:') === 0) return { did: first, note: isValidDid(first) ? null : '"' + first + '" is not a valid DID.' };
    var note = /^\s*</.test(text) ? 'The URL returns an HTML page, not a DID. Many site builders send every unknown path to the home page.' :
      first ? 'The first line is "' + first.slice(0, 80) + '", which does not start with "did:".' : 'The file is empty.';
    return { did: null, note: note };
  }

  // Does the DID document claim this handle? (The second half of the two-way check.)
  function akaHandles(doc) {
    return ((doc && doc.alsoKnownAs) || []).filter(function (a) { return /^at:\/\//.test(a); })
      .map(function (a) { return a.slice(5).toLowerCase(); });
  }
  function pdsOf(doc) {
    var s = ((doc && doc.service) || []).filter(function (x) { return /#atproto_pds$/.test(x.id) || x.type === 'AtprotoPersonalDataServer'; })[0];
    return s ? s.serviceEndpoint : null;
  }

  function didDocUrl(did) {
    if (/^did:plc:/.test(did)) return 'https://plc.directory/' + did;
    if (/^did:web:/.test(did)) return 'https://' + decodeURIComponent(did.slice(8)) + '/.well-known/did.json';
    return null;
  }

  // ---- network (fetchFn injectable for tests) ----
  function getJson(fetchFn, url, headers) {
    return fetchFn(url, { headers: headers || {} }).then(function (r) {
      return r.json().then(function (j) { return { status: r.status, json: j }; });
    });
  }

  function doh(fetchFn, name) {
    var q = 'name=' + encodeURIComponent(name) + '&type=TXT';
    function shape(res) {
      var j = res.json || {};
      var txt = (j.Answer || []).filter(function (a) { return a.type === 16; }).map(function (a) { return parseTxtData(a.data); });
      return { rcode: j.Status, txt: txt };
    }
    return getJson(fetchFn, 'https://cloudflare-dns.com/dns-query?' + q, { accept: 'application/dns-json' }).then(shape)
      .catch(function () { return getJson(fetchFn, 'https://dns.google/resolve?' + q).then(shape); })
      .catch(function () { return { rcode: null, txt: [], error: 'DNS lookup failed (both Cloudflare and Google DNS-over-HTTPS).' }; });
  }

  function wellKnown(fetchFn, h) {
    return fetchFn('https://' + h + '/.well-known/atproto-did', {}).then(function (r) {
      return r.text().then(function (t) {
        var p = parseWellKnown(t);
        if (r.status !== 200) p.note = 'HTTP ' + r.status + '. ' + (p.did ? '' : p.note);
        return { reached: true, status: r.status, did: p.did, note: p.note };
      });
    }, function () {
      return { reached: false, did: null, note: 'Your browser could not read it. Usually the site just does not allow ' +
        'cross-site reads (normal, and Bluesky does not care), or the domain has no website.' };
    });
  }

  var API = 'https://public.api.bsky.app/xrpc/';

  function check(rawInput, rawExpected, fetchFn) {
    fetchFn = fetchFn || root.fetch.bind(root);
    var n = normalizeInput(rawInput);
    var h = n.handle;
    var rep = { handle: h, inputNotes: n.notes, syntaxError: validateHandle(h) };
    if (!h) { rep.syntaxError = 'Type a handle, like alice.example.com.'; }
    if (rep.syntaxError) { rep.verdict = verdict(rep); return Promise.resolve(rep); }

    // Common mistake: full name typed into a panel that appends the zone -> _atproto.<h>.<zone>.
    var labels = h.split('.');
    var zones = [h];
    if (labels.length > 2) zones.push(labels.slice(-2).join('.'));

    var expectedP = Promise.resolve(null);
    var ex = normalizeInput(rawExpected).handle;
    if (ex) {
      expectedP = /^did:/.test(ex) ? Promise.resolve({ did: String(rawExpected).trim(), from: 'did' }) :
        getJson(fetchFn, API + 'com.atproto.identity.resolveHandle?handle=' + encodeURIComponent(ex))
          .then(function (r) { return { did: r.json.did || null, from: ex }; }, function () { return { did: null, from: ex }; });
    }

    return Promise.all([
      doh(fetchFn, '_atproto.' + h),
      wellKnown(fetchFn, h),
      getJson(fetchFn, API + 'com.atproto.identity.resolveHandle?handle=' + encodeURIComponent(h))
        .then(function (r) { return { did: r.json.did || null, message: r.json.message || null }; },
          function () { return { did: null, message: 'Request failed.' }; }),
      expectedP
    ]).then(function (res) {
      rep.dns = res[0]; rep.dns.pick = pickDid(rep.dns.txt);
      rep.http = res[1]; rep.appview = res[2]; rep.expected = res[3];
      // DNS first, then HTTP: same order as the official resolver.
      rep.did = rep.dns.pick.did || rep.http.did || null;
      rep.didSource = rep.dns.pick.did ? 'dns' : rep.http.did ? 'http' : null;
      if (!rep.did && rep.appview.did) { rep.did = rep.appview.did; rep.didSource = 'appview'; }
      var extra = [];
      if (!rep.dns.pick.did) {
        extra = zones.map(function (z) {
          var name = '_atproto.' + h + '.' + z;
          return doh(fetchFn, name).then(function (d) { return { name: name, zone: z, d: d }; });
        });
        extra.push(doh(fetchFn, h).then(function (d) { return { name: h, zone: null, d: d }; }));
        // Does the domain exist at all? NXDOMAIN on the registered name (RFC 8020: nothing below it exists either)
        // almost always means it expired. Last two labels is a guess; for co.uk-style names it asks "co.uk",
        // which exists, so the worst case is a missed hint, never a false one.
        var apex = labels.slice(-2).join('.');
        extra.push(doh(fetchFn, apex).then(function (d) { rep.apex = { name: apex, rcode: d.rcode }; return { name: apex, zone: null, d: { txt: [] } }; }));
      }
      // Several different did= records: find out whose each one is. Typical case: an organisation with a second
      // account (e.g. a sports or language desk) added that account's record at the main name.
      var dupesP = Promise.resolve(null);
      var all = (rep.dns.pick.all || []).filter(isValidDid);
      if (all.length > 1) {
        dupesP = Promise.all(all.map(function (did) {
          var url = didDocUrl(did);
          return Promise.all([
            url ? getJson(fetchFn, url).then(function (r) { return r.status === 200 ? r.json : null; }, function () { return null; }) : null,
            getJson(fetchFn, API + 'app.bsky.actor.getProfile?actor=' + encodeURIComponent(did))
              .then(function (r) { return r.json && r.json.handle ? r.json : null; }, function () { return null; })
          ]).then(function (x) {
            return { did: did, aka: x[0] ? akaHandles(x[0]) : null, displayName: x[1] ? (x[1].displayName || '') : '' };
          });
        }));
      }
      return Promise.all([Promise.all(extra), dupesP]).then(function (x) { rep.dupes = x[1]; return x[0]; });
    }).then(function (misplaced) {
      rep.misplaced = misplaced.filter(function (m) {
        return m.d.txt.some(function (t) { return /did[=:]/i.test(t); });
      }).map(function (m) { return { name: m.name, zone: m.zone, txt: m.d.txt.filter(function (t) { return /did[=:]/i.test(t); }) }; });
      if (!rep.did || !isValidDid(rep.did)) return null;
      var url = didDocUrl(rep.did);
      return Promise.all([
        url ? getJson(fetchFn, url).then(function (r) { return r.status === 200 ? r.json : null; }, function () { return null; }) : null,
        getJson(fetchFn, API + 'app.bsky.actor.getProfile?actor=' + encodeURIComponent(rep.did))
          .then(function (r) { return r.json && r.json.handle ? r.json : null; }, function () { return null; })
      ]);
    }).then(function (docs) {
      if (docs) {
        rep.doc = docs[0]; rep.aka = akaHandles(docs[0]); rep.pds = pdsOf(docs[0]);
        rep.profile = docs[1] ? { handle: docs[1].handle, displayName: docs[1].displayName || '' } : null;
      }
      rep.verdict = verdict(rep);
      return rep;
    });
  }

  // Host/name to type in a DNS panel whose zone is `zone`: "_atproto" for the apex, "_atproto.alice" for alice.<zone>.
  function hostField(h, zone) {
    var full = '_atproto.' + h;
    return full.slice(0, full.length - zone.length - 1);
  }

  // Which of several did= records to keep, and where the others belong.
  function dupeSteps(r) {
    var d = r.dupes || [];
    if (d.length < 2) return [];
    var keep = d.filter(function (x) { return x.aka && x.aka.indexOf(r.handle) >= 0; });
    var who = function (x) { return x.did + (x.displayName ? ' ("' + x.displayName + '")' : ''); };
    if (keep.length !== 1) {
      return d.map(function (x) {
        return 'did=' + who(x) + ': ' + (x.aka ? 'claims ' + (x.aka.join(', ') || 'no handle') + '.' : 'could not load its DID document.');
      }).concat(['None of them (or more than one) claims ' + r.handle + ', so the record list alone can not say which to keep. ' +
        'Keep the DID of the account that should have this handle.']);
    }
    var out = ['Keep did=' + keep[0].did + ': that account' + (keep[0].displayName ? ' ("' + keep[0].displayName + '")' : '') +
      ' is the one that claims ' + r.handle + ' as its handle.'];
    d.forEach(function (x) {
      if (x === keep[0]) return;
      var h = x.aka && x.aka[0];
      var s = 'Remove did=' + x.did + ' from _atproto.' + r.handle + ': it is a different account' +
        (x.displayName ? ' ("' + x.displayName + '")' : '') + (h ? ', which uses ' + h : '') + '.';
      if (h && h !== r.handle && h.slice(-(r.handle.length + 1)) === '.' + r.handle) {
        var zone = r.handle.split('.').slice(-2).join('.');
        s += ' Its own record goes at _atproto.' + h + ' (host/name "' + hostField(h, zone) + '" in the DNS panel for ' + zone +
          '), not here.';
      }
      out.push(s);
    });
    return out;
  }

  // level: ok | wait | bad. steps: what to do next.
  function verdict(r) {
    if (r.syntaxError) return { level: 'bad', title: 'Not a valid handle', steps: [r.syntaxError] };
    var steps = [];
    if (r.dns.error) steps.push(r.dns.error);
    if (!r.did) {
      if (r.apex && r.apex.rcode === 3) {
        return { level: 'bad', title: 'The domain ' + r.apex.name + ' does not exist right now',
          steps: steps.concat(['DNS answers "no such domain" (NXDOMAIN) for ' + r.apex.name + ', so there is nothing for Bluesky to check. ' +
            'Check the spelling first. If it is right, the registration has most likely expired: check it at your registrar ' +
            '(or with a WHOIS lookup) and renew it.',
          'After renewing, it can take a few hours for the domain to come back. If the _atproto TXT record is gone, add it again: ' +
            'host/name "' + hostField(r.handle, r.apex.name) + '", value "did=" followed by your DID. Then re-verify the handle in the app.']) };
      }
      steps = steps.concat(r.dns.pick.notes);
      steps = steps.concat(dupeSteps(r));
      (r.misplaced || []).forEach(function (m) {
        if (m.name === r.handle) steps.push('Found a DID record on ' + m.name + ' itself. It must be on _atproto.' + r.handle +
          ' (in most DNS panels: host/name "_atproto", type TXT).');
        else steps.push('Found the record at ' + m.name + ': the full name was typed into a DNS panel that adds "' + m.zone +
          '" by itself. Set the host/name field to just "' + hostField(r.handle, m.zone) + '".');
      });
      if (!(r.misplaced || []).length && !r.dns.pick.notes.length) {
        steps.push(r.dns.txt.length ? 'There are TXT records on _atproto.' + r.handle + ', but none starts with "did=".' :
          'No TXT record found at _atproto.' + r.handle + '. Add one: type TXT, host/name "' +
          hostField(r.handle, r.handle.split('.').slice(-2).join('.')) + '"' +
          (r.handle.split('.').length > 2 ? ' (if the domain in your DNS panel is ' + r.handle.split('.').slice(-2).join('.') + ')' : '') +
          ', value "did=" followed by your DID. DNS changes can take a few minutes to an hour to show up.');
        if (r.http.reached) steps.push('/.well-known/atproto-did: ' + r.http.note);
      }
      return { level: 'bad', title: 'Bluesky can not find an account for ' + r.handle, steps: steps };
    }
    if (!isValidDid(r.did)) return { level: 'bad', title: 'The record is there but the DID in it is broken', steps: steps.concat(r.dns.pick.notes) };
    if (r.dns.pick.did && r.http.did && r.dns.pick.did !== r.http.did) {
      steps.push('DNS says ' + r.dns.pick.did + ' but /.well-known/atproto-did says ' + r.http.did + '. DNS wins; fix or remove the other one.');
    }
    if (r.expected && r.expected.did && r.expected.did !== r.did) {
      return { level: 'bad', title: r.handle + ' points to a different account than ' + r.expected.from,
        steps: steps.concat(['The record points to ' + r.did + ', but ' + r.expected.from + ' is ' + r.expected.did +
          '. Replace the value with did=' + r.expected.did + '.']) };
    }
    if (r.didSource === 'appview') steps.push('No DNS record found; Bluesky\'s servers resolve it another way (most likely ' +
      'https://' + r.handle + '/.well-known/atproto-did, which your browser could not read).');
    if (r.appview.did && r.appview.did !== r.did) steps.push('Bluesky\'s public API still returns ' + r.appview.did +
      ' for this name (cached or not yet updated). Give it some time.');
    var claimed = (r.aka || []).indexOf(r.handle) >= 0;
    if (!r.doc) {
      return { level: 'wait', title: r.handle + ' points to ' + r.did, steps: steps.concat(['Could not load the DID document to finish the check.']) };
    }
    if (!claimed) {
      return { level: 'wait', title: 'Half done: the domain points to the account, but the account has not switched to it',
        steps: steps.concat(['The account currently claims: ' + ((r.aka || []).join(', ') || 'no handle') + '.',
          'Finish in the Bluesky app: change your handle, choose the option for your own domain, enter ' + r.handle + ' and verify.']) };
    }
    if (r.profile && r.profile.handle === r.handle) {
      if (r.didSource === 'http') steps.push('This handle works through the .well-known file only. That is allowed, but if the ' +
        'website is down or slow when Bluesky re-checks, the handle shows as invalid until the next check. A DNS TXT record ' +
        '(_atproto, value did=' + r.did + ') does not depend on the website.');
      steps.push('Still seeing "Invalid Handle" in the app? Then the setup is fine right now and an earlier check failed. ' +
        'To force a fresh check: Settings, Account, Handle, "I have my own domain", enter ' + r.handle + ', verify, then "Update to ' +
        r.handle + '".');
      return { level: 'ok', title: 'All good: ' + r.handle + ' is a working Bluesky handle', steps: steps };
    }
    var shown = r.profile ? r.profile.handle : '(profile not found)';
    return { level: 'wait', title: 'Your records are right; Bluesky shows "' + shown + '" for now',
      steps: steps.concat([shown === 'handle.invalid' ?
        'Both directions check out now, so Bluesky\'s cached result is stale. It re-checks on its own; saving the handle again in the app usually forces it.' :
        'Both directions check out. Bluesky\'s view updates shortly after a handle change.']) };
  }

  var api = { normalizeInput: normalizeInput, validateHandle: validateHandle, parseTxtData: parseTxtData, pickDid: pickDid,
    parseWellKnown: parseWellKnown, hostField: hostField, akaHandles: akaHandles, pdsOf: pdsOf, didDocUrl: didDocUrl, isValidDid: isValidDid,
    check: check, verdict: verdict };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.HandleCheck = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
