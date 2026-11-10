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

  function dnsName(s) { return String(s || '').replace(/\.$/, '').toLowerCase(); }

  // Nameservers of domain parking / marketplace services, and GoDaddy's "expired, pending deletion" servers.
  // A domain served by these is not pointing at anyone's own DNS any more. Kept short on purpose: only names checked
  // to exist, and only services whose whole job is parked or for-sale domains.
  var PARKING = {
    'pendingrenewaldeletion.com': 'GoDaddy (expired domain)', 'sedoparking.com': 'Sedo', 'parkingcrew.net': 'ParkingCrew',
    'above.com': 'Above.com', 'dan.com': 'Dan.com', 'afternic.com': 'Afternic', 'hugedomains.com': 'HugeDomains',
    'parity.domains': 'Parity'
  };
  function parkingOf(ns) {
    for (var i = 0; i < ns.length; i++) {
      for (var k in PARKING) if (ns[i] === k || ns[i].slice(-(k.length + 1)) === '.' + k) return PARKING[k];
    }
    return null;
  }

  // type: 'TXT' (default) or 'NS'. Also reports a CNAME sitting on `name` itself (a name with a CNAME can't
  // have a TXT record of its own; resolvers follow the alias instead).
  function doh(fetchFn, name, type) {
    var q = 'name=' + encodeURIComponent(name) + '&type=' + (type || 'TXT');
    function shape(res) {
      var j = res.json || {}, ans = j.Answer || [];
      var txt = ans.filter(function (a) { return a.type === 16; }).map(function (a) { return parseTxtData(a.data); });
      var ns = ans.filter(function (a) { return a.type === 2; }).map(function (a) { return dnsName(a.data); });
      var c = ans.filter(function (a) { return a.type === 5 && dnsName(a.name) === dnsName(name); })[0];
      return { rcode: j.Status, txt: txt, ns: ns, cname: c ? dnsName(c.data) : null };
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

  // Handles like alice.bsky.social are handed out by a hosting service (PDS). Its describeServer lists the domains it
  // gives out ("availableUserDomains", e.g. ".bsky.social"); the service answers for those names, not the user's DNS.
  function userDomains(fetchFn, base) {
    return getJson(fetchFn, String(base).replace(/\/+$/, '') + '/xrpc/com.atproto.server.describeServer').then(function (r) {
      var d = r.status === 200 && r.json && r.json.availableUserDomains;
      return Array.isArray(d) ? d : null;
    }, function () { return null; });
  }
  function hostedSuffix(h, domains) {
    var s = (domains || []).map(function (d) {
      d = String(d).toLowerCase();
      return d.charAt(0) === '.' ? d : '.' + d;
    }).filter(function (d) { return d.length > 1 && h.length > d.length && h.slice(-d.length) === d; });
    return s[0] || null;
  }
  // Has the Bluesky relay ever crawled this hostname as a PDS? 404 HostNotFound = no. Sends ACAO *.
  var RELAY = 'https://relay1.us-east.bsky.network/xrpc/';
  function hostKnown(fetchFn, host) {
    return getJson(fetchFn, RELAY + 'com.atproto.sync.getHostStatus?hostname=' + encodeURIComponent(host)).then(function (r) {
      return r.status === 200 && r.json && dnsName(r.json.hostname) === dnsName(host) ? r.json : null;
    }, function () { return null; });
  }
  function hostName(url) { return String(url || '').replace(/^https?:\/\//, '').replace(/[\/:].*$/, ''); }

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
        // Asking for NS also shows where the domain is hosted: parking / for-sale nameservers mean it lapsed or was sold.
        var apex = labels.slice(-2).join('.');
        extra.push(doh(fetchFn, apex, 'NS').then(function (d) {
          rep.apex = { name: apex, rcode: d.rcode, ns: d.ns || [], parked: parkingOf(d.ns || []) };
          return { name: apex, zone: null, d: { txt: [] } };
        }));
        // Nothing resolves and the parent is a hosting service that hands out <name>.<parent>: there is no DNS for the
        // user to fix; the account was renamed, moved, deleted, or the service is down.
        if (!rep.did && labels.length > 2) {
          var parent = labels.slice(1).join('.');
          extra.push(userDomains(fetchFn, 'https://' + parent).then(function (d) {
            var sfx = hostedSuffix(h, d);
            rep.parentHost = sfx ? { name: parent, suffix: sfx } : null;
            if (d) return null;
            // No answer at all. If the Bluesky relay knows the parent as a PDS, the hosting service itself is down.
            // (The relay's own "status" field is not used: it says "offline" for many PDSes that answer fine.)
            return hostKnown(fetchFn, parent).then(function (k) {
              if (k) rep.parentHost = { name: parent, suffix: '.' + parent, down: true, accounts: k.accountCount };
            });
          }).then(function () { return { name: parent, zone: null, d: { txt: [] } }; }));
        }
        // _atproto.<h> is an alias. If a made-up name next to it is the same alias, it comes from a wildcard (*) record.
        if (rep.dns.cname) {
          extra.push(doh(fetchFn, 'wildcard-probe-q7x.' + h).then(function (d) {
            rep.dns.wildcard = !!d.cname && d.cname === rep.dns.cname;
            return { name: 'wildcard-probe-q7x.' + h, zone: null, d: { txt: [] } };
          }));
        }
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
        // Keep the error name too: "AccountTakedown" / "AccountDeactivated" explain an invalid handle better than DNS can.
        getJson(fetchFn, API + 'app.bsky.actor.getProfile?actor=' + encodeURIComponent(rep.did))
          .then(function (r) { return r.json && r.json.handle ? r.json : { error: (r.json && r.json.error) || null }; },
            function () { return null; })
      ]);
    }).then(function (docs) {
      if (docs) {
        rep.doc = docs[0]; rep.aka = akaHandles(docs[0]); rep.pds = pdsOf(docs[0]);
        rep.profile = docs[1] && docs[1].handle ? { handle: docs[1].handle, displayName: docs[1].displayName || '' } : null;
        rep.profileError = docs[1] && docs[1].error ? String(docs[1].error) : null;
      }
      if (!rep.pds || !/^https:\/\//.test(rep.pds)) return null;
      return userDomains(fetchFn, rep.pds).then(function (d) {
        var sfx = hostedSuffix(h, d);
        rep.hosted = sfx ? { pds: hostName(rep.pds), suffix: sfx } : null;
      });
    }).then(function () {
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
      if (r.apex && r.apex.parked) {
        return { level: 'bad', title: 'The domain ' + r.apex.name + ' looks parked, for sale, or expired',
          steps: steps.concat(['Its nameservers are ' + r.apex.ns.join(', ') + ', which belong to ' + r.apex.parked +
            ', a domain parking / marketplace service. That usually means the registration lapsed and the domain was ' +
            'parked or sold, so your DNS records (including _atproto) are no longer being served.',
          'Check at your registrar (or with a WHOIS lookup) whether you still own ' + r.apex.name + '. If you do, renew it if needed, ' +
            'set its nameservers back to your DNS provider, and re-add the TXT record: host/name "' + hostField(r.handle, r.apex.name) +
            '", value "did=" followed by your DID. Then re-verify the handle in the app.',
          'If someone else owns it now, the handle can not come back; pick a new one in the app (your posts and followers stay, they ' +
            'belong to your DID, not the handle).']) };
      }
      if (r.parentHost && !r.dns.pick.notes.length && !(r.misplaced || []).length) {
        var ph = r.parentHost;
        if (ph.down) {
          return { level: 'bad', title: 'The hosting service ' + ph.name + ' is not answering',
            steps: steps.concat([ph.name + ' is a Bluesky hosting service (PDS): the Bluesky network has seen ' +
              (ph.accounts ? ph.accounts + ' accounts' : 'accounts') + ' there. Handles ending in .' + ph.name +
              ' are answered by that service, and right now it does not respond (checked ' +
              'https://' + ph.name + '/xrpc/com.atproto.server.describeServer). So there is no DNS record for you to add.',
            'If your account lives on ' + ph.name + ', the handle shows as invalid because the service is down or unreachable. ' +
              'Usually that is temporary: wait, then check again, or ask whoever runs ' + ph.name + '.',
            'If it is gone for good, your account (posts, follows) lives on that server too. Moving it elsewhere needs a backup or ' +
              'the account\'s recovery (rotation) key; without either, the realistic option is a new account.']) };
        }
        return { level: 'bad', title: 'No account uses ' + r.handle + ' on ' + ph.name + ' right now',
          steps: steps.concat([ph.name + ' is a hosting service: it hands out names ending in ' + ph.suffix + ' itself, and it ' +
            'answers for them. So there is no DNS record for you to add here.',
          'Most likely the account changed its handle, moved to another host, or was deleted. Check the spelling. If it is your ' +
            'account, your posts and followers belong to your DID, not the name: log in and pick a handle again in Settings, ' +
            'Account, Handle. If the service itself seems down, try again later or contact ' + ph.name + '.']) };
      }
      steps = steps.concat(r.dns.pick.notes);
      steps = steps.concat(dupeSteps(r));
      (r.misplaced || []).forEach(function (m) {
        if (m.name === r.handle) steps.push('Found a DID record on ' + m.name + ' itself. It must be on _atproto.' + r.handle +
          ' (in most DNS panels: host/name "_atproto", type TXT).');
        else steps.push('Found the record at ' + m.name + ': the full name was typed into a DNS panel that adds "' + m.zone +
          '" by itself. Set the host/name field to just "' + hostField(r.handle, m.zone) + '".');
      });
      var zone2 = r.handle.split('.').slice(-2).join('.');
      if (!(r.misplaced || []).length && !r.dns.pick.notes.length && r.dns.cname) {
        steps.push('_atproto.' + r.handle + ' is an alias (CNAME) for ' + r.dns.cname + ', which has no did= record. ' +
          (r.dns.wildcard ? 'It comes from a wildcard (*) record on the domain, often added by the registrar for parking or URL ' +
            'forwarding, so you may never have added it yourself.' : 'A name with a CNAME can not have a TXT record of its own.'));
        steps.push(r.dns.wildcard ?
          'Add the TXT record anyway: an exact record at _atproto.' + r.handle + ' takes priority over the wildcard. Type TXT, host/name "' +
            hostField(r.handle, zone2) + '", value "did=" followed by your DID.' :
          'Delete the CNAME on _atproto.' + r.handle + ', then add a TXT record there: host/name "' + hostField(r.handle, zone2) +
            '", value "did=" followed by your DID.');
        if (r.handle.split('.').length > 2) steps.push('If ' + zone2 + ' is not your own domain (a shared or free subdomain ' +
          'service), only its owner can change this; ask them.');
      } else if (!(r.misplaced || []).length && !r.dns.pick.notes.length) {
        steps.push(r.dns.txt.length ?'There are TXT records on _atproto.' + r.handle + ', but none starts with "did=".' :
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
    // The records are fine, but the account they point to is suspended or switched off. Typical symptom: an OLDER account that
    // used to have this handle shows "Invalid Handle", because the domain now points to this one.
    if (r.profileError === 'AccountTakedown' || r.profileError === 'AccountDeactivated') {
      var down = r.profileError === 'AccountTakedown';
      var older = 'If an older account used to have ' + r.handle + ', that one now shows "Invalid Handle", because the domain points ' +
        'away from it. Either point the record back to the older account\'s DID (then re-verify the handle there), or give the ' +
        'older account a different handle.';
      var out = [r.handle + ' points to ' + r.did + ' and that account claims it back, so the handle setup itself is fine.',
        down ? 'But Bluesky\'s public API answers "AccountTakedown" for this account: it has been suspended, so it does not show ' +
          'up in the app. DNS changes can not fix that; if it is your account and you think it is a mistake, contact Bluesky ' +
          'support or moderation.' :
          'But Bluesky\'s public API answers "AccountDeactivated": the owner switched the account off. Logging in to it again ' +
          'reactivates it.',
        older];
      if (/(^|\.)brid\.gy$/.test(hostName(r.pds))) out.push('This account is bridged from the fediverse by Bridgy Fed (it lives on ' +
        hostName(r.pds) + '). If the fediverse account moved or its address changed, Bridgy Fed can create a NEW Bluesky account ' +
        'that takes over the same handle, and the older bridged account (with the followers) loses it. The fediverse server\'s ' +
        'admin or Bridgy Fed (https://fed.brid.gy/docs) can sort that out.');
      return { level: 'bad', title: down ? 'The records are right, but Bluesky has suspended the account they point to' :
        'The records are right, but the account they point to is deactivated', steps: steps.concat(out) };
    }
    if (r.profile && r.profile.handle === r.handle && r.hosted) {
      var sub = r.handle.slice(0, -r.hosted.suffix.length);
      steps.push('This handle comes from your hosting service, which hands out names ending in ' + r.hosted.suffix +
        ' (your account lives on ' + r.hosted.pds + '). The service answers for it, so there is nothing for you to set up in DNS.');
      steps.push('Still seeing "Invalid Handle" in the app? Then it works right now; the service was probably slow or down during ' +
        'an earlier re-check. To force a fresh check: Settings, Account, Handle, type ' + sub + ' as the new handle (the ' +
        r.hosted.suffix + ' part is added for you), then Save. If it keeps happening, tell your hosting service.');
      return { level: 'ok', title: 'All good: ' + r.handle + ' is a working Bluesky handle', steps: steps };
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
    hostedSuffix: hostedSuffix, check: check, verdict: verdict };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.HandleCheck = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
