// Bluesky post length, counted the way the official app counts it.
// Needs Facets (facet-check/facets.js) for link detection. Browser: window.BskyCount. Node: module.exports.
// Mirrors bluesky-social/social-app: src/lib/strings/url-helpers.ts (toShortUrl),
// src/lib/strings/rich-text-manip.ts (shortenLinks), src/lib/api/index.ts (resolveRT: trim, cleanNewlines),
// and @atproto/api sanitization.js (EXCESS_SPACE_RE). Limits from the app.bsky.feed.post lexicon.
(function (root) {
  const Facets = typeof module !== "undefined" && module.exports ? require("../../facet-check/facets.js") : root.Facets;

  const MAX_GRAPHEMES = 300; // app.bsky.feed.post text maxGraphemes
  const MAX_BYTES = 3000; // app.bsky.feed.post text maxLength (UTF-8 bytes)

  const seg = typeof Intl !== "undefined" && Intl.Segmenter ? new Intl.Segmenter() : null;
  const graphemes = (s) => (seg ? [...seg.segment(s)].map((x) => x.segment) : [...s]);
  const graphemeLen = (s) => graphemes(s).length;
  const byteLen = (s) => new TextEncoder().encode(s).length;

  // Same as the app's toShortUrl. Gets the link's *visible text*, so bare domains (no http) throw in
  // new URL() and come back unchanged.
  function toShortUrl(url) {
    try {
      const u = new URL(url);
      if (u.protocol !== "http:" && u.protocol !== "https:") return url;
      const path = (u.pathname === "/" ? "" : u.pathname) + u.search + u.hash;
      if (path.length > 15) return u.host + path.slice(0, 13) + "...";
      return u.host + path;
    } catch (e) {
      return url;
    }
  }

  // Replace each detected link's text with its short form. Returns {text, links:[{from,to,bare}]}.
  function shortenLinks(text) {
    const links = Facets.findSpans(text).filter((s) => s.kind === "link");
    let out = "", pos = 0;
    const info = [];
    for (const l of links) {
      const shown = text.slice(l.start, l.end);
      const short = toShortUrl(shown);
      out += text.slice(pos, l.start) + short;
      pos = l.end;
      info.push({ from: shown, to: short, uri: l.value, bare: !/^https?:\/\//i.test(shown) });
    }
    return { text: out + text.slice(pos), links: info };
  }

  // Faithful port of what the app really does: RichText.insert/delete on UTF-8 byte facets. Includes a
  // quirk in @atproto/api and @bsky/sdk: insert() shifts the *other* facets by insertText.length (UTF-16
  // units, not bytes). So if an earlier link's short text has non-ASCII characters (e.g. a bare
  // example.com/café, which isn't shortened), later links get the wrong range and the text gets mangled.
  const enc = new TextEncoder(), dec = new TextDecoder();
  function appShortenLinks(text) {
    const links = Facets.findSpans(text).filter((s) => s.kind === "link")
      .map((s) => ({ bs: Facets.byteOffset(text, s.start), be: Facets.byteOffset(text, s.end) }))
      .sort((a, b) => a.bs - b.bs);
    let u = text, b = enc.encode(u);
    const sl = (s, e) => dec.decode(b.slice(s, e));
    let live = links.slice();
    for (const f of links) {
      const bs = f.bs, be = f.be;
      const short = toShortUrl(sl(bs, be));
      const sb = enc.encode(short).length;
      u = sl(0, bs) + short + sl(bs); b = enc.encode(u); // insert
      for (const e of live) {
        if (bs <= e.bs) { e.bs += short.length; e.be += short.length; }
        else if (bs >= e.bs && bs < e.be) e.be += short.length;
      }
      f.bs = bs; f.be = bs + sb;
      const rs = bs + sb, re = be + sb, n = re - rs; // delete
      u = sl(0, rs) + sl(re); b = enc.encode(u);
      for (const e of live) {
        if (rs <= e.bs && re >= e.be) { e.bs = 0; e.be = 0; }
        else if (rs > e.be) { /* noop */ }
        else if (rs > e.bs && rs <= e.be && re > e.be) e.be = rs;
        else if (rs >= e.bs && re <= e.be) e.be -= n;
        else if (rs < e.bs && re >= e.bs && re <= e.be) { e.bs = rs; e.be -= n; }
        else if (re < e.bs) { e.bs -= n; e.be -= n; }
      }
      live = live.filter((e) => e.bs < e.be);
    }
    return u;
  }

  // eslint-disable-next-line no-misleading-character-class
  const EXCESS_SPACE_RE = /[\r\n]([­⁠‍‌​\s]*[\r\n]){2,}/;
  function cleanNewlines(t) {
    let m;
    while ((m = t.match(EXCESS_SPACE_RE))) {
      const next = t.slice(0, m.index) + "\n\n" + t.slice(m.index + m[0].length);
      if (next === t) break;
      t = next;
    }
    return t;
  }

  // What the app does just before it posts.
  function prepareForPost(text) {
    const trimmed = text.replace(/^(\s*\n)+/, "").trimEnd();
    return shortenLinks(cleanNewlines(trimmed));
  }

  function count(text) {
    const composerText = appShortenLinks(text);
    const intended = prepareForPost(text);
    const postedText = appShortenLinks(cleanNewlines(text.replace(/^(\s*\n)+/, "").trimEnd()));
    const composerLen = graphemeLen(composerText);
    return {
      composer: composerLen, // the number next to the Post button
      composerLeft: MAX_GRAPHEMES - composerLen,
      postedText,
      posted: graphemeLen(postedText),
      postedBytes: byteLen(postedText),
      mangled: postedText !== intended.text, // the app's insert() quirk hit this text
      intendedText: intended.text,
      links: intended.links,
      raw: graphemeLen(text), // what an API client that doesn't shorten links sends
      rawBytes: byteLen(text),
      codePoints: [...text].length,
      utf16: text.length,
      appOk: composerLen <= MAX_GRAPHEMES,
      apiOk: graphemeLen(text) <= MAX_GRAPHEMES && byteLen(text) <= MAX_BYTES,
    };
  }

  const api = { MAX_GRAPHEMES, MAX_BYTES, toShortUrl, shortenLinks, appShortenLinks, cleanNewlines, prepareForPost, count, graphemes, graphemeLen };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.BskyCount = api;
})(typeof window !== "undefined" ? window : this);
