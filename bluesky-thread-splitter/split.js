// Split long text into Bluesky posts that each fit the app's 300 limit.
// Uses BskyCount (bluesky-character-counter/count.js), so each post is measured the way the app measures it:
// graphemes, with http(s) links shortened. Browser: window.BskySplit. Node: module.exports.
(function (root) {
  const BskyCount = typeof module !== "undefined" && module.exports
    ? require("../bluesky-character-counter/count.js") : root.BskyCount;

  const SENTENCE_END = /[.!?…:;)"'”’»]$/;

  // Words with the whitespace that follows them, plus how good a break point the end of each word is:
  // 3 = paragraph (blank line), 2 = line break or end of sentence, 1 = between words.
  function tokenize(text) {
    const out = [];
    const re = /(\S+)(\s*)/g;
    let m;
    while ((m = re.exec(text))) {
      const ws = m[2];
      let strength = 1;
      if (/\n[^\S\n]*\n/.test(ws)) strength = 3;
      else if (ws.includes("\n") || SENTENCE_END.test(m[1])) strength = 2;
      out.push({ word: m[1], ws, strength });
    }
    return out;
  }

  const join = (toks, i, j) => toks.slice(i, j).map((t, k) => t.word + (i + k < j - 1 ? t.ws : "")).join("");

  function numbering(style, k, n) {
    if (style === "slash") return "\n" + k + "/" + n;
    if (style === "paren") return " (" + k + "/" + n + ")";
    if (style === "thread") return k === 1 ? " 🧵" : "";
    return "";
  }

  // The number the app shows next to the Post button (same as BskyCount.count(s).composer, but cheaper).
  const composerLen = (s) => BskyCount.graphemeLen(BskyCount.appShortenLinks(s));

  // Largest n in [lo, hi] with ok(n) true, given ok(lo) is true and ok is monotone (gallop, then bisect).
  function largest(lo, hi, ok) {
    let step = 1, good = lo, bad = hi + 1;
    while (good + step < bad) {
      if (ok(good + step)) { good += step; step *= 2; } else { bad = good + step; break; }
    }
    while (bad - good > 1) {
      const mid = (good + bad) >> 1;
      if (ok(mid)) good = mid; else bad = mid;
    }
    return good;
  }

  // Cut one over-long word by graphemes (only for things like a 400-character string with no spaces).
  function hardSplit(word, fits) {
    const g = BskyCount.graphemes(word), parts = [];
    let i = 0;
    while (i < g.length) {
      const n = largest(1, g.length - i, (k) => fits(g.slice(i, i + k).join("")));
      parts.push(g.slice(i, i + n).join(""));
      i += n;
    }
    return parts;
  }

  // One pass with a fixed reserved suffix width (worst case for the given total).
  function pack(sections, limit, style, totalGuess) {
    const a = numbering(style, 1, totalGuess), b = numbering(style, totalGuess, totalGuess);
    const worst = a.length > b.length ? a : b;
    const fits = (s) => composerLen(s + worst) <= limit;
    const posts = [];
    for (const sec of sections) {
      const toks = tokenize(sec);
      let i = 0;
      while (i < toks.length) {
        if (!fits(toks[i].word)) { // a single word that can't fit: cut it
          hardSplit(toks[i].word, fits).forEach((p) => posts.push(p));
          i++;
          continue;
        }
        const j = largest(i + 1, toks.length, (k) => fits(join(toks, i, k))); // toks[i..j) fits
        let end = j;
        if (j < toks.length) {
          // Prefer the latest strong break, as long as the post stays at least half full.
          const len = composerLen(join(toks, i, j));
          for (const want of [3, 2]) {
            let k = j;
            while (k > i + 1 && toks[k - 1].strength < want) k--;
            if (toks[k - 1].strength >= want && composerLen(join(toks, i, k)) >= len / 2) { end = k; break; }
          }
        }
        posts.push(join(toks, i, end));
        i = end;
      }
    }
    return posts;
  }

  // text: anything. opts: {limit=300, style="none"|"slash"|"paren"|"thread"}.
  // A line with only --- forces a new post. Returns [{text, count}] where text is what you paste
  // (full links; the app shortens them) and count is what the app will show.
  function split(text, opts) {
    const o = Object.assign({ limit: BskyCount.MAX_GRAPHEMES, style: "none" }, opts || {});
    const sections = text.split(/^[^\S\n]*---[^\S\n]*$/m).map((s) => s.trim()).filter(Boolean);
    let guess = 9, posts = [];
    for (let tries = 0; tries < 5; tries++) {
      posts = pack(sections, o.limit, o.style, guess);
      if (String(posts.length).length <= String(guess).length) break;
      guess = Math.pow(10, String(posts.length).length) - 1;
    }
    const n = posts.length;
    return posts.map((p, idx) => {
      const t = p + numbering(o.style, idx + 1, n);
      return { text: t, count: BskyCount.count(t).composer };
    });
  }

  const api = { split, tokenize };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.BskySplit = api;
})(typeof window !== "undefined" ? window : this);
