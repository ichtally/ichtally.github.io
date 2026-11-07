// node bluesky-character-counter/test.js  (needs ../../facet-check/facets.js next to this repo, or a copy)
const assert = require("assert");
const C = require("./count.js");
let n = 0;
const t = (name, fn) => { fn(); n++; console.log("ok", name); };

t("plain text", () => { const r = C.count("hello"); assert.strictEqual(r.composer, 5); assert.strictEqual(r.composerLeft, 295); });
t("emoji are one grapheme", () => assert.strictEqual(C.count("🙂🇫🇷👨‍👩‍👧").composer, 3));
t("long link is shortened", () => {
  const r = C.count("read https://github.com/bluesky-social/social-app/blob/main/src/lib/strings/url-helpers.ts ok");
  assert.strictEqual(r.postedText, "read github.com/bluesky-soci... ok");
  assert.strictEqual(r.composer, 34); assert.strictEqual(r.raw, 93);
});
t("short path kept", () => assert.strictEqual(C.toShortUrl("https://example.com/"), "example.com"));
t("15-char path (incl. leading /) kept, 16 cut", () => {
  assert.strictEqual(C.toShortUrl("https://a.com/12345678901234"), "a.com/12345678901234");
  assert.strictEqual(C.toShortUrl("https://a.com/123456789012345"), "a.com/123456789012...");
});
t("bare domain not shortened", () => {
  const r = C.count("example.com/a/very/long/path/here");
  assert.strictEqual(r.postedText, "example.com/a/very/long/path/here"); assert.ok(r.links[0].bare);
});
t("punycode + percent-encoding", () =>
  assert.strictEqual(C.count("https://münchen.de/straße/und/noch/mehr").postedText, "xn--mnchen-3ya.de/stra%C3%9Fe/..."));
t("trim + newline cleanup at post time", () => {
  const r = C.count("\n\n  hi\n\n\n\nthere  \n");
  assert.strictEqual(r.postedText, "  hi\n\nthere"); assert.strictEqual(r.composer, 18);
});
t("insert() quirk is reproduced and flagged", () => {
  const r = C.count("example.com/café and https://b.org/xxxxxxxxxxxxxxxxxxxx");
  assert.ok(r.mangled);
  assert.strictEqual(r.intendedText, "example.com/café and b.org/xxxxxxxxxxxx...");
  assert.notStrictEqual(r.postedText, r.intendedText);
  console.log("   app would post:", JSON.stringify(r.postedText));
});
t("no quirk when first link is ASCII", () => assert.ok(!C.count("https://a.com/xxxxxxxxxxxxxxxxxxx and https://b.org/yyyyyyyyyyyyyyyyyy").mangled));
t("api limits", () => {
  assert.ok(!C.count("x".repeat(301)).apiOk); assert.ok(C.count("x".repeat(300)).apiOk);
  assert.ok(C.count("日".repeat(300)).appOk); assert.ok(!C.count("日".repeat(301)).appOk);
  assert.strictEqual(C.count("👨‍👩‍👧".repeat(170)).rawBytes, 3060); assert.ok(!C.count("👨‍👩‍👧".repeat(170)).apiOk);
});
console.log(n + " tests passed");
