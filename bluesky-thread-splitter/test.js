// node bluesky-thread-splitter/test.js  (needs ../facet-check/facets.js next to this repo, as in CI)
const assert = require("assert");
const { split } = require("./split.js");
const C = require("../bluesky-character-counter/count.js");

let n = 0;
function t(name, fn) { fn(); n++; console.log("ok", name); }

const words = (k, w = "word") => Array.from({ length: k }, (_, i) => w + i).join(" ");
const norm = (s) => s.replace(/\s+/g, " ").trim();

t("short text stays one post", () => {
  const r = split("Hello there.");
  assert.deepStrictEqual(r, [{ text: "Hello there.", count: 12 }]);
});

t("empty text gives no posts", () => assert.deepStrictEqual(split("  \n "), []));

t("every post fits and no words are lost", () => {
  const src = words(400);
  const r = split(src);
  assert(r.length > 1);
  r.forEach((p) => assert(p.count <= 300 && C.count(p.text).composer === p.count));
  assert.strictEqual(norm(r.map((p) => p.text).join(" ")), norm(src));
});

t("prefers paragraph breaks", () => {
  const p1 = words(40, "para"), p2 = words(40, "graf");
  const r = split(p1 + "\n\n" + p2);
  assert.strictEqual(r.length, 2);
  assert.strictEqual(r[0].text, p1);
  assert.strictEqual(r[1].text, p2);
});

t("prefers sentence ends over mid-sentence", () => {
  const s1 = words(25, "alpha") + ".", s2 = words(25, "beta") + ".";
  const r = split(s1 + " " + s2);
  assert.strictEqual(r[0].text, s1);
});

t("--- forces a break", () => {
  const r = split("one\n---\ntwo");
  assert.deepStrictEqual(r.map((p) => p.text), ["one", "two"]);
});

t("long links are counted short, so more fits", () => {
  const url = "https://example.com/" + "p".repeat(200);
  const src = "see " + url + " " + words(20);
  const r = split(src);
  assert.strictEqual(r.length, 1); // 230+ graphemes raw, but the app shows ~40 for the link
  assert(r[0].text.includes(url));
});

t("links are never cut", () => {
  const url = "https://example.com/" + "q".repeat(60);
  const src = Array.from({ length: 12 }, (_, i) => "item " + i + " " + url).join(" ");
  split(src).forEach((p) => {
    const parts = p.text.split(" ").filter((w) => w.startsWith("https://"));
    parts.forEach((w) => assert.strictEqual(w, url));
  });
});

t("emoji count as one and are not split", () => {
  const src = Array(320).fill("👨‍👩‍👧").join("");
  const r = split(src);
  assert.strictEqual(r.length, 2);
  assert.strictEqual(r[0].count, 300);
  assert.strictEqual(r[0].text + r[1].text, src);
});

t("1/N numbering fits, and N with 2 digits is reserved", () => {
  const r = split(words(1500), { style: "slash" });
  assert(r.length >= 10);
  r.forEach((p, i) => {
    assert(p.count <= 300, "post " + i + " is " + p.count);
    assert(p.text.endsWith("\n" + (i + 1) + "/" + r.length));
  });
});

t("(k/N) and thread styles", () => {
  const r = split(words(200), { style: "paren" });
  r.forEach((p, i) => assert(p.text.endsWith(" (" + (i + 1) + "/" + r.length + ")") && p.count <= 300));
  const s = split(words(200), { style: "thread" });
  assert(s[0].text.endsWith(" 🧵") && !s[1].text.includes("🧵"));
  s.forEach((p) => assert(p.count <= 300));
});

t("custom limit", () => {
  split(words(100), { limit: 100 }).forEach((p) => assert(p.count <= 100));
});

console.log(n, "tests passed");
