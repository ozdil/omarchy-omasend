import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { markdown, assetLinks, join } from "./pages.js";

test("privacy policy renders headings, lists and links", () => {
  const html = markdown(readFileSync(new URL("../../PRIVACY_POLICY.md", import.meta.url), "utf8"));
  assert.match(html, /<h1>Privacy Policy for OmaSend<\/h1>/);
  assert.match(html, /<h3>2.4 Optional OmaID Account<\/h3>/);
  assert.match(html, /<li>.*<code>id.omaid.app<\/code>/);
  assert.doesNotMatch(html, /<script/);
});

test("markdown escapes HTML", () => {
  assert.equal(markdown("<b>x</b> [a](javascript:alert(1))"), "<p>&lt;b&gt;x&lt;/b&gt; [a](javascript:alert(1))</p>");
});

test("assetlinks only with valid fingerprints", () => {
  assert.equal(assetLinks("io.omarchy.omasend", ""), null);
  assert.equal(assetLinks("io.omarchy.omasend", "nope"), null);
  const fp = Array(32).fill("ab").join(":");
  const l = assetLinks("io.omarchy.omasend", fp);
  assert.deepEqual(l[0].target.sha256_cert_fingerprints, [fp.toUpperCase()]);
});

test("join page never puts the invite in markup", () => {
  assert.doesNotMatch(join(), /fetch\(|XMLHttpRequest|sendBeacon/);
});
