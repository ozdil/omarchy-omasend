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

test("pages follow the device theme without script", () => {
  const html = join();
  assert.match(html, /prefers-color-scheme:dark/);
  assert.match(html, /<meta name="color-scheme" content="light dark">/);
  assert.match(html, /theme-color" media="\(prefers-color-scheme: dark\)/);
});

test("only /j may run script, and only the join script", async () => {
  const { HEADERS, JOIN_HEADERS, JOIN_SCRIPT_HASH } = await import("./headers.js");
  const { JOIN_SCRIPT } = await import("./pages.js");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JOIN_SCRIPT));
  assert.equal(JOIN_SCRIPT_HASH, "sha256-" + Buffer.from(digest).toString("base64"));
  assert.match(JOIN_HEADERS["content-security-policy"], new RegExp(`script-src '${JOIN_SCRIPT_HASH.replace(/[+/=]/g, "\\$&")}'`));
  assert.doesNotMatch(HEADERS["content-security-policy"], /script-src/);
  for (const h of [HEADERS, JOIN_HEADERS]) {
    assert.doesNotMatch(h["content-security-policy"], /script-src 'unsafe-inline/);
    assert.match(h["content-security-policy"], /object-src 'none'/);
  }
  assert.match(join(), new RegExp(`<script>${JOIN_SCRIPT.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}</script>`));
});
