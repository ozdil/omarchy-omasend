// omaid.app: a few static pages. No cookies, no scripts from elsewhere, no logs.
// Light or dark follows the device (prefers-color-scheme), with the same ink and paper as the web app.
// The join page reads its invite from the URL fragment, which browsers never send to a server.

const MARK =
  '<svg viewBox="0 0 300 300" width="40" height="40" aria-hidden="true"><path fill="currentColor" d="M0 0h180v20h-180zM200 0h100v20h-100zM0 20h20v20h-20zM140 20h20v20h-20zM240 20h60v20h-60zM0 40h20v20h-20zM40 40h120v20h-120zM220 40h40v20h-40zM280 40h20v20h-20zM0 60h20v20h-20zM40 60h20v20h-20zM200 60h40v20h-40zM280 60h20v20h-20zM0 80h20v20h-20zM40 80h20v20h-20zM180 80h40v20h-40zM0 100h20v20h-20zM40 100h20v20h-20zM160 100h40v20h-40zM240 100h20v20h-20zM280 100h20v20h-20zM0 120h20v20h-20zM40 120h20v20h-20zM160 120h20v20h-20zM240 120h20v20h-20zM280 120h20v20h-20zM0 140h60v20h-60zM240 140h20v20h-20zM280 140h20v20h-20zM0 160h20v20h-20zM40 160h20v20h-20zM240 160h20v20h-20zM280 160h20v20h-20zM0 180h20v20h-20zM40 180h20v20h-20zM240 180h20v20h-20zM280 180h20v20h-20zM0 200h20v20h-20zM40 200h20v20h-20zM240 200h20v20h-20zM280 200h20v20h-20zM0 220h20v20h-20zM40 220h20v20h-20zM240 220h20v20h-20zM280 220h20v20h-20zM0 240h20v20h-20zM40 240h220v20h-220zM280 240h20v20h-20zM0 260h20v20h-20zM140 260h20v20h-20zM280 260h20v20h-20zM0 280h160v20h-160zM180 280h120v20h-120z"/></svg>';

export const PLAY_URL = "https://play.google.com/store/apps/details?id=io.omarchy.omasend";
export const SOURCE_URL = "https://github.com/ozdil/omarchy-omasend";

const CSS = `
:root{color-scheme:light dark;--paper:#f6f6f4;--ink:#18181a}
@media (prefers-color-scheme:dark){:root{--paper:#111214;--ink:#e8e8e6}}
:root{--bg:var(--paper);--fg:var(--ink);--mute:color-mix(in srgb,var(--ink) 62%,var(--paper));--line:color-mix(in srgb,var(--ink) 16%,var(--paper));--box:color-mix(in srgb,var(--ink) 4%,var(--paper));accent-color:var(--ink)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 ui-monospace,"JetBrains Mono","Cascadia Code",Menlo,monospace}
main{max-width:720px;margin:0 auto;padding:40px 16px 64px}
header{display:flex;align-items:center;gap:14px;margin-bottom:32px}
header a{color:inherit;text-decoration:none;font-weight:700;font-size:20px}
nav{margin-left:auto;display:flex;gap:16px;font-size:14px}
nav a{color:var(--mute)}
h1{font-size:26px;line-height:1.3;margin:0 0 12px}
h2{font-size:19px;margin:36px 0 8px}
h3{font-size:16px;margin:24px 0 6px}
a{color:inherit}
p,li{color:var(--fg)}
.mute{color:var(--mute)}
code,pre{background:var(--box);border:1px solid var(--line);border-radius:4px}
code{padding:1px 5px;font-size:14px}
pre{padding:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
pre code{border:0;padding:0;background:none}
hr{border:0;border-top:1px solid var(--line);margin:32px 0}
.btn{display:inline-block;padding:10px 16px;border:1px solid var(--fg);border-radius:4px;background:var(--fg);color:var(--bg);font:inherit;text-decoration:none;cursor:pointer}
.btn.alt{background:none;color:var(--fg)}
.row{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0}
.card{border:1px solid var(--line);border-radius:6px;padding:4px 16px;margin:16px 0}
footer{margin-top:48px;font-size:13px;color:var(--mute)}
`;

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

export function layout(title, body, script = "") {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" media="(prefers-color-scheme: light)" content="#f6f6f4">
<meta name="theme-color" media="(prefers-color-scheme: dark)" content="#111214">
<title>${esc(title)}</title>
<style>${CSS}</style></head>
<body><main>
<header>${MARK}<a href="/">OmaID</a><nav><a href="/support">Support</a><a href="/privacy">Privacy</a></nav></header>
${body}
<footer>OmaID is the anonymous account behind OmaSend. No email, no phone number, no tracking. <a href="${SOURCE_URL}">Source code</a></footer>
</main>${script ? `<script>${script}</script>` : ""}</body></html>`;
}

export function home() {
  return layout(
    "OmaID",
    `<h1>One anonymous number for all your devices.</h1>
<p>An OmaID is a 16-digit account number. Type it on a new device, approve it once from a device you already have, and your phone and computers find each other anywhere: same Wi-Fi or across the internet.</p>
<ul>
<li>No email, phone number, name or password.</li>
<li>The number never leaves your devices. The registry stores only an encrypted list it cannot read.</li>
<li>Files and clipboard go device to device, end-to-end encrypted.</li>
</ul>
<div class="row"><a class="btn" href="${PLAY_URL}">Get OmaSend for Android</a><a class="btn alt" href="${SOURCE_URL}">OmaSend for Omarchy</a></div>`,
  );
}

// The invite stays in the fragment: this script copies it locally and sends it nowhere.
const JOIN_SCRIPT = `
(function(){
  var link = location.href.split("?")[0];
  var ok = /#n=\\d{16}&k=[A-Za-z0-9_-]+$/.test(link);
  document.getElementById(ok ? "invite" : "noinvite").hidden = false;
  if (!ok) return;
  document.getElementById("cmd").textContent = "omasend-engine --account-join '" + link + "'";
  document.getElementById("copy").onclick = function(){
    navigator.clipboard.writeText(link).then(function(){ document.getElementById("copy").textContent = "Copied"; });
  };
})();`;

export function join() {
  return layout(
    "Join an OmaID",
    `<h1>Add this device to an OmaID</h1>
<div id="invite" hidden>
<p>Someone opened an invite on one of their devices. Open this link in OmaSend on the device you want to add. The invite works once and expires after 10 minutes.</p>
<div class="card"><h3>Android</h3>
<p>If OmaSend is installed, this link opens it directly. If it opened here instead, copy the link, then in OmaSend go to Settings, OmaID, Join, and paste it.</p>
<div class="row"><button class="btn" id="copy" type="button">Copy invite link</button><a class="btn alt" href="${PLAY_URL}">Get OmaSend</a></div></div>
<div class="card"><h3>Omarchy</h3><p>Run this in a terminal:</p><pre><code id="cmd"></code></pre></div>
<p class="mute">The invite is in the part of the address after <code>#</code>. Browsers never send that part to a server, so omaid.app never sees it.</p>
</div>
<div id="noinvite" hidden><p>This page opens OmaID invites. Ask for a new invite: on a device that is already in the account, open Settings, OmaID, and choose Add a device.</p></div>
<noscript><p>Copy this page's full address and paste it into OmaSend under Settings, OmaID, Join.</p></noscript>`,
    JOIN_SCRIPT,
  );
}

export function support() {
  return layout(
    "OmaID support",
    `<h1>Support</h1>
<h2>Add a device</h2>
<p>On the new device, choose Join and type your 16-digit number. It shows a 6-digit code. On a device already in the account, approve the request only if it shows the same code. You approve each new device once. You can also show an invite QR on an existing device and scan it with the new one; that approves it for you.</p>
<h2>Remove a device</h2>
<p>On any of your devices, open OmaID and remove the device. It loses access at once and the account's keys are replaced, so it cannot read anything written after that. If your number may have leaked, choose Change number.</p>
<h2>Lost every device</h2>
<p>Type your number on a new device and choose Reset. After 24 hours the account starts again with just that device, unless one of your old devices cancels the reset in the meantime.</p>
<h2 id="delete">Delete your account</h2>
<p>Leave the account on each device (OmaID, Leave). When the last device leaves, the account record is deleted from the registry right away. An account that nobody opens for two years is deleted automatically.</p>
<p>The registry cannot tell whose account is whose, so nobody can delete an account for you without one of your devices. If you have lost all of them, the record will expire on its own; it is encrypted and useless without your number.</p>
<h2>Report a problem</h2>
<p>Open an issue at <a href="${SOURCE_URL}/issues">github.com/ozdil/omarchy-omasend</a>. Never post your OmaID number.</p>`,
  );
}

function inline(s) {
  return esc(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2">$1</a>');
}

/** Renders the small Markdown subset PRIVACY_POLICY.md uses. */
export function markdown(md) {
  const out = [];
  let list = null;
  let para = [];
  const flushPara = () => {
    if (para.length) out.push(`<p>${inline(para.join(" "))}</p>`);
    para = [];
  };
  const flushList = () => {
    if (list) out.push(`<ul>${list.map((li) => `<li>${inline(li)}</li>`).join("")}</ul>`);
    list = null;
  };
  for (const raw of md.split("\n")) {
    const line = raw.trimEnd();
    const h = /^(#{1,3}) (.*)$/.exec(line);
    if (h) {
      flushPara();
      flushList();
      out.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`);
    } else if (line === "---") {
      flushPara();
      flushList();
      out.push("<hr>");
    } else if (/^- /.test(line)) {
      flushPara();
      (list ||= []).push(line.slice(2));
    } else if (list && /^\s+\S/.test(line)) {
      list[list.length - 1] += " " + line.trim();
    } else if (line === "") {
      flushPara();
      flushList();
    } else {
      flushList();
      para.push(line);
    }
  }
  flushPara();
  flushList();
  return out.join("\n");
}

export function privacy(md) {
  return layout("OmaSend privacy policy", markdown(md));
}

export function assetLinks(pkg, fingerprints) {
  const certs = fingerprints
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter((s) => /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(s));
  if (!certs.length) return null;
  return [
    {
      relation: ["delegate_permission/common.handle_all_urls"],
      target: { namespace: "android_app", package_name: pkg, sha256_cert_fingerprints: certs },
    },
  ];
}
