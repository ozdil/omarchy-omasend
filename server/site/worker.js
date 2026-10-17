import privacyMd from "../../PRIVACY_POLICY.md";
import { home, join, support, privacy, assetLinks } from "./pages.js";

const HEADERS = {
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

const page = (html) => new Response(html, { headers: { ...HEADERS, "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=600" } });

export function route(req, env, md = privacyMd) {
  if (req.method !== "GET" && req.method !== "HEAD") return new Response("Method not allowed", { status: 405, headers: HEADERS });
  const path = new URL(req.url).pathname.replace(/\/+$/, "") || "/";
  switch (path) {
    case "/":
      return page(home());
    case "/j":
      return page(join());
    case "/support":
    case "/delete":
      return page(support());
    case "/privacy":
      return page(privacy(md));
    case "/.well-known/assetlinks.json": {
      const links = assetLinks(env.ANDROID_PACKAGE || "", env.ANDROID_CERT_SHA256 || "");
      if (links) return new Response(JSON.stringify(links), { headers: { ...HEADERS, "content-type": "application/json", "cache-control": "public, max-age=3600" } });
      break;
    }
  }
  return new Response("Not found", { status: 404, headers: HEADERS });
}

export default { fetch: (req, env) => route(req, env) };
