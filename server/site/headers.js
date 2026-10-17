// Response headers for omaid.app. The only inline script is JOIN_SCRIPT on /j, so that page
// allows exactly its SHA-256 hash and every other page allows no script at all.
import { JOIN_SCRIPT } from "./pages.js";

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

export const JOIN_SCRIPT_HASH = `sha256-${b64(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JOIN_SCRIPT)))}`;

const csp = (scriptSrc) =>
  [
    "default-src 'none'",
    "style-src 'unsafe-inline'",
    ...(scriptSrc ? [`script-src '${scriptSrc}'`] : []),
    "img-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
  ].join("; ");

const COMMON = {
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

export const HEADERS = { ...COMMON, "content-security-policy": csp() };
export const JOIN_HEADERS = { ...COMMON, "content-security-policy": csp(JOIN_SCRIPT_HASH) };
