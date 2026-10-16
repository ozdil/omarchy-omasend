//! Browser client (omasend-web PWA) served by the engine at `/web/`.
//!
//! The page is served on the same origin as the signed-HTTP API, so the browser needs no CORS
//! and never mixes https/http. It pairs through `POST /api/v2/pair` (`client: "web"`) and then
//! only sends: a browser has no server and no QUIC endpoint (see PROTOCOL_V2.md, "Browser client").
//!
//! Everything here is pure (no sockets), so path safety can be unit-tested directly.

use std::path::{Component, Path, PathBuf};

/// URL prefix of the web client.
pub const WEB_PREFIX: &str = "/web";
/// Largest file served from the web root.
pub const MAX_WEB_FILE_BYTES: u64 = 20 * 1024 * 1024;
/// Installed by build.sh (relative to $HOME).
pub const USER_WEB_DIR: &str = ".local/share/omarchy/omasend/web";
/// Optional system-wide install (packagers).
pub const SYSTEM_WEB_DIR: &str = "/usr/share/omasend/web";

/// Security headers sent with every `/web` response.
pub const SECURITY_HEADERS: [(&str, &str); 3] =
    [("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("X-Frame-Options", "DENY")];

pub const NOT_INSTALLED_HTML: &str = "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>OmaSend</title>\
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;\
color:#ddd;background:#111}code{background:#222;padding:0 .3em}</style></head><body>\
<h1>OmaSend web client is not installed</h1>\
<p>This computer runs OmaSend, but the browser client is not installed.</p>\
<p>Install it with <code>build.sh</code> next to an <code>omasend-web</code> checkout, \
or put the built files in <code>~/.local/share/omarchy/omasend/web</code>.</p>\
</body></html>\n";

/// Web root candidates in priority order: `$OMASEND_WEB_DIR`, the per-user install, the
/// system install.
pub fn web_root_candidates(env_dir: Option<&str>, home: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(d) = env_dir.map(str::trim).filter(|d| !d.is_empty()) {
        out.push(PathBuf::from(d));
    }
    if let Some(h) = home {
        out.push(h.join(USER_WEB_DIR));
    }
    out.push(PathBuf::from(SYSTEM_WEB_DIR));
    out
}

/// First existing web root directory.
pub fn find_web_root(env_dir: Option<&str>, home: Option<&Path>) -> Option<PathBuf> {
    web_root_candidates(env_dir, home).into_iter().find(|p| p.is_dir())
}

/// The web root for the running engine (from the environment).
pub fn web_root() -> Option<PathBuf> {
    let env_dir = std::env::var("OMASEND_WEB_DIR").ok();
    let home = std::env::var("HOME").ok().map(PathBuf::from);
    find_web_root(env_dir.as_deref(), home.as_deref())
}

/// Strict percent-decoding: every `%` must start a valid `%XX`, the result must be UTF-8.
/// `+` is NOT a space in a path.
pub fn percent_decode_strict(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            let v = u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[derive(Debug, PartialEq, Eq)]
pub enum WebTarget {
    /// `/web` → `301` to `/web/`.
    Redirect,
    /// A file inside the web root (canonical path) and its path relative to the root.
    File { path: PathBuf, rel: String },
    /// `/web/` or `/web/index.html` with no web root installed.
    NotInstalled,
    NotFound,
    /// Unsafe or malformed path.
    BadRequest,
}

/// Maps a request path (raw, as sent, without the query) under `/web` to what to serve.
/// Returns `None` if the path is not under `/web` at all.
pub fn resolve(root: Option<&Path>, raw_path: &str) -> Option<WebTarget> {
    if raw_path == WEB_PREFIX {
        return Some(WebTarget::Redirect);
    }
    let rest = raw_path.strip_prefix("/web/")?;
    Some(resolve_rel(root, rest))
}

fn resolve_rel(root: Option<&Path>, rest_raw: &str) -> WebTarget {
    let Some(rest) = percent_decode_strict(rest_raw) else { return WebTarget::BadRequest };
    // Anything still looking encoded after one decode is a double-encoding attempt.
    if rest.contains('%') || rest.contains('\\') || rest.contains('\0') || rest.chars().any(char::is_control) {
        return WebTarget::BadRequest;
    }
    let rel = if rest.is_empty() { "index.html".to_string() } else { rest };
    if rel.starts_with('/') {
        return WebTarget::BadRequest;
    }
    let p = Path::new(&rel);
    if p.is_absolute() {
        return WebTarget::BadRequest;
    }
    for seg in rel.split('/') {
        if seg == "." || seg == ".." {
            return WebTarget::BadRequest;
        }
        // Empty segments ("a//b", a trailing "/") and hidden files are not served.
        if seg.is_empty() || seg.starts_with('.') {
            return WebTarget::NotFound;
        }
    }
    if p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return WebTarget::BadRequest;
    }
    let is_index = rel == "index.html";
    let Some(root) = root else {
        return if is_index { WebTarget::NotInstalled } else { WebTarget::NotFound };
    };
    let Ok(canon_root) = root.canonicalize() else {
        return if is_index { WebTarget::NotInstalled } else { WebTarget::NotFound };
    };
    let Ok(canon) = canon_root.join(p).canonicalize() else { return WebTarget::NotFound };
    // A symlink inside the root must not lead outside of it.
    if !canon.starts_with(&canon_root) {
        return WebTarget::NotFound;
    }
    match std::fs::metadata(&canon) {
        Ok(m) if m.is_file() => WebTarget::File { path: canon, rel },
        _ => WebTarget::NotFound,
    }
}

/// Content-Type by file extension.
pub fn content_type(rel: &str) -> &'static str {
    let ext = rel.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "wasm" => "application/wasm",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Cache-Control: hashed build assets are immutable; everything else is revalidated so a new
/// install (index.html, sw.js, manifest) takes effect immediately.
pub fn cache_control(rel: &str) -> &'static str {
    if rel.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

/// JavaScript `encodeURIComponent`.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// `http://<ip>:<port>/web/#pair=<encodeURIComponent(uri)>`. The pairing link travels in the
/// fragment, which browsers never send to a server (not even this one).
pub fn pair_web_url(host: &str, port: u16, pair_uri: &str) -> String {
    let host = if host.contains(':') && !host.starts_with('[') { format!("[{}]", host) } else { host.to_string() };
    format!("http://{}:{}/web/#pair={}", host, port, encode_uri_component(pair_uri))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let mut b = [0u8; 6];
        getrandom::getrandom(&mut b).unwrap();
        let d = std::env::temp_dir().join(format!("omasend-web-{}-{}", tag, hex::encode(b)));
        std::fs::create_dir_all(d.join("web/assets")).unwrap();
        std::fs::write(d.join("web/index.html"), "<!doctype html>app").unwrap();
        std::fs::write(d.join("web/sw.js"), "self").unwrap();
        std::fs::write(d.join("web/assets/app-1234.js"), "x").unwrap();
        std::fs::write(d.join("web/çay (1).txt"), "t").unwrap();
        std::fs::write(d.join("secret.txt"), "outside").unwrap();
        d
    }

    #[test]
    fn test_resolve_serves_index_and_files() {
        let d = tmp_root("ok");
        let root = d.join("web");
        assert_eq!(resolve(Some(&root), "/web"), Some(WebTarget::Redirect));
        assert_eq!(resolve(Some(&root), "/webx"), None);
        assert_eq!(resolve(Some(&root), "/api/status"), None);
        for p in ["/web/", "/web/index.html"] {
            match resolve(Some(&root), p) {
                Some(WebTarget::File { rel, .. }) => assert_eq!(rel, "index.html"),
                other => panic!("{} -> {:?}", p, other),
            }
        }
        assert!(matches!(resolve(Some(&root), "/web/assets/app-1234.js"), Some(WebTarget::File { ref rel, .. }) if rel == "assets/app-1234.js"));
        assert!(matches!(resolve(Some(&root), "/web/%C3%A7ay%20(1).txt"), Some(WebTarget::File { .. })));
        assert_eq!(resolve(Some(&root), "/web/missing.js"), Some(WebTarget::NotFound));
        assert_eq!(resolve(Some(&root), "/web/assets"), Some(WebTarget::NotFound), "directories are not served");
        assert_eq!(resolve(Some(&root), "/web/assets/"), Some(WebTarget::NotFound));
    }

    #[test]
    fn test_resolve_rejects_traversal_and_encoding_tricks() {
        let d = tmp_root("bad");
        let root = d.join("web");
        for p in [
            "/web/../secret.txt",
            "/web/assets/../../secret.txt",
            "/web/%2e%2e/secret.txt",
            "/web/%2E%2E/secret.txt",
            "/web/.%2e/secret.txt",
            "/web/%2e%2e%2fsecret.txt",
            "/web/assets%2f..%2f..%2fsecret.txt",
            "/web/%252e%252e/secret.txt",
            "/web/%252e%252e%252fsecret.txt",
            "/web/..%5csecret.txt",
            "/web/..\\secret.txt",
            "/web/%00index.html",
            "/web/index.html%00.js",
            "/web//etc/passwd",
            "/web/%2fetc%2fpasswd",
            "/web/%",
            "/web/%zz",
            "/web/%ff",
            "/web/./index.html",
            "/web/a/./b",
        ] {
            let r = resolve(Some(&root), p);
            assert!(matches!(r, Some(WebTarget::BadRequest) | Some(WebTarget::NotFound)), "{} -> {:?}", p, r);
            assert!(!matches!(r, Some(WebTarget::File { .. })), "{}", p);
        }
        assert_eq!(resolve(Some(&root), "/web/%2e%2e/secret.txt"), Some(WebTarget::BadRequest));
        assert_eq!(resolve(Some(&root), "/web/%252e%252e/secret.txt"), Some(WebTarget::BadRequest));
        // Hidden files are never served.
        std::fs::write(root.join(".env"), "x").unwrap();
        assert_eq!(resolve(Some(&root), "/web/.env"), Some(WebTarget::NotFound));
    }

    #[test]
    fn test_resolve_rejects_symlinks_escaping_root() {
        let d = tmp_root("link");
        let root = d.join("web");
        std::os::unix::fs::symlink(d.join("secret.txt"), root.join("leak.txt")).unwrap();
        std::os::unix::fs::symlink(&d, root.join("up")).unwrap();
        std::os::unix::fs::symlink(root.join("sw.js"), root.join("inside.js")).unwrap();
        assert_eq!(resolve(Some(&root), "/web/leak.txt"), Some(WebTarget::NotFound));
        assert_eq!(resolve(Some(&root), "/web/up/secret.txt"), Some(WebTarget::NotFound));
        assert!(matches!(resolve(Some(&root), "/web/inside.js"), Some(WebTarget::File { .. })), "symlink inside the root is fine");
        // The root itself may be a symlink (e.g. a versioned install dir).
        let alias = d.join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        assert!(matches!(resolve(Some(&alias), "/web/sw.js"), Some(WebTarget::File { .. })));
    }

    #[test]
    fn test_not_installed_page_and_root_lookup() {
        assert_eq!(resolve(None, "/web/"), Some(WebTarget::NotInstalled));
        assert_eq!(resolve(None, "/web/index.html"), Some(WebTarget::NotInstalled));
        assert_eq!(resolve(None, "/web/app.js"), Some(WebTarget::NotFound));
        assert_eq!(resolve(None, "/web/../x"), Some(WebTarget::BadRequest));
        assert!(NOT_INSTALLED_HTML.contains("not installed"));

        let d = tmp_root("lookup");
        let home = d.join("home");
        let user = home.join(USER_WEB_DIR);
        // Nothing user-level yet: falls through to the system dir only if it exists.
        let cands = web_root_candidates(Some(d.join("web").to_str().unwrap()), Some(&home));
        assert_eq!(cands, vec![d.join("web"), user.clone(), PathBuf::from(SYSTEM_WEB_DIR)]);
        assert_eq!(find_web_root(Some(d.join("web").to_str().unwrap()), Some(&home)), Some(d.join("web")));
        std::fs::create_dir_all(&user).unwrap();
        assert_eq!(find_web_root(Some(d.join("nope").to_str().unwrap()), Some(&home)), Some(user.clone()));
        assert_eq!(find_web_root(Some("  "), Some(&home)), Some(user));
    }

    #[test]
    fn test_content_types_and_cache_policy() {
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("assets/a.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("assets/a.MJS"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("a.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("manifest.json"), "application/json");
        assert_eq!(content_type("manifest.webmanifest"), "application/manifest+json");
        assert_eq!(content_type("icon.svg"), "image/svg+xml");
        assert_eq!(content_type("icon.png"), "image/png");
        assert_eq!(content_type("favicon.ico"), "image/x-icon");
        assert_eq!(content_type("f.woff2"), "font/woff2");
        assert_eq!(content_type("m.wasm"), "application/wasm");
        assert_eq!(content_type("noext"), "application/octet-stream");
        assert_eq!(cache_control("index.html"), "no-cache");
        assert_eq!(cache_control("sw.js"), "no-cache");
        assert_eq!(cache_control("manifest.webmanifest"), "no-cache");
        assert_eq!(cache_control("assets/index-abc.js"), "public, max-age=31536000, immutable");
    }

    #[test]
    fn test_pair_web_url_matches_encode_uri_component() {
        // Values checked against JavaScript encodeURIComponent.
        assert_eq!(encode_uri_component("omasend://pair?v=2&n=Desk%20(1)"), "omasend%3A%2F%2Fpair%3Fv%3D2%26n%3DDesk%2520(1)");
        assert_eq!(encode_uri_component("a b*!~'"), "a%20b*!~'");
        assert_eq!(encode_uri_component("ç"), "%C3%A7");
        let u = pair_web_url("192.168.1.10", 53317, "omasend://pair?v=2&pk=x");
        assert_eq!(u, "http://192.168.1.10:53317/web/#pair=omasend%3A%2F%2Fpair%3Fv%3D2%26pk%3Dx");
        assert!(pair_web_url("fe80::1", 1, "x").starts_with("http://[fe80::1]:1/web/#pair="));
        // Round trip back to the link (what the page does with decodeURIComponent).
        let enc = u.split("#pair=").nth(1).unwrap();
        assert_eq!(percent_decode_strict(enc).unwrap(), "omasend://pair?v=2&pk=x");
    }
}
