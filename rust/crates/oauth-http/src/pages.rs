//! Server-rendered HTML pages (ADR 0025). No scripts or external assets;
//! system fonts; every interpolated value goes through [`esc`].

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

/// HTML-escapes text for element content and double-quoted attributes.
pub fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

const CSS: &str = r#"
:root{color-scheme:light dark;--fg:#1d1d1f;--muted:#5f6368;--bg:#fafafa;--card:#fff;--line:#e3e3e8;--accent:#3a5bd9;--err:#b3261e;--ok:#1e7b34}
@media (prefers-color-scheme:dark){:root{--fg:#ececf1;--muted:#a0a3ab;--bg:#111214;--card:#1b1c1f;--line:#2c2e33;--accent:#8ea6ff;--err:#ff8a80;--ok:#7bd88f}}
*{box-sizing:border-box}
body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:30rem;margin:4rem auto;padding:0 1rem}
main.wide{max-width:46rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1.75rem}
h1{font-size:1.5rem;margin:0 0 .25rem}
h2{font-size:1.1rem;margin:1.75rem 0 .5rem}
p.lead{color:var(--muted);margin:0 0 1.25rem}
.brand{font-weight:650;letter-spacing:-.01em;color:var(--fg);text-decoration:none}
header{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:1.5rem}
label{display:block;margin:.85rem 0 .3rem;font-weight:550;font-size:.95rem}
input{width:100%;padding:.6rem .7rem;font:inherit;color:inherit;background:transparent;border:1px solid var(--line);border-radius:8px}
input:focus{outline:2px solid var(--accent);outline-offset:1px}
button{margin-top:1.25rem;width:100%;padding:.65rem;font:inherit;font-weight:600;color:#fff;background:var(--accent);border:0;border-radius:8px;cursor:pointer}
@media (prefers-color-scheme:dark){button{color:#111}}
a{color:var(--accent)}
.err{color:var(--err)} .ok{color:var(--ok)}
.muted{color:var(--muted);font-size:.9rem}
.links{margin-top:1.25rem;display:flex;gap:1rem;flex-wrap:wrap;font-size:.95rem}
code{font:.9em ui-monospace,SFMono-Regular,Menlo,monospace}
ul.facts{padding-left:1.1rem} ul.facts li{margin:.3rem 0}
footer{margin:2rem 0;color:var(--muted);font-size:.85rem;text-align:center}
"#;

/// The favicon, embedded in the binary (source and generator in `assets/`).
pub const FAVICON_SVG: &[u8] = include_bytes!("../assets/favicon.svg");
/// 16/32/48 px ICO generated from [`FAVICON_SVG`] by `assets/make-favicon.py`.
pub const FAVICON_ICO: &[u8] = include_bytes!("../assets/favicon.ico");

/// Serves an embedded static asset with a one-week public cache.
pub fn asset(body: &'static [u8], content_type: &'static str) -> Response {
    (
        [
            (axum::http::header::CONTENT_TYPE, content_type),
            (axum::http::header::CACHE_CONTROL, "public, max-age=604800"),
        ],
        body,
    )
        .into_response()
}

/// A full page: `<title>`, the authcraft header, a card holding `body`.
pub fn layout(title: &str, body: &str) -> Html<String> {
    layout_with(title, body, false)
}

/// [`layout`] with a wider column (landing and account pages).
pub fn layout_wide(title: &str, body: &str) -> Html<String> {
    layout_with(title, body, true)
}

fn layout_with(title: &str, body: &str, wide: bool) -> Html<String> {
    let class = if wide { " class=\"wide\"" } else { "" };
    Html(format!(
        r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">
<title>{title} · authcraft</title>
<style>{CSS}</style>
</head><body><main{class}>
<header><a class="brand" href="/">authcraft</a></header>
<div class="card">
{body}
</div>
<footer>authcraft · an OAuth 2.0 / OpenID Connect provider built from the JOSE layer up</footer>
</main></body></html>"#,
        title = esc(title),
    ))
}

/// A short message page with an optional error paragraph.
pub fn message(status: StatusCode, title: &str, text: &str) -> Response {
    let body = format!("<h1>{}</h1><p class=\"lead\">{}</p>", esc(title), esc(text));
    (status, layout(title, &body)).into_response()
}

/// `<p class="err">` for an optional error, escaped.
pub fn error_line(error: Option<&str>) -> String {
    error
        .map(|e| format!("<p class=\"err\" role=\"alert\">{}</p>", esc(e)))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup_and_quotes() {
        assert_eq!(esc(r#"<a href="x">&'"#), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
    }

    #[test]
    fn favicon_assets_are_embedded() {
        assert!(FAVICON_SVG.starts_with(b"<svg"));
        // ICO header: reserved 0, type 1 (icon), three images.
        assert_eq!(&FAVICON_ICO[..6], &[0, 0, 1, 0, 3, 0]);
        let Html(page) = layout("t", "b");
        assert!(page.contains(r#"href="/favicon.svg""#));
    }

    #[test]
    fn layout_escapes_title() {
        let Html(page) = layout("<script>", "body");
        assert!(page.contains("&lt;script&gt; · authcraft"));
        assert!(!page.contains("<script>"));
    }
}
