use super::{warning, ParseWarning};
use crate::error::Result;
use crate::model::Cookie;

pub(super) fn parse(input: &str, fallback_domain: &str) -> Result<(Vec<Cookie>, Vec<ParseWarning>)> {
    let mut cookies = Vec::new();
    let mut warnings = Vec::new();
    for (index, raw) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            warnings.push(warning("lines.pair", "ignored line without '='", Some(line_number)));
            continue;
        };
        let mut cookie = Cookie::new(name.trim(), value.trim());
        cookie.domain = fallback_domain.to_owned();
        cookies.push(cookie);
    }
    Ok((cookies, warnings))
}
