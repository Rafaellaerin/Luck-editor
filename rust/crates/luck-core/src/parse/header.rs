use super::{warning, ParseWarning};
use crate::error::Result;
use crate::model::Cookie;

pub(super) fn parse(input: &str, fallback_domain: &str) -> Result<(Vec<Cookie>, Vec<ParseWarning>)> {
    let compact = input.lines().map(str::trim).filter(|line| !line.is_empty()).collect::<Vec<_>>().join("; ");
    let header = strip_ascii_prefix(&compact, "cookie:").trim();
    let mut cookies = Vec::new();
    let mut warnings = Vec::new();
    for (index, pair) in header.split(';').enumerate() {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((name, value)) = pair.split_once('=') else {
            warnings.push(warning("header.pair", format!("ignored pair {} without '='", index + 1), None));
            continue;
        };
        let mut cookie = Cookie::new(name.trim(), value.trim());
        cookie.domain = fallback_domain.to_owned();
        cookies.push(cookie);
    }
    Ok((cookies, warnings))
}

fn strip_ascii_prefix<'a>(value: &'a str, prefix: &str) -> &'a str {
    if value.len() >= prefix.len() && value[..prefix.len()].eq_ignore_ascii_case(prefix) {
        &value[prefix.len()..]
    } else {
        value
    }
}
