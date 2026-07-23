use super::{warning, ParseWarning};
use crate::error::Result;
use crate::model::{Cookie, SameSite};

pub(super) fn parse(input: &str) -> Result<(Vec<Cookie>, Vec<ParseWarning>)> {
    let mut cookies = Vec::new();
    let mut warnings = Vec::new();
    for (index, raw) in input.lines().enumerate() {
        let line_number = index + 1;
        let mut line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let http_only = if let Some(rest) = line.strip_prefix("#HttpOnly_") {
            line = rest;
            true
        } else {
            false
        };
        if line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 7 {
            warnings.push(warning("netscape.columns", "expected at least seven tab-separated columns", Some(line_number)));
            continue;
        }
        let raw_domain = fields[0].trim();
        let include_subdomains = parse_bool(fields[1]);
        let domain = if include_subdomains && !raw_domain.starts_with('.') {
            format!(".{raw_domain}")
        } else {
            raw_domain.to_owned()
        };
        let expiration = fields[4].trim().parse::<f64>().ok().filter(|value| *value > 0.0);
        let mut cookie = Cookie {
            name: fields[5].trim().to_owned(),
            value: fields[6..].join("\t"),
            domain,
            path: non_empty(fields[2], "/"),
            secure: parse_bool(fields[3]),
            http_only,
            same_site: SameSite::Unspecified,
            expiration_date: expiration,
            session: expiration.is_none(),
            host_only: !include_subdomains,
            store_id: None,
            partition_site: None,
            metadata: Default::default(),
        };
        if fields.len() > 7 {
            cookie.metadata.insert("extra_columns".into(), fields[7..].join("\t"));
            warnings.push(warning("netscape.extra", "preserved extra columns as metadata", Some(line_number)));
        }
        cookies.push(cookie);
    }
    Ok((cookies, warnings))
}

fn parse_bool(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes")
}

fn non_empty(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() { fallback.to_owned() } else { trimmed.to_owned() }
}
