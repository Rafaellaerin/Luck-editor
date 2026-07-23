use super::{warning, ParseWarning};
use crate::error::Result;
use crate::model::{Cookie, SameSite};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn parse(input: &str, fallback_domain: &str) -> Result<(Vec<Cookie>, Vec<ParseWarning>)> {
    let mut cookies = Vec::new();
    let mut warnings = Vec::new();
    for (index, raw) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = strip_set_cookie_prefix(raw.trim());
        if line.is_empty() {
            continue;
        }
        let mut segments = split_attributes(line);
        let Some(pair) = segments.first().cloned() else {
            continue;
        };
        segments.remove(0);
        let Some((name, value)) = pair.split_once('=') else {
            warnings.push(warning("set_cookie.pair", "missing cookie name/value pair", Some(line_number)));
            continue;
        };
        let mut cookie = Cookie::new(name.trim(), value.trim());
        cookie.domain = fallback_domain.to_owned();
        for segment in segments {
            let (name, value) = segment.split_once('=').map_or((segment.as_str(), ""), |pair| pair);
            match name.trim().to_ascii_lowercase().as_str() {
                "domain" => {
                    cookie.domain = value.trim().to_owned();
                    cookie.host_only = false;
                }
                "path" => cookie.path = non_empty(value, "/"),
                "secure" => cookie.secure = true,
                "httponly" => cookie.http_only = true,
                "samesite" => cookie.same_site = SameSite::from_label(value),
                "partitioned" => {
                    cookie.metadata.insert("partitioned".into(), "true".into());
                    cookie.secure = true;
                }
                "priority" => {
                    cookie.metadata.insert("priority".into(), value.trim().to_owned());
                }
                "max-age" => match value.trim().parse::<i64>() {
                    Ok(seconds) => {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|duration| duration.as_secs_f64())
                            .unwrap_or_default();
                        cookie.expiration_date = Some(now + seconds as f64);
                        cookie.session = false;
                    }
                    Err(_) => warnings.push(warning("set_cookie.max_age", "invalid Max-Age attribute", Some(line_number))),
                },
                "expires" => {
                    cookie.metadata.insert("expires_raw".into(), value.trim().to_owned());
                    warnings.push(warning(
                        "set_cookie.expires_raw",
                        "Expires was preserved as metadata; use Max-Age or JSON for exact conversion",
                        Some(line_number),
                    ));
                }
                "" => warnings.push(warning("set_cookie.empty_attribute", "ignored empty attribute", Some(line_number))),
                unknown => warnings.push(warning(
                    "set_cookie.unknown_attribute",
                    format!("ignored unsupported attribute {unknown}"),
                    Some(line_number),
                )),
            }
        }
        cookie.session = cookie.expiration_date.is_none();
        cookies.push(cookie);
    }
    Ok((cookies, warnings))
}

fn strip_set_cookie_prefix(value: &str) -> &str {
    const PREFIX: &str = "set-cookie:";
    if value.len() >= PREFIX.len() && value[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        value[PREFIX.len()..].trim_start()
    } else {
        value
    }
}

fn split_attributes(line: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => {
                current.push(character);
                escaped = true;
            }
            '"' => {
                quoted = !quoted;
                current.push(character);
            }
            ';' if !quoted => {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    parts.push(trimmed.to_owned());
                }
                current.clear();
            }
            _ => current.push(character),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_owned());
    }
    parts
}

fn non_empty(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() { fallback.to_owned() } else { trimmed.to_owned() }
}
