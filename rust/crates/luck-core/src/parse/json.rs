use super::{warning, with_defaults, ParseWarning};
use crate::error::Result;
use crate::model::Cookie;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub(super) fn parse(input: &str, fallback_domain: &str) -> Result<(Vec<Cookie>, Vec<ParseWarning>)> {
    let value: Value = serde_json::from_str(input)?;
    let mut warnings = Vec::new();
    let cookies = match value {
        Value::Array(items) => parse_array(items, fallback_domain, &mut warnings),
        Value::Object(mut object) => {
            if let Some(Value::Array(items)) = object.remove("cookies") {
                parse_array(items, fallback_domain, &mut warnings)
            } else if object.contains_key("name") {
                vec![cookie_from_object(object, fallback_domain, &mut warnings, None)]
            } else {
                parse_map(object, fallback_domain, &mut warnings)
            }
        }
        _ => {
            warnings.push(warning("json.shape", "JSON root must be an object or array", None));
            Vec::new()
        }
    };
    Ok((cookies, warnings))
}

fn parse_array(items: Vec<Value>, fallback_domain: &str, warnings: &mut Vec<ParseWarning>) -> Vec<Cookie> {
    items
        .into_iter()
        .enumerate()
        .filter_map(|(index, item)| match item {
            Value::Object(object) => Some(cookie_from_object(object, fallback_domain, warnings, Some(index + 1))),
            _ => {
                warnings.push(warning("json.item", "ignored non-object array item", Some(index + 1)));
                None
            }
        })
        .collect()
}

fn parse_map(object: Map<String, Value>, fallback_domain: &str, warnings: &mut Vec<ParseWarning>) -> Vec<Cookie> {
    object
        .into_iter()
        .map(|(name, value)| {
            let value = match value {
                Value::String(text) => text,
                other => serde_json::to_string(&other).unwrap_or_default(),
            };
            let mut cookie = Cookie::new(name, value);
            cookie.domain = fallback_domain.to_owned();
            if cookie.domain.is_empty() {
                warnings.push(warning("json.map_domain", "map-style JSON needs a fallback domain", None));
            }
            cookie
        })
        .collect()
}

fn cookie_from_object(
    mut object: Map<String, Value>,
    fallback_domain: &str,
    warnings: &mut Vec<ParseWarning>,
    line: Option<usize>,
) -> Cookie {
    normalize_alias(&mut object, "http_only", "httpOnly");
    normalize_alias(&mut object, "same_site", "sameSite");
    normalize_alias(&mut object, "expires", "expirationDate");
    normalize_alias(&mut object, "expiry", "expirationDate");
    let metadata = collect_unknown_metadata(&object);
    let serialized = Value::Object(object);
    let mut cookie: Cookie = match serde_json::from_value(serialized) {
        Ok(cookie) => cookie,
        Err(error) => {
            warnings.push(warning("json.cookie", format!("cookie object could not be decoded: {error}"), line));
            Cookie::new("", "")
        }
    };
    cookie.metadata.extend(metadata);
    if cookie.expiration_date.is_some_and(|value| value > 1_000_000_000_000.0) {
        cookie.expiration_date = cookie.expiration_date.map(|value| (value / 1000.0).floor());
    }
    cookie.session = cookie.expiration_date.is_none() || cookie.session;
    with_defaults(cookie, fallback_domain)
}

fn normalize_alias(object: &mut Map<String, Value>, from: &str, to: &str) {
    if !object.contains_key(to) {
        if let Some(value) = object.remove(from) {
            object.insert(to.to_owned(), value);
        }
    }
}

fn collect_unknown_metadata(object: &Map<String, Value>) -> BTreeMap<String, String> {
    const KNOWN: &[&str] = &[
        "name", "value", "domain", "path", "secure", "httpOnly", "http_only", "sameSite", "same_site",
        "expirationDate", "expires", "expiry", "session", "hostOnly", "storeId", "partitionSite", "metadata",
    ];
    object
        .iter()
        .filter(|(key, _)| !KNOWN.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string())))
        .collect()
}
