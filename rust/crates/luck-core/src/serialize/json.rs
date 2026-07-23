use super::SerializeOptions;
use crate::error::Result;
use crate::model::{Cookie, CookieCollection};

pub(super) fn serialize(collection: &CookieCollection, options: &SerializeOptions, redacted: bool) -> Result<String> {
    let cookies: Vec<Cookie> = collection
        .iter()
        .cloned()
        .map(|mut cookie| {
            if redacted {
                cookie.value = "[REDACTED]".into();
            }
            if !options.include_metadata {
                cookie.metadata.clear();
            }
            cookie
        })
        .collect();
    if options.pretty_json {
        Ok(serde_json::to_string_pretty(&cookies)?)
    } else {
        Ok(serde_json::to_string(&cookies)?)
    }
}
