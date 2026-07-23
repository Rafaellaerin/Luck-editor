use crate::error::Result;
use crate::model::CookieCollection;
use std::fmt::Write;

pub(super) fn serialize(collection: &CookieCollection) -> Result<String> {
    let mut output = String::new();
    for cookie in collection {
        write!(output, "Set-Cookie: {}={}; Path={}", cookie.name, sanitize(&cookie.value), cookie.path)
            .map_err(|error| crate::error::LuckError::Serialization(error.to_string()))?;
        if cookie.domain.starts_with('.') {
            write!(output, "; Domain={}", cookie.domain)
                .map_err(|error| crate::error::LuckError::Serialization(error.to_string()))?;
        }
        if let Some(expiration) = cookie.expiration_date {
            write!(output, "; Max-Age={}", lifetime_from_now(expiration))
                .map_err(|error| crate::error::LuckError::Serialization(error.to_string()))?;
        }
        if cookie.secure {
            output.push_str("; Secure");
        }
        if cookie.http_only {
            output.push_str("; HttpOnly");
        }
        if let Some(value) = cookie.same_site.as_set_cookie_str() {
            write!(output, "; SameSite={value}")
                .map_err(|error| crate::error::LuckError::Serialization(error.to_string()))?;
        }
        output.push('\n');
    }
    Ok(output)
}

fn sanitize(value: &str) -> String {
    value.replace(['\r', '\n', ';'], "")
}

fn lifetime_from_now(expiration: f64) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or_default();
    (expiration - now).max(0.0).floor() as i64
}
