use crate::error::Result;
use crate::model::CookieCollection;

pub(super) fn serialize(collection: &CookieCollection) -> Result<String> {
    let joined = collection
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, sanitize(&cookie.value)))
        .collect::<Vec<_>>()
        .join("; ");
    Ok(format!("Cookie: {joined}"))
}

fn sanitize(value: &str) -> String {
    value.replace(['\r', '\n'], "")
}
