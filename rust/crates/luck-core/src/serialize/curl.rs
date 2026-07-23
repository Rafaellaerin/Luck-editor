use crate::error::Result;
use crate::model::CookieCollection;

pub(super) fn serialize(collection: &CookieCollection, hostname: &str) -> Result<String> {
    let cookies = collection
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ");
    Ok(format!(
        "curl --fail --show-error --location --cookie {} {}",
        shell_quote(&cookies),
        shell_quote(&format!("https://{}/", normalize_hostname(hostname)))
    ))
}

fn normalize_hostname(hostname: &str) -> String {
    hostname
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_matches('/')
        .to_owned()
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
