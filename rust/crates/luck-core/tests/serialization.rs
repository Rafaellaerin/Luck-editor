use luck_core::{serialize_cookies, Cookie, CookieCollection, OutputFormat, SerializeOptions};

fn collection() -> CookieCollection {
    let mut cookie = Cookie::new("session", "secret");
    cookie.domain = ".example.com".into();
    cookie.secure = true;
    cookie.http_only = true;
    CookieCollection::new(vec![cookie])
}

#[test]
fn redacted_json_hides_values() {
    let options = SerializeOptions { format: OutputFormat::RedactedJson, include_http_only: true, ..SerializeOptions::default() };
    let output = serialize_cookies(&collection(), &options).unwrap();
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("secret"));
}

#[test]
fn netscape_has_header() {
    let options = SerializeOptions { format: OutputFormat::Netscape, include_http_only: true, ..SerializeOptions::default() };
    let output = serialize_cookies(&collection(), &options).unwrap();
    assert!(output.starts_with("# Netscape HTTP Cookie File"));
    assert!(output.contains("#HttpOnly_.example.com"));
}

#[test]
fn header_filters_http_only_by_default() {
    let options = SerializeOptions { format: OutputFormat::CookieHeader, ..SerializeOptions::default() };
    assert_eq!(serialize_cookies(&collection(), &options).unwrap(), "Cookie: ");
}

#[test]
fn curl_shell_quotes_secret() {
    let mut collection = collection();
    collection.iter_mut().next().unwrap().value = "a'b".into();
    let options = SerializeOptions { format: OutputFormat::Curl, include_http_only: true, hostname: "example.com".into(), ..SerializeOptions::default() };
    let output = serialize_cookies(&collection, &options).unwrap();
    assert!(output.contains("'\"'\"'"));
}
