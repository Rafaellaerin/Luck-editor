use luck_core::{detect_format, parse_cookies, InputFormat, ParseOptions, SameSite};

#[test]
fn detects_json() {
    assert_eq!(detect_format(r#"[{"name":"a","value":"b"}]"#), InputFormat::Json);
}

#[test]
fn parses_json_array() {
    let report = parse_cookies(
        r#"[{"name":"session","value":"abc","domain":"example.com","path":"/","secure":true,"httpOnly":true,"sameSite":"lax"}]"#,
        &ParseOptions::default(),
    )
    .unwrap();
    assert_eq!(report.cookies.len(), 1);
    let cookie = report.cookies.iter().next().unwrap();
    assert_eq!(cookie.name, "session");
    assert_eq!(cookie.same_site, SameSite::Lax);
}

#[test]
fn parses_json_map() {
    let options = ParseOptions { fallback_domain: "example.com".into(), ..ParseOptions::default() };
    let report = parse_cookies(r#"{"a":"1","b":"2"}"#, &options).unwrap();
    assert_eq!(report.cookies.len(), 2);
}

#[test]
fn parses_netscape() {
    let input = ".example.com\tTRUE\t/\tTRUE\t2000000000\tsession\tabc";
    let report = parse_cookies(input, &ParseOptions::default()).unwrap();
    let cookie = report.cookies.iter().next().unwrap();
    assert!(cookie.secure);
    assert_eq!(cookie.domain, ".example.com");
}

#[test]
fn parses_cookie_header() {
    let options = ParseOptions { fallback_domain: "example.com".into(), ..ParseOptions::default() };
    let report = parse_cookies("Cookie: a=1; b=2", &options).unwrap();
    assert_eq!(report.cookies.len(), 2);
}

#[test]
fn parses_set_cookie() {
    let options = ParseOptions { fallback_domain: "example.com".into(), ..ParseOptions::default() };
    let report = parse_cookies("Set-Cookie: session=abc; Path=/; Secure; HttpOnly; SameSite=Lax", &options).unwrap();
    let cookie = report.cookies.iter().next().unwrap();
    assert!(cookie.secure);
    assert!(cookie.http_only);
    assert_eq!(cookie.same_site, SameSite::Lax);
}

#[test]
fn rejects_invalid_cookie_name() {
    let options = ParseOptions { fallback_domain: "example.com".into(), ..ParseOptions::default() };
    let report = parse_cookies("bad name=value", &options).unwrap();
    assert_eq!(report.cookies.len(), 0);
    assert_eq!(report.rejected, 1);
}

#[test]
fn deduplicates_last_cookie() {
    let options = ParseOptions { fallback_domain: "example.com".into(), ..ParseOptions::default() };
    let report = parse_cookies("a=1\na=2", &options).unwrap();
    assert_eq!(report.cookies.len(), 1);
    assert_eq!(report.cookies.iter().next().unwrap().value, "2");
    assert_eq!(report.duplicates_removed, 1);
}
