use luck_core::{validate_cookie, Cookie, SameSite, ValidationConfig};

fn valid_cookie() -> Cookie {
    let mut cookie = Cookie::new("session", "abc");
    cookie.domain = "example.com".into();
    cookie.path = "/".into();
    cookie.secure = true;
    cookie.http_only = true;
    cookie.same_site = SameSite::Lax;
    cookie
}

#[test]
fn accepts_valid_cookie() {
    assert!(validate_cookie(&valid_cookie(), &ValidationConfig::default()).is_valid());
}

#[test]
fn rejects_spaces_in_name() {
    let mut cookie = valid_cookie();
    cookie.name = "bad name".into();
    assert!(!validate_cookie(&cookie, &ValidationConfig::default()).is_valid());
}

#[test]
fn rejects_same_site_none_without_secure() {
    let mut cookie = valid_cookie();
    cookie.secure = false;
    cookie.same_site = SameSite::None;
    assert!(!validate_cookie(&cookie, &ValidationConfig::default()).is_valid());
}

#[test]
fn enforces_host_prefix() {
    let mut cookie = valid_cookie();
    cookie.name = "__Host-session".into();
    cookie.path = "/admin".into();
    cookie.host_only = false;
    let report = validate_cookie(&cookie, &ValidationConfig::default());
    assert!(report.errors().count() >= 2);
}

#[test]
fn validates_ipv4_domains() {
    let mut cookie = valid_cookie();
    cookie.domain = "127.0.0.1".into();
    assert!(validate_cookie(&cookie, &ValidationConfig::default()).is_valid());
}

#[test]
fn rejects_control_characters() {
    let mut cookie = valid_cookie();
    cookie.value = "hello\nworld".into();
    assert!(!validate_cookie(&cookie, &ValidationConfig::default()).is_valid());
}
