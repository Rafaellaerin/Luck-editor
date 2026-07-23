use luck_core::{Cookie, CookieCollection, CookiePolicy, CookieQuery, PolicyDecision, QueryExpr, SameSite};

fn cookie(name: &str, domain: &str, secure: bool) -> Cookie {
    let mut cookie = Cookie::new(name, "value");
    cookie.domain = domain.into();
    cookie.secure = secure;
    cookie.http_only = true;
    cookie.same_site = SameSite::Lax;
    cookie
}

#[test]
fn policy_denies_insecure_cookie_when_required() {
    let policy = CookiePolicy { require_secure: true, ..CookiePolicy::default() };
    assert!(matches!(policy.evaluate(&cookie("a", "example.com", false)), PolicyDecision::Deny(_)));
}

#[test]
fn policy_allowlist_accepts_subdomain() {
    let policy = CookiePolicy { allow_domains: vec!["example.com".into()], ..CookiePolicy::default() };
    assert!(policy.evaluate(&cookie("a", "api.example.com", true)).is_allowed());
}

#[test]
fn query_matches_name_and_secure() {
    let expression = QueryExpr::And(vec![QueryExpr::NameContains("session".into()), QueryExpr::Secure(true)]);
    assert!(expression.matches(&cookie("session_id", "example.com", true)));
    assert!(!expression.matches(&cookie("session_id", "example.com", false)));
}

#[test]
fn parses_query_language() {
    let query = CookieQuery::parse("name:session and secure:true").unwrap();
    let collection = CookieCollection::new(vec![
        cookie("session", "example.com", true),
        cookie("theme", "example.com", true),
        cookie("session", "example.com", false),
    ]);
    let result = query.execute(&collection);
    assert_eq!(result.len(), 1);
}

#[test]
fn query_supports_grouping_and_not() {
    let query = CookieQuery::parse("(domain:example.com or domain:example.org) and not session:true").unwrap();
    let mut persistent = cookie("a", "example.com", true);
    persistent.expiration_date = Some(2_000_000_000.0);
    persistent.session = false;
    let collection = CookieCollection::new(vec![persistent, cookie("b", "example.org", true)]);
    assert_eq!(query.execute(&collection).len(), 1);
}
