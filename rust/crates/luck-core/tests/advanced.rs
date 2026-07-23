use luck_core::{
    apply_diff, decode_binary, diff_collections, encode_binary, BinaryLimits, CommitMetadata,
    ConflictStrategy, Cookie, CookieCanonicalizer, CookieCollection, CookieStatistics, CookieStore,
    DomainIndex, SameSite,
};

fn cookie(name: &str, value: &str, domain: &str) -> Cookie {
    let mut cookie = Cookie::new(name, value);
    cookie.domain = domain.into();
    cookie.path = "/".into();
    cookie.secure = true;
    cookie.http_only = true;
    cookie.same_site = SameSite::Lax;
    cookie
}

#[test]
fn canonicalizer_normalizes_domain_path_and_flags() {
    let mut value = cookie("__Host-session", "a", " .Example.COM. ");
    value.path = "/a/../".into();
    value.secure = false;
    value.host_only = false;
    let report = CookieCanonicalizer::default().canonicalize(&mut value);
    assert!(report.changed());
    assert_eq!(value.domain, "example.com");
    assert_eq!(value.path, "/");
    assert!(value.secure);
    assert!(value.host_only);
}

#[test]
fn diff_round_trip_restores_collection() {
    let before = CookieCollection::new(vec![cookie("a", "1", "example.com")]);
    let after = CookieCollection::new(vec![
        cookie("a", "2", "example.com"),
        cookie("b", "3", "example.com"),
    ]);
    let diff = diff_collections(&before, &after);
    let applied = apply_diff(&before, &diff, ConflictStrategy::Reject);
    assert!(applied.conflicts.is_empty());
    assert_eq!(applied.collection, after);
    let restored = apply_diff(&after, &diff.invert(), ConflictStrategy::Reject);
    assert_eq!(restored.collection, before);
}

#[test]
fn binary_round_trip_preserves_cookie_data() {
    let collection = CookieCollection::new(vec![cookie("session", "secret", ".example.com")]);
    let encoded = encode_binary(&collection).unwrap();
    let decoded = decode_binary(&encoded, &BinaryLimits::default()).unwrap();
    assert_eq!(decoded.collection, collection);
    assert_eq!(decoded.trailing_bytes, 0);
}

#[test]
fn binary_checksum_detects_corruption() {
    let collection = CookieCollection::new(vec![cookie("a", "1", "example.com")]);
    let mut encoded = encode_binary(&collection).unwrap();
    *encoded.last_mut().unwrap() ^= 0xff;
    assert!(decode_binary(&encoded, &BinaryLimits::default()).is_err());
}

#[test]
fn domain_index_matches_parent_domains() {
    let collection = CookieCollection::new(vec![
        cookie("root", "1", ".example.com"),
        cookie("api", "2", "api.example.com"),
    ]);
    let index = DomainIndex::build(&collection);
    assert_eq!(index.matching_host("api.example.com").len(), 2);
    assert!(index.validate_against(&collection).valid);
}

#[test]
fn statistics_count_security_properties() {
    let mut insecure = cookie("theme", "dark", "example.com");
    insecure.secure = false;
    insecure.http_only = false;
    let stats = CookieStatistics::compute(&CookieCollection::new(vec![
        cookie("session", "secret", "example.com"),
        insecure,
    ]));
    assert_eq!(stats.total, 2);
    assert_eq!(stats.secure, 1);
    assert_eq!(stats.http_only, 1);
    assert_eq!(stats.domains, 1);
}

#[test]
fn store_commits_and_rolls_back_transaction() {
    let initial = CookieCollection::new(vec![cookie("a", "1", "example.com")]);
    let mut store = CookieStore::from_collection(initial.clone(), 10);
    let mut transaction = store.begin();
    transaction.insert(cookie("b", "2", "example.com"));
    let record = store
        .commit(transaction, CommitMetadata::new("test", "add b"))
        .unwrap();
    assert_eq!(record.revision, 1);
    assert_eq!(store.len(), 2);
    store
        .rollback_last(CommitMetadata::new("test", "undo add b"))
        .unwrap();
    assert_eq!(store.collection(), initial);
}
