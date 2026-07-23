use crate::model::{Cookie, CookieCollection, CookieKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainIndex {
    domains: BTreeMap<String, BTreeSet<CookieKey>>,
    host_only: BTreeSet<CookieKey>,
    secure: BTreeSet<CookieKey>,
    http_only: BTreeSet<CookieKey>,
    session: BTreeSet<CookieKey>,
}

impl DomainIndex {
    pub fn build(collection: &CookieCollection) -> Self {
        let mut index = Self::default();
        for cookie in collection {
            index.insert(cookie);
        }
        index
    }

    pub fn insert(&mut self, cookie: &Cookie) {
        let key = cookie.key();
        let domain = normalize_domain(&cookie.domain);
        self.domains.entry(domain).or_default().insert(key.clone());
        set_membership(&mut self.host_only, &key, cookie.host_only);
        set_membership(&mut self.secure, &key, cookie.secure);
        set_membership(&mut self.http_only, &key, cookie.http_only);
        set_membership(&mut self.session, &key, cookie.effective_session());
    }

    pub fn remove(&mut self, cookie: &Cookie) -> bool {
        let key = cookie.key();
        let domain = normalize_domain(&cookie.domain);
        let mut removed = false;
        let mut delete_domain = false;
        if let Some(keys) = self.domains.get_mut(&domain) {
            removed = keys.remove(&key);
            delete_domain = keys.is_empty();
        }
        if delete_domain {
            self.domains.remove(&domain);
        }
        self.host_only.remove(&key);
        self.secure.remove(&key);
        self.http_only.remove(&key);
        self.session.remove(&key);
        removed
    }

    pub fn replace(&mut self, before: &Cookie, after: &Cookie) {
        self.remove(before);
        self.insert(after);
    }

    pub fn exact_domain(&self, domain: &str) -> Vec<CookieKey> {
        self.domains
            .get(&normalize_domain(domain))
            .map(|keys| keys.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn matching_host(&self, hostname: &str) -> Vec<CookieKey> {
        let hostname = normalize_domain(hostname);
        let labels: Vec<&str> = hostname.split('.').filter(|label| !label.is_empty()).collect();
        let mut keys = BTreeSet::new();
        for start in 0..labels.len() {
            let candidate = labels[start..].join(".");
            if let Some(domain_keys) = self.domains.get(&candidate) {
                keys.extend(domain_keys.iter().cloned());
            }
        }
        keys.into_iter().collect()
    }

    pub fn subdomains_of(&self, parent: &str) -> Vec<(String, Vec<CookieKey>)> {
        let parent = normalize_domain(parent);
        self.domains
            .iter()
            .filter(|(domain, _)| *domain == &parent || domain.ends_with(&format!(".{parent}")))
            .map(|(domain, keys)| (domain.clone(), keys.iter().cloned().collect()))
            .collect()
    }

    pub fn secure_keys(&self) -> impl Iterator<Item = &CookieKey> {
        self.secure.iter()
    }

    pub fn insecure_keys(&self, collection: &CookieCollection) -> Vec<CookieKey> {
        collection
            .iter()
            .filter(|cookie| !self.secure.contains(&cookie.key()))
            .map(Cookie::key)
            .collect()
    }

    pub fn http_only_keys(&self) -> impl Iterator<Item = &CookieKey> {
        self.http_only.iter()
    }

    pub fn session_keys(&self) -> impl Iterator<Item = &CookieKey> {
        self.session.iter()
    }

    pub fn persistent_keys(&self, collection: &CookieCollection) -> Vec<CookieKey> {
        collection
            .iter()
            .filter(|cookie| !self.session.contains(&cookie.key()))
            .map(Cookie::key)
            .collect()
    }

    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    pub fn cookie_count(&self) -> usize {
        self.domains.values().map(BTreeSet::len).sum()
    }

    pub fn domains(&self) -> impl Iterator<Item = (&str, usize)> {
        self.domains.iter().map(|(domain, keys)| (domain.as_str(), keys.len()))
    }

    pub fn largest_domains(&self, limit: usize) -> Vec<(String, usize)> {
        let mut entries: Vec<_> = self
            .domains
            .iter()
            .map(|(domain, keys)| (domain.clone(), keys.len()))
            .collect();
        entries.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        entries.truncate(limit);
        entries
    }

    pub fn validate_against(&self, collection: &CookieCollection) -> IndexValidationReport {
        let rebuilt = Self::build(collection);
        let mut issues = Vec::new();
        if self.domains != rebuilt.domains {
            issues.push("domain mapping differs from collection".to_owned());
        }
        if self.host_only != rebuilt.host_only {
            issues.push("host-only membership differs from collection".to_owned());
        }
        if self.secure != rebuilt.secure {
            issues.push("secure membership differs from collection".to_owned());
        }
        if self.http_only != rebuilt.http_only {
            issues.push("HttpOnly membership differs from collection".to_owned());
        }
        if self.session != rebuilt.session {
            issues.push("session membership differs from collection".to_owned());
        }
        IndexValidationReport { valid: issues.is_empty(), issues }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexValidationReport {
    pub valid: bool,
    pub issues: Vec<String>,
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase()
}

fn set_membership(set: &mut BTreeSet<CookieKey>, key: &CookieKey, included: bool) {
    if included {
        set.insert(key.clone());
    } else {
        set.remove(key);
    }
}
