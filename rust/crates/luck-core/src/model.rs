use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SameSite {
    None,
    Lax,
    Strict,
    #[default]
    Unspecified,
}

impl SameSite {
    pub fn from_label(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "none" | "no_restriction" | "norestriction" => Self::None,
            "lax" => Self::Lax,
            "strict" => Self::Strict,
            _ => Self::Unspecified,
        }
    }

    pub fn as_chrome_str(&self) -> &'static str {
        match self {
            Self::None => "no_restriction",
            Self::Lax => "lax",
            Self::Strict => "strict",
            Self::Unspecified => "unspecified",
        }
    }

    pub fn as_set_cookie_str(&self) -> Option<&'static str> {
        match self {
            Self::None => Some("None"),
            Self::Lax => Some("Lax"),
            Self::Strict => Some("Strict"),
            Self::Unspecified => None,
        }
    }
}

impl fmt::Display for SameSite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_chrome_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CookieKey {
    pub store_id: String,
    pub partition_site: String,
    pub domain: String,
    pub path: String,
    pub name: String,
}

impl CookieKey {
    pub fn new(cookie: &Cookie) -> Self {
        Self {
            store_id: cookie.store_id.clone().unwrap_or_default(),
            partition_site: cookie.partition_site.clone().unwrap_or_default(),
            domain: cookie.domain.clone(),
            path: cookie.path.clone(),
            name: cookie.name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cookie {
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub secure: bool,
    #[serde(default, alias = "http_only")]
    pub http_only: bool,
    #[serde(default, alias = "same_site")]
    pub same_site: SameSite,
    #[serde(default, alias = "expires", alias = "expiry")]
    pub expiration_date: Option<f64>,
    #[serde(default)]
    pub session: bool,
    #[serde(default)]
    pub host_only: bool,
    #[serde(default)]
    pub store_id: Option<String>,
    #[serde(default)]
    pub partition_site: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl Cookie {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: String::new(),
            path: default_path(),
            secure: false,
            http_only: false,
            same_site: SameSite::Unspecified,
            expiration_date: None,
            session: true,
            host_only: false,
            store_id: None,
            partition_site: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn key(&self) -> CookieKey {
        CookieKey::new(self)
    }

    pub fn is_expired_at(&self, unix_seconds: f64) -> bool {
        self.expiration_date.is_some_and(|expiry| expiry <= unix_seconds)
    }

    pub fn is_expired_now(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs_f64())
            .unwrap_or_default();
        self.is_expired_at(now)
    }

    pub fn is_host_prefix(&self) -> bool {
        self.name.starts_with("__Host-")
    }

    pub fn is_secure_prefix(&self) -> bool {
        self.name.starts_with("__Secure-")
    }

    pub fn normalized_domain(&self) -> &str {
        self.domain.strip_prefix('.').unwrap_or(&self.domain)
    }

    pub fn domain_matches(&self, hostname: &str) -> bool {
        let cookie_domain = self.normalized_domain().trim_end_matches('.').to_ascii_lowercase();
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        host == cookie_domain || host.ends_with(&format!(".{cookie_domain}"))
    }

    pub fn path_matches(&self, request_path: &str) -> bool {
        let cookie_path = if self.path.is_empty() { "/" } else { &self.path };
        if request_path == cookie_path {
            return true;
        }
        if !request_path.starts_with(cookie_path) {
            return false;
        }
        cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
    }

    pub fn effective_session(&self) -> bool {
        self.session || self.expiration_date.is_none()
    }

    pub fn estimated_bytes(&self) -> usize {
        self.name.len()
            + self.value.len()
            + self.domain.len()
            + self.path.len()
            + self.store_id.as_deref().map(str::len).unwrap_or(0)
            + self.partition_site.as_deref().map(str::len).unwrap_or(0)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CookieCollection {
    cookies: Vec<Cookie>,
}

impl CookieCollection {
    pub fn new(cookies: Vec<Cookie>) -> Self {
        Self { cookies }
    }

    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Cookie> {
        self.cookies.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Cookie> {
        self.cookies.iter_mut()
    }

    pub fn into_vec(self) -> Vec<Cookie> {
        self.cookies
    }

    pub fn push(&mut self, cookie: Cookie) {
        self.cookies.push(cookie);
    }

    pub fn deduplicate_last_wins(&mut self) -> usize {
        let mut seen = HashSet::new();
        let original = self.cookies.len();
        self.cookies.reverse();
        self.cookies.retain(|cookie| seen.insert(cookie.key()));
        self.cookies.reverse();
        original - self.cookies.len()
    }

    pub fn remove_expired_at(&mut self, unix_seconds: f64) -> usize {
        let original = self.cookies.len();
        self.cookies.retain(|cookie| !cookie.is_expired_at(unix_seconds));
        original - self.cookies.len()
    }

    pub fn sort_stable(&mut self) {
        self.cookies.sort_by(|left, right| {
            left.domain
                .cmp(&right.domain)
                .then_with(|| left.path.cmp(&right.path))
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.store_id.cmp(&right.store_id))
        });
    }

    pub fn by_domain<'a>(&'a self, hostname: &'a str) -> impl Iterator<Item = &'a Cookie> {
        self.cookies.iter().filter(move |cookie| cookie.domain_matches(hostname))
    }

    pub fn total_estimated_bytes(&self) -> usize {
        self.cookies.iter().map(Cookie::estimated_bytes).sum()
    }
}

impl IntoIterator for CookieCollection {
    type Item = Cookie;
    type IntoIter = std::vec::IntoIter<Cookie>;

    fn into_iter(self) -> Self::IntoIter {
        self.cookies.into_iter()
    }
}

impl<'a> IntoIterator for &'a CookieCollection {
    type Item = &'a Cookie;
    type IntoIter = std::slice::Iter<'a, Cookie>;

    fn into_iter(self) -> Self::IntoIter {
        self.cookies.iter()
    }
}

fn default_path() -> String {
    "/".to_owned()
}
