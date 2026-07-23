use crate::model::{Cookie, CookieCollection, SameSite};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalizationConfig {
    pub lowercase_domains: bool,
    pub remove_trailing_domain_dot: bool,
    pub normalize_paths: bool,
    pub secure_same_site_none: bool,
    pub enforce_prefix_rules: bool,
    pub infer_session_flag: bool,
    pub trim_names: bool,
    pub trim_domains: bool,
    pub maximum_path_segments: usize,
}

impl Default for CanonicalizationConfig {
    fn default() -> Self {
        Self {
            lowercase_domains: true,
            remove_trailing_domain_dot: true,
            normalize_paths: true,
            secure_same_site_none: true,
            enforce_prefix_rules: true,
            infer_session_flag: true,
            trim_names: true,
            trim_domains: true,
            maximum_path_segments: 256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalizationChange {
    TrimmedName,
    TrimmedDomain,
    LowercasedDomain,
    RemovedTrailingDomainDot,
    NormalizedPath,
    EnabledSecureForSameSiteNone,
    EnabledSecureForSecurePrefix,
    EnabledSecureForHostPrefix,
    SetHostPrefixPath,
    SetHostOnlyForHostPrefix,
    InferredSession,
    InferredPersistent,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalizationReport {
    pub changes: BTreeSet<CanonicalizationChange>,
    pub warnings: Vec<String>,
}

impl CanonicalizationReport {
    pub fn changed(&self) -> bool {
        !self.changes.is_empty()
    }

    pub fn merge(&mut self, other: Self) {
        self.changes.extend(other.changes);
        self.warnings.extend(other.warnings);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionCanonicalizationReport {
    pub cookie_reports: Vec<CanonicalizationReport>,
    pub duplicates_removed: usize,
    pub total_changes: usize,
}

#[derive(Debug, Clone)]
pub struct CookieCanonicalizer {
    config: CanonicalizationConfig,
}

impl CookieCanonicalizer {
    pub fn new(config: CanonicalizationConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &CanonicalizationConfig {
        &self.config
    }

    pub fn canonicalize(&self, cookie: &mut Cookie) -> CanonicalizationReport {
        let mut report = CanonicalizationReport::default();
        self.canonicalize_name(cookie, &mut report);
        self.canonicalize_domain(cookie, &mut report);
        self.canonicalize_path(cookie, &mut report);
        self.canonicalize_security(cookie, &mut report);
        self.canonicalize_lifetime(cookie, &mut report);
        report
    }

    pub fn canonicalized(&self, mut cookie: Cookie) -> (Cookie, CanonicalizationReport) {
        let report = self.canonicalize(&mut cookie);
        (cookie, report)
    }

    pub fn canonicalize_collection(
        &self,
        collection: &mut CookieCollection,
    ) -> CollectionCanonicalizationReport {
        let mut reports = Vec::with_capacity(collection.len());
        let mut total_changes = 0;
        for cookie in collection.iter_mut() {
            let report = self.canonicalize(cookie);
            total_changes += report.changes.len();
            reports.push(report);
        }
        let duplicates_removed = collection.deduplicate_last_wins();
        collection.sort_stable();
        CollectionCanonicalizationReport {
            cookie_reports: reports,
            duplicates_removed,
            total_changes,
        }
    }

    fn canonicalize_name(&self, cookie: &mut Cookie, report: &mut CanonicalizationReport) {
        if self.config.trim_names {
            let trimmed = cookie.name.trim();
            if trimmed != cookie.name {
                cookie.name = trimmed.to_owned();
                report.changes.insert(CanonicalizationChange::TrimmedName);
            }
        }
    }

    fn canonicalize_domain(&self, cookie: &mut Cookie, report: &mut CanonicalizationReport) {
        if self.config.trim_domains {
            let trimmed = cookie.domain.trim();
            if trimmed != cookie.domain {
                cookie.domain = trimmed.to_owned();
                report.changes.insert(CanonicalizationChange::TrimmedDomain);
            }
        }
        if self.config.lowercase_domains {
            let lowered = cookie.domain.to_ascii_lowercase();
            if lowered != cookie.domain {
                cookie.domain = lowered;
                report.changes.insert(CanonicalizationChange::LowercasedDomain);
            }
        }
        if self.config.remove_trailing_domain_dot {
            let trimmed = cookie.domain.trim_end_matches('.');
            if trimmed != cookie.domain {
                cookie.domain = trimmed.to_owned();
                report
                    .changes
                    .insert(CanonicalizationChange::RemovedTrailingDomainDot);
            }
        }
        cookie.host_only = !cookie.domain.starts_with('.');
    }

    fn canonicalize_path(&self, cookie: &mut Cookie, report: &mut CanonicalizationReport) {
        if !self.config.normalize_paths {
            return;
        }
        let normalized = normalize_path(&cookie.path, self.config.maximum_path_segments);
        if normalized != cookie.path {
            cookie.path = normalized;
            report.changes.insert(CanonicalizationChange::NormalizedPath);
        }
    }

    fn canonicalize_security(&self, cookie: &mut Cookie, report: &mut CanonicalizationReport) {
        if self.config.secure_same_site_none && cookie.same_site == SameSite::None && !cookie.secure {
            cookie.secure = true;
            report
                .changes
                .insert(CanonicalizationChange::EnabledSecureForSameSiteNone);
        }
        if !self.config.enforce_prefix_rules {
            return;
        }
        if cookie.is_secure_prefix() && !cookie.secure {
            cookie.secure = true;
            report
                .changes
                .insert(CanonicalizationChange::EnabledSecureForSecurePrefix);
        }
        if cookie.is_host_prefix() {
            if !cookie.secure {
                cookie.secure = true;
                report
                    .changes
                    .insert(CanonicalizationChange::EnabledSecureForHostPrefix);
            }
            if cookie.path != "/" {
                cookie.path = "/".to_owned();
                report
                    .changes
                    .insert(CanonicalizationChange::SetHostPrefixPath);
            }
            if !cookie.host_only || cookie.domain.starts_with('.') {
                cookie.domain = cookie.domain.trim_start_matches('.').to_owned();
                cookie.host_only = true;
                report
                    .changes
                    .insert(CanonicalizationChange::SetHostOnlyForHostPrefix);
            }
        }
    }

    fn canonicalize_lifetime(&self, cookie: &mut Cookie, report: &mut CanonicalizationReport) {
        if !self.config.infer_session_flag {
            return;
        }
        let should_be_session = cookie.expiration_date.is_none();
        if should_be_session && !cookie.session {
            cookie.session = true;
            report.changes.insert(CanonicalizationChange::InferredSession);
        } else if !should_be_session && cookie.session {
            cookie.session = false;
            report
                .changes
                .insert(CanonicalizationChange::InferredPersistent);
        }
    }
}

impl Default for CookieCanonicalizer {
    fn default() -> Self {
        Self::new(CanonicalizationConfig::default())
    }
}

pub fn normalize_path(path: &str, maximum_segments: usize) -> String {
    let mut segments = Vec::new();
    let prefixed;
    let candidate = if path.starts_with('/') {
        path
    } else {
        prefixed = format!("/{path}");
        &prefixed
    };
    for segment in candidate.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            segments.pop();
            continue;
        }
        if segments.len() >= maximum_segments {
            break;
        }
        segments.push(segment);
    }
    if segments.is_empty() {
        return "/".to_owned();
    }
    let mut output = String::with_capacity(path.len().max(1));
    output.push('/');
    output.push_str(&segments.join("/"));
    if path.ends_with('/') && !output.ends_with('/') {
        output.push('/');
    }
    output
}
