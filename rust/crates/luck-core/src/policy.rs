use crate::model::{Cookie, SameSite};
use crate::validation::{validate_cookie, IssueSeverity, ValidationConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub rule: String,
    pub message: String,
    pub risk: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    AllowWithWarnings(Vec<PolicyViolation>),
    Deny(Vec<PolicyViolation>),
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        !matches!(self, Self::Deny(_))
    }

    pub fn violations(&self) -> &[PolicyViolation] {
        match self {
            Self::Allow => &[],
            Self::AllowWithWarnings(violations) | Self::Deny(violations) => violations,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookiePolicy {
    pub validation: ValidationConfig,
    pub require_secure: bool,
    pub require_http_only_for_names: Vec<String>,
    pub deny_name_prefixes: Vec<String>,
    pub deny_domain_suffixes: Vec<String>,
    pub allow_domains: Vec<String>,
    pub maximum_lifetime_days: Option<u64>,
    pub maximum_total_bytes: Option<usize>,
    pub deny_same_site_none: bool,
    pub deny_session_cookies: bool,
    pub deny_empty_values: bool,
}

impl Default for CookiePolicy {
    fn default() -> Self {
        Self {
            validation: ValidationConfig::default(),
            require_secure: false,
            require_http_only_for_names: vec!["session".into(), "auth".into(), "token".into()],
            deny_name_prefixes: Vec::new(),
            deny_domain_suffixes: Vec::new(),
            allow_domains: Vec::new(),
            maximum_lifetime_days: Some(400),
            maximum_total_bytes: Some(4096 + 256),
            deny_same_site_none: false,
            deny_session_cookies: false,
            deny_empty_values: false,
        }
    }
}

impl CookiePolicy {
    pub fn evaluate(&self, cookie: &Cookie) -> PolicyDecision {
        let mut violations = Vec::new();
        let validation = validate_cookie(cookie, &self.validation);
        for issue in validation.issues {
            violations.push(PolicyViolation {
                rule: issue.code,
                message: issue.message,
                risk: if issue.severity == IssueSeverity::Error { RiskLevel::High } else { RiskLevel::Low },
            });
        }
        if self.require_secure && !cookie.secure {
            violations.push(violation("policy.require_secure", "policy requires Secure", RiskLevel::High));
        }
        if self.deny_same_site_none && cookie.same_site == SameSite::None {
            violations.push(violation("policy.same_site_none", "SameSite=None is denied", RiskLevel::High));
        }
        if self.deny_session_cookies && cookie.effective_session() {
            violations.push(violation("policy.session", "session cookies are denied", RiskLevel::Medium));
        }
        if self.deny_empty_values && cookie.value.is_empty() {
            violations.push(violation("policy.empty", "empty cookie values are denied", RiskLevel::Medium));
        }
        let name_lower = cookie.name.to_ascii_lowercase();
        if self
            .require_http_only_for_names
            .iter()
            .any(|needle| name_lower.contains(&needle.to_ascii_lowercase()))
            && !cookie.http_only
        {
            violations.push(violation(
                "policy.sensitive_http_only",
                "cookie name appears sensitive but HttpOnly is disabled",
                RiskLevel::High,
            ));
        }
        for prefix in &self.deny_name_prefixes {
            if cookie.name.starts_with(prefix) {
                violations.push(violation("policy.name_prefix", format!("cookie name prefix {prefix:?} is denied"), RiskLevel::High));
            }
        }
        let domain = cookie.normalized_domain().to_ascii_lowercase();
        for suffix in &self.deny_domain_suffixes {
            let suffix = suffix.trim_start_matches('.').to_ascii_lowercase();
            if domain == suffix || domain.ends_with(&format!(".{suffix}")) {
                violations.push(violation("policy.domain_suffix", format!("domain suffix {suffix:?} is denied"), RiskLevel::Critical));
            }
        }
        if !self.allow_domains.is_empty()
            && !self.allow_domains.iter().any(|allowed| domain_matches(&domain, allowed))
        {
            violations.push(violation("policy.domain_allowlist", "domain is not in the allowlist", RiskLevel::Critical));
        }
        if let Some(maximum) = self.maximum_total_bytes {
            if cookie.estimated_bytes() > maximum {
                violations.push(violation(
                    "policy.size",
                    format!("estimated cookie size {} exceeds {maximum}", cookie.estimated_bytes()),
                    RiskLevel::High,
                ));
            }
        }
        if let (Some(days), Some(expiration)) = (self.maximum_lifetime_days, cookie.expiration_date) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs_f64())
                .unwrap_or_default();
            if expiration > now + days as f64 * 86_400.0 {
                violations.push(violation(
                    "policy.lifetime",
                    format!("cookie lifetime exceeds {days} days"),
                    RiskLevel::Medium,
                ));
            }
        }
        let deny = violations.iter().any(|entry| entry.risk >= RiskLevel::High);
        if violations.is_empty() {
            PolicyDecision::Allow
        } else if deny {
            PolicyDecision::Deny(violations)
        } else {
            PolicyDecision::AllowWithWarnings(violations)
        }
    }
}

fn violation(rule: &'static str, message: impl Into<String>, risk: RiskLevel) -> PolicyViolation {
    PolicyViolation { rule: rule.to_owned(), message: message.into(), risk }
}

fn domain_matches(domain: &str, allowed: &str) -> bool {
    let allowed = allowed.trim_start_matches('.').to_ascii_lowercase();
    domain == allowed || domain.ends_with(&format!(".{allowed}"))
}
