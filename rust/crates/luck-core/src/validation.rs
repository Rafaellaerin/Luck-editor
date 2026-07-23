use crate::model::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub code: String,
    pub message: String,
    pub field: String,
    pub severity: IssueSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub issues: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        !self.issues.iter().any(|issue| issue.severity == IssueSeverity::Error)
    }

    pub fn errors(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues.iter().filter(|issue| issue.severity == IssueSeverity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues.iter().filter(|issue| issue.severity == IssueSeverity::Warning)
    }

    fn error(&mut self, code: &'static str, field: &'static str, message: impl Into<String>) {
        self.issues.push(ValidationIssue {
            code: code.to_owned(),
            field: field.to_owned(),
            message: message.into(),
            severity: IssueSeverity::Error,
        });
    }

    fn warning(&mut self, code: &'static str, field: &'static str, message: impl Into<String>) {
        self.issues.push(ValidationIssue {
            code: code.to_owned(),
            field: field.to_owned(),
            message: message.into(),
            severity: IssueSeverity::Warning,
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationConfig {
    pub maximum_name_bytes: usize,
    pub maximum_value_bytes: usize,
    pub maximum_domain_bytes: usize,
    pub maximum_path_bytes: usize,
    pub require_domain: bool,
    pub require_secure_for_none: bool,
    pub reject_public_suffix_like_domains: bool,
    pub warn_on_long_lifetime_days: Option<u64>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            maximum_name_bytes: 256,
            maximum_value_bytes: 4096,
            maximum_domain_bytes: 253,
            maximum_path_bytes: 1024,
            require_domain: true,
            require_secure_for_none: true,
            reject_public_suffix_like_domains: true,
            warn_on_long_lifetime_days: Some(400),
        }
    }
}

pub fn validate_cookie(cookie: &Cookie, config: &ValidationConfig) -> ValidationReport {
    let mut report = ValidationReport::default();
    validate_name(cookie, config, &mut report);
    validate_value(cookie, config, &mut report);
    validate_domain(cookie, config, &mut report);
    validate_path(cookie, config, &mut report);
    validate_security_flags(cookie, config, &mut report);
    validate_expiration(cookie, config, &mut report);
    validate_prefixes(cookie, &mut report);
    report
}

fn validate_name(cookie: &Cookie, config: &ValidationConfig, report: &mut ValidationReport) {
    if cookie.name.is_empty() {
        report.error("name.empty", "name", "cookie name is required");
        return;
    }
    if cookie.name.len() > config.maximum_name_bytes {
        report.error(
            "name.too_long",
            "name",
            format!("cookie name is {} bytes; maximum is {}", cookie.name.len(), config.maximum_name_bytes),
        );
    }
    for (offset, byte) in cookie.name.bytes().enumerate() {
        if !is_token_byte(byte) {
            report.error(
                "name.invalid_character",
                "name",
                format!("cookie name contains forbidden byte 0x{byte:02x} at offset {offset}"),
            );
            break;
        }
    }
}

fn validate_value(cookie: &Cookie, config: &ValidationConfig, report: &mut ValidationReport) {
    if cookie.value.len() > config.maximum_value_bytes {
        report.error(
            "value.too_long",
            "value",
            format!("cookie value is {} bytes; maximum is {}", cookie.value.len(), config.maximum_value_bytes),
        );
    }
    if let Some((offset, byte)) = cookie
        .value
        .bytes()
        .enumerate()
        .find(|(_, byte)| *byte < 0x20 || *byte == 0x7f)
    {
        report.error(
            "value.control_character",
            "value",
            format!("cookie value contains control byte 0x{byte:02x} at offset {offset}"),
        );
    }
    if cookie.value.contains(['\r', '\n']) {
        report.error("value.header_injection", "value", "cookie value contains a line break");
    }
}

fn validate_domain(cookie: &Cookie, config: &ValidationConfig, report: &mut ValidationReport) {
    if cookie.domain.is_empty() {
        if config.require_domain {
            report.error("domain.empty", "domain", "cookie domain is required");
        }
        return;
    }
    if cookie.domain.len() > config.maximum_domain_bytes {
        report.error(
            "domain.too_long",
            "domain",
            format!("cookie domain is {} bytes; maximum is {}", cookie.domain.len(), config.maximum_domain_bytes),
        );
    }
    let domain = cookie.domain.trim_start_matches('.').trim_end_matches('.');
    if domain.is_empty() {
        report.error("domain.invalid", "domain", "cookie domain is empty after normalization");
        return;
    }
    if domain.parse::<Ipv4Addr>().is_ok() || domain.parse::<Ipv6Addr>().is_ok() || domain.eq_ignore_ascii_case("localhost") {
        return;
    }
    if domain.contains("..") {
        report.error("domain.empty_label", "domain", "cookie domain contains an empty label");
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            report.error("domain.label_length", "domain", format!("invalid domain label length for {label:?}"));
            continue;
        }
        let valid = label
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_alphanumeric() || (byte == b'-' && index > 0 && index + 1 < label.len()));
        if !valid {
            report.error("domain.label_character", "domain", format!("domain label {label:?} contains an invalid character"));
        }
    }
    if config.reject_public_suffix_like_domains && !domain.contains('.') && !domain.eq_ignore_ascii_case("localhost") {
        report.warning(
            "domain.single_label",
            "domain",
            "single-label domains may not work outside local development",
        );
    }
}

fn validate_path(cookie: &Cookie, config: &ValidationConfig, report: &mut ValidationReport) {
    if !cookie.path.starts_with('/') {
        report.error("path.slash", "path", "cookie path must start with '/'");
    }
    if cookie.path.len() > config.maximum_path_bytes {
        report.error(
            "path.too_long",
            "path",
            format!("cookie path is {} bytes; maximum is {}", cookie.path.len(), config.maximum_path_bytes),
        );
    }
    if cookie.path.contains(';') {
        report.error("path.semicolon", "path", "cookie path cannot contain ';'");
    }
    if cookie.path.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        report.error("path.control_character", "path", "cookie path contains a control character");
    }
}

fn validate_security_flags(cookie: &Cookie, config: &ValidationConfig, report: &mut ValidationReport) {
    if config.require_secure_for_none && cookie.same_site == SameSite::None && !cookie.secure {
        report.error("same_site.none_without_secure", "same_site", "SameSite=None requires Secure");
    }
    if cookie.http_only && cookie.value.is_empty() {
        report.warning("http_only.empty", "value", "HttpOnly cookie has an empty value");
    }
    if cookie.partition_site.is_some() && !cookie.secure {
        report.error("partitioned.not_secure", "secure", "partitioned cookies must be Secure");
    }
}

fn validate_expiration(cookie: &Cookie, config: &ValidationConfig, report: &mut ValidationReport) {
    let Some(expiry) = cookie.expiration_date else {
        return;
    };
    if !expiry.is_finite() || expiry <= 0.0 {
        report.error("expiration.invalid", "expiration_date", "expiration must be a positive finite Unix timestamp");
        return;
    }
    if expiry > 253_402_300_799.0 {
        report.error("expiration.range", "expiration_date", "expiration exceeds year 9999");
    }
    if cookie.session {
        report.warning("expiration.session_conflict", "session", "session is true while expiration is present");
    }
    if let Some(days) = config.warn_on_long_lifetime_days {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs_f64())
            .unwrap_or_default();
        let threshold = now + days as f64 * 86_400.0;
        if expiry > threshold {
            report.warning(
                "expiration.long_lifetime",
                "expiration_date",
                format!("cookie lifetime is longer than {days} days"),
            );
        }
    }
}

fn validate_prefixes(cookie: &Cookie, report: &mut ValidationReport) {
    if cookie.is_host_prefix() {
        if !cookie.secure {
            report.error("prefix.host.secure", "secure", "__Host- cookie must be Secure");
        }
        if cookie.path != "/" {
            report.error("prefix.host.path", "path", "__Host- cookie must use path '/'");
        }
        if cookie.domain.starts_with('.') || !cookie.host_only {
            report.error("prefix.host.domain", "domain", "__Host- cookie must be host-only and omit Domain");
        }
    }
    if cookie.is_secure_prefix() && !cookie.secure {
        report.error("prefix.secure", "secure", "__Secure- cookie must be Secure");
    }
}

fn is_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
    ) || byte.is_ascii_alphanumeric()
}
