mod header;
mod json;
mod lines;
mod netscape;
mod set_cookie;

use crate::error::{LuckError, Result};
use crate::model::{Cookie, CookieCollection};
use crate::validation::{validate_cookie, ValidationConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputFormat {
    Auto,
    Json,
    Netscape,
    CookieHeader,
    SetCookie,
    Lines,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseWarning {
    pub code: String,
    pub message: String,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParseReport {
    pub format: InputFormat,
    pub cookies: CookieCollection,
    pub warnings: Vec<ParseWarning>,
    pub rejected: usize,
    pub duplicates_removed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseOptions {
    pub format: InputFormat,
    pub fallback_domain: String,
    pub maximum_input_bytes: usize,
    pub maximum_cookies: usize,
    pub reject_invalid: bool,
    pub deduplicate: bool,
    pub validation: ValidationConfig,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            format: InputFormat::Auto,
            fallback_domain: String::new(),
            maximum_input_bytes: 2 * 1024 * 1024,
            maximum_cookies: 5_000,
            reject_invalid: true,
            deduplicate: true,
            validation: ValidationConfig::default(),
        }
    }
}

pub fn detect_format(input: &str) -> InputFormat {
    let trimmed = input.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return InputFormat::Json;
    }
    if input.lines().any(|line| line.contains('\t') && line.split('\t').count() >= 7) {
        return InputFormat::Netscape;
    }
    if input.lines().any(|line| line.trim_start().to_ascii_lowercase().starts_with("set-cookie:")) {
        return InputFormat::SetCookie;
    }
    let lower = input.to_ascii_lowercase();
    if lower.contains("; secure") || lower.contains("; httponly") || lower.contains("; samesite=") || lower.contains("; path=") {
        return InputFormat::SetCookie;
    }
    if lower.trim_start().starts_with("cookie:") || (input.contains(';') && input.contains('=')) {
        return InputFormat::CookieHeader;
    }
    InputFormat::Lines
}

pub fn parse_cookies(input: &str, options: &ParseOptions) -> Result<ParseReport> {
    if input.trim().is_empty() {
        return Err(LuckError::EmptyInput);
    }
    if input.len() > options.maximum_input_bytes {
        return Err(LuckError::InputTooLarge { actual: input.len(), limit: options.maximum_input_bytes });
    }
    let format = if options.format == InputFormat::Auto { detect_format(input) } else { options.format };
    let (raw, mut warnings) = match format {
        InputFormat::Auto => unreachable!("auto is resolved above"),
        InputFormat::Json => json::parse(input, &options.fallback_domain)?,
        InputFormat::Netscape => netscape::parse(input)?,
        InputFormat::CookieHeader => header::parse(input, &options.fallback_domain)?,
        InputFormat::SetCookie => set_cookie::parse(input, &options.fallback_domain)?,
        InputFormat::Lines => lines::parse(input, &options.fallback_domain)?,
    };
    if raw.len() > options.maximum_cookies {
        return Err(LuckError::TooManyCookies { actual: raw.len(), limit: options.maximum_cookies });
    }
    let mut accepted = Vec::with_capacity(raw.len());
    let mut rejected = 0;
    for (index, cookie) in raw.into_iter().enumerate() {
        let validation = validate_cookie(&cookie, &options.validation);
        if options.reject_invalid && !validation.is_valid() {
            rejected += 1;
            warnings.push(ParseWarning {
                code: "cookie.rejected".to_owned(),
                line: Some(index + 1),
                message: validation.errors().map(|issue| issue.message.as_str()).collect::<Vec<_>>().join("; "),
            });
        } else {
            for warning in validation.warnings() {
                warnings.push(ParseWarning {
                    code: warning.code.clone(),
                    line: Some(index + 1),
                    message: warning.message.clone(),
                });
            }
            accepted.push(cookie);
        }
    }
    let mut cookies = CookieCollection::new(accepted);
    let duplicates_removed = if options.deduplicate { cookies.deduplicate_last_wins() } else { 0 };
    Ok(ParseReport { format, cookies, warnings, rejected, duplicates_removed })
}

pub(crate) fn warning(code: &'static str, message: impl Into<String>, line: Option<usize>) -> ParseWarning {
    ParseWarning { code: code.to_owned(), message: message.into(), line }
}

pub(crate) fn with_defaults(mut cookie: Cookie, fallback_domain: &str) -> Cookie {
    if cookie.domain.is_empty() {
        cookie.domain = fallback_domain.to_owned();
    }
    if cookie.path.is_empty() {
        cookie.path = "/".to_owned();
    }
    cookie
}
