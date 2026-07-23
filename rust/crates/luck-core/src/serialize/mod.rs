mod curl;
mod header;
mod json;
mod netscape;
mod set_cookie;

use crate::error::Result;
use crate::model::CookieCollection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputFormat {
    Json,
    RedactedJson,
    Netscape,
    CookieHeader,
    SetCookie,
    Curl,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializeOptions {
    pub format: OutputFormat,
    pub hostname: String,
    pub include_http_only: bool,
    pub pretty_json: bool,
    pub include_metadata: bool,
}

impl Default for SerializeOptions {
    fn default() -> Self {
        Self {
            format: OutputFormat::RedactedJson,
            hostname: "example.invalid".into(),
            include_http_only: false,
            pretty_json: true,
            include_metadata: false,
        }
    }
}

pub fn serialize_cookies(collection: &CookieCollection, options: &SerializeOptions) -> Result<String> {
    let filtered = CookieCollection::new(
        collection
            .iter()
            .filter(|cookie| options.include_http_only || !cookie.http_only)
            .cloned()
            .collect(),
    );
    match options.format {
        OutputFormat::Json => json::serialize(&filtered, options, false),
        OutputFormat::RedactedJson => json::serialize(&filtered, options, true),
        OutputFormat::Netscape => netscape::serialize(&filtered),
        OutputFormat::CookieHeader => header::serialize(&filtered),
        OutputFormat::SetCookie => set_cookie::serialize(&filtered),
        OutputFormat::Curl => curl::serialize(&filtered, &options.hostname),
    }
}
