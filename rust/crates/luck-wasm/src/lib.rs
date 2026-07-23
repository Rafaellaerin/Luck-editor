#![forbid(unsafe_code)]

use luck_core::{
    parse_cookies, serialize_cookies, CookiePolicy, CookieQuery, OutputFormat, ParseOptions, SerializeOptions,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WasmParseOptions {
    #[serde(default)]
    fallback_domain: String,
    #[serde(default = "default_maximum_bytes")]
    maximum_bytes: usize,
    #[serde(default = "default_maximum_cookies")]
    maximum_cookies: usize,
}

impl Default for WasmParseOptions {
    fn default() -> Self {
        Self {
            fallback_domain: String::new(),
            maximum_bytes: default_maximum_bytes(),
            maximum_cookies: default_maximum_cookies(),
        }
    }
}

#[wasm_bindgen]
pub fn parse(input: &str, options: JsValue) -> Result<JsValue, JsValue> {
    let options: WasmParseOptions = if options.is_undefined() || options.is_null() {
        WasmParseOptions::default()
    } else {
        serde_wasm_bindgen::from_value(options).map_err(js_error)?
    };
    let report = parse_cookies(
        input,
        &ParseOptions {
            fallback_domain: options.fallback_domain,
            maximum_input_bytes: options.maximum_bytes,
            maximum_cookies: options.maximum_cookies,
            ..ParseOptions::default()
        },
    )
    .map_err(js_error)?;
    serde_wasm_bindgen::to_value(&report).map_err(js_error)
}

#[wasm_bindgen]
pub fn query(input: &str, query_text: &str, fallback_domain: &str) -> Result<JsValue, JsValue> {
    let report = parse_cookies(
        input,
        &ParseOptions { fallback_domain: fallback_domain.to_owned(), ..ParseOptions::default() },
    )
    .map_err(js_error)?;
    let query = CookieQuery::parse(query_text).map_err(js_error)?;
    let result = query.execute(&report.cookies);
    serde_wasm_bindgen::to_value(&result).map_err(js_error)
}

#[wasm_bindgen]
pub fn audit(input: &str, policy: JsValue, fallback_domain: &str) -> Result<JsValue, JsValue> {
    let report = parse_cookies(
        input,
        &ParseOptions { fallback_domain: fallback_domain.to_owned(), ..ParseOptions::default() },
    )
    .map_err(js_error)?;
    let policy: CookiePolicy = if policy.is_undefined() || policy.is_null() {
        CookiePolicy::default()
    } else {
        serde_wasm_bindgen::from_value(policy).map_err(js_error)?
    };
    let decisions: Vec<_> = report.cookies.iter().map(|cookie| policy.evaluate(cookie)).collect();
    serde_wasm_bindgen::to_value(&decisions).map_err(js_error)
}

#[wasm_bindgen]
pub fn convert_redacted_json(input: &str, fallback_domain: &str) -> Result<String, JsValue> {
    let report = parse_cookies(
        input,
        &ParseOptions { fallback_domain: fallback_domain.to_owned(), ..ParseOptions::default() },
    )
    .map_err(js_error)?;
    serialize_cookies(
        &report.cookies,
        &SerializeOptions {
            format: OutputFormat::RedactedJson,
            hostname: fallback_domain.to_owned(),
            include_http_only: true,
            ..SerializeOptions::default()
        },
    )
    .map_err(js_error)
}

fn js_error(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}

const fn default_maximum_bytes() -> usize { 2 * 1024 * 1024 }
const fn default_maximum_cookies() -> usize { 5_000 }
