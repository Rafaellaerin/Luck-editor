use crate::model::{Cookie, CookieCollection};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMode {
    Full,
    KeepEdges,
    HashLike,
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redactor {
    pub mode: RedactionMode,
    pub visible_edge_characters: usize,
    pub replacement: char,
}

impl Default for Redactor {
    fn default() -> Self {
        Self { mode: RedactionMode::KeepEdges, visible_edge_characters: 3, replacement: '•' }
    }
}

impl Redactor {
    pub fn redact_value(&self, value: &str) -> String {
        match self.mode {
            RedactionMode::Full => self.replacement.to_string().repeat(value.chars().count().clamp(4, 64)),
            RedactionMode::Empty => String::new(),
            RedactionMode::KeepEdges => keep_edges(value, self.visible_edge_characters, self.replacement),
            RedactionMode::HashLike => hash_like(value),
        }
    }

    pub fn redact_cookie(&self, cookie: &Cookie) -> Cookie {
        let mut redacted = cookie.clone();
        redacted.value = self.redact_value(&redacted.value);
        redacted
    }

    pub fn redact_collection(&self, collection: &CookieCollection) -> CookieCollection {
        CookieCollection::new(collection.iter().map(|cookie| self.redact_cookie(cookie)).collect())
    }
}

fn keep_edges(value: &str, visible: usize, replacement: char) -> String {
    let characters: Vec<char> = value.chars().collect();
    if characters.is_empty() {
        return "(empty)".into();
    }
    if characters.len() <= visible.saturating_mul(2) {
        return replacement.to_string().repeat(characters.len().max(4));
    }
    let hidden = (characters.len() - visible * 2).min(64);
    format!(
        "{}{}{}",
        characters[..visible].iter().collect::<String>(),
        replacement.to_string().repeat(hidden),
        characters[characters.len() - visible..].iter().collect::<String>()
    )
}

fn hash_like(value: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("redacted-{hash:016x}")
}
