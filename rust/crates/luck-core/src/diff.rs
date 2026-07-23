use crate::model::{Cookie, CookieCollection, CookieKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CookieField {
    Value,
    Secure,
    HttpOnly,
    SameSite,
    ExpirationDate,
    Session,
    HostOnly,
    PartitionSite,
    Metadata,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CookieModification {
    pub key: CookieKey,
    pub before: Cookie,
    pub after: Cookie,
    pub fields: Vec<CookieField>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CookieDiff {
    pub added: Vec<Cookie>,
    pub removed: Vec<Cookie>,
    pub modified: Vec<CookieModification>,
}

impl CookieDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    pub fn total_changes(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }

    pub fn invert(&self) -> Self {
        Self {
            added: self.removed.clone(),
            removed: self.added.clone(),
            modified: self
                .modified
                .iter()
                .map(|change| CookieModification {
                    key: change.key.clone(),
                    before: change.after.clone(),
                    after: change.before.clone(),
                    fields: change.fields.clone(),
                })
                .collect(),
        }
    }

    pub fn affected_keys(&self) -> Vec<CookieKey> {
        let mut keys = Vec::with_capacity(self.total_changes());
        keys.extend(self.added.iter().map(Cookie::key));
        keys.extend(self.removed.iter().map(Cookie::key));
        keys.extend(self.modified.iter().map(|change| change.key.clone()));
        keys.sort();
        keys.dedup();
        keys
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictStrategy {
    Reject,
    PreferBase,
    PreferDiff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffConflict {
    pub key: CookieKey,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplyDiffReport {
    pub collection: CookieCollection,
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub conflicts: Vec<DiffConflict>,
}

pub fn diff_collections(before: &CookieCollection, after: &CookieCollection) -> CookieDiff {
    let before_map = collection_map(before);
    let after_map = collection_map(after);
    let mut diff = CookieDiff::default();

    for (key, after_cookie) in &after_map {
        match before_map.get(key) {
            None => diff.added.push(after_cookie.clone()),
            Some(before_cookie) => {
                let fields = changed_fields(before_cookie, after_cookie);
                if !fields.is_empty() {
                    diff.modified.push(CookieModification {
                        key: key.clone(),
                        before: before_cookie.clone(),
                        after: after_cookie.clone(),
                        fields,
                    });
                }
            }
        }
    }
    for (key, before_cookie) in &before_map {
        if !after_map.contains_key(key) {
            diff.removed.push(before_cookie.clone());
        }
    }
    diff.added.sort_by_key(Cookie::key);
    diff.removed.sort_by_key(Cookie::key);
    diff.modified.sort_by(|left, right| left.key.cmp(&right.key));
    diff
}

pub fn apply_diff(
    base: &CookieCollection,
    diff: &CookieDiff,
    strategy: ConflictStrategy,
) -> ApplyDiffReport {
    let mut map = collection_map(base);
    let mut conflicts = Vec::new();
    let mut added = 0;
    let mut removed = 0;
    let mut modified = 0;

    for cookie in &diff.removed {
        let key = cookie.key();
        let existing = map.get(&key).cloned();
        match existing {
            Some(existing) if existing == *cookie => {
                map.remove(&key);
                removed += 1;
            }
            Some(_) => {
                let apply = register_conflict(
                    &mut conflicts,
                    &key,
                    "remove precondition does not match base cookie",
                    strategy,
                );
                if apply {
                    map.remove(&key);
                    removed += 1;
                }
            }
            None => {
                register_conflict(&mut conflicts, &key, "cookie to remove is absent", strategy);
            }
        }
    }

    for change in &diff.modified {
        let existing = map.get(&change.key).cloned();
        match existing {
            Some(existing) if existing == change.before => {
                map.insert(change.key.clone(), change.after.clone());
                modified += 1;
            }
            Some(_) => {
                let apply = register_conflict(
                    &mut conflicts,
                    &change.key,
                    "modify precondition does not match base cookie",
                    strategy,
                );
                if apply {
                    map.insert(change.key.clone(), change.after.clone());
                    modified += 1;
                }
            }
            None => {
                let apply = register_conflict(
                    &mut conflicts,
                    &change.key,
                    "cookie to modify is absent",
                    strategy,
                );
                if apply {
                    map.insert(change.key.clone(), change.after.clone());
                    modified += 1;
                }
            }
        }
    }

    for cookie in &diff.added {
        let key = cookie.key();
        if map.contains_key(&key) {
            let apply = register_conflict(
                &mut conflicts,
                &key,
                "cookie to add already exists",
                strategy,
            );
            if apply {
                map.insert(key, cookie.clone());
                added += 1;
            }
        } else {
            map.insert(key, cookie.clone());
            added += 1;
        }
    }

    let mut collection = CookieCollection::new(map.into_values().collect());
    collection.sort_stable();
    ApplyDiffReport {
        collection,
        added,
        removed,
        modified,
        conflicts,
    }
}

fn collection_map(collection: &CookieCollection) -> BTreeMap<CookieKey, Cookie> {
    collection
        .iter()
        .map(|cookie| (cookie.key(), cookie.clone()))
        .collect()
}

fn changed_fields(before: &Cookie, after: &Cookie) -> Vec<CookieField> {
    let mut fields = Vec::new();
    if before.value != after.value {
        fields.push(CookieField::Value);
    }
    if before.secure != after.secure {
        fields.push(CookieField::Secure);
    }
    if before.http_only != after.http_only {
        fields.push(CookieField::HttpOnly);
    }
    if before.same_site != after.same_site {
        fields.push(CookieField::SameSite);
    }
    if before.expiration_date != after.expiration_date {
        fields.push(CookieField::ExpirationDate);
    }
    if before.session != after.session {
        fields.push(CookieField::Session);
    }
    if before.host_only != after.host_only {
        fields.push(CookieField::HostOnly);
    }
    if before.partition_site != after.partition_site {
        fields.push(CookieField::PartitionSite);
    }
    if before.metadata != after.metadata {
        fields.push(CookieField::Metadata);
    }
    fields
}

fn register_conflict(
    conflicts: &mut Vec<DiffConflict>,
    key: &CookieKey,
    message: &str,
    strategy: ConflictStrategy,
) -> bool {
    conflicts.push(DiffConflict {
        key: key.clone(),
        message: message.to_owned(),
    });
    strategy == ConflictStrategy::PreferDiff
}
