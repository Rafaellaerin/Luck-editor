use crate::diff::{apply_diff, diff_collections, ApplyDiffReport, ConflictStrategy, CookieDiff};
use crate::error::{LuckError, Result};
use crate::model::{Cookie, CookieCollection, CookieKey};
use crate::query::CookieQuery;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoreSnapshot {
    pub revision: u64,
    pub collection: CookieCollection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitMetadata {
    pub actor: String,
    pub reason: String,
    pub timestamp_millis: u128,
}

impl CommitMetadata {
    pub fn new(actor: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            actor: actor.into(),
            reason: reason.into(),
            timestamp_millis: now_millis(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitRecord {
    pub revision: u64,
    pub parent_revision: u64,
    pub metadata: CommitMetadata,
    pub diff: CookieDiff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionOperation {
    Insert(CookieKey),
    Replace(CookieKey),
    Remove(CookieKey),
    Clear,
}

#[derive(Debug, Clone)]
pub struct CookieStore {
    revision: u64,
    cookies: BTreeMap<CookieKey, Cookie>,
    history_limit: usize,
    history: VecDeque<CommitRecord>,
}

impl CookieStore {
    pub fn new(history_limit: usize) -> Self {
        Self {
            revision: 0,
            cookies: BTreeMap::new(),
            history_limit: history_limit.max(1),
            history: VecDeque::new(),
        }
    }

    pub fn from_collection(collection: CookieCollection, history_limit: usize) -> Self {
        let mut store = Self::new(history_limit);
        store.cookies = collection.into_iter().map(|cookie| (cookie.key(), cookie)).collect();
        store
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    pub fn get(&self, key: &CookieKey) -> Option<&Cookie> {
        self.cookies.get(key)
    }

    pub fn contains(&self, key: &CookieKey) -> bool {
        self.cookies.contains_key(key)
    }

    pub fn collection(&self) -> CookieCollection {
        CookieCollection::new(self.cookies.values().cloned().collect())
    }

    pub fn snapshot(&self) -> StoreSnapshot {
        StoreSnapshot { revision: self.revision, collection: self.collection() }
    }

    pub fn query(&self, query: &CookieQuery) -> CookieCollection {
        query.execute(&self.collection())
    }

    pub fn history(&self) -> impl Iterator<Item = &CommitRecord> {
        self.history.iter()
    }

    pub fn begin(&self) -> CookieTransaction {
        CookieTransaction {
            base_revision: self.revision,
            base: self.collection(),
            working: self.collection(),
            operations: Vec::new(),
            closed: false,
        }
    }

    pub fn commit(&mut self, mut transaction: CookieTransaction, metadata: CommitMetadata) -> Result<CommitRecord> {
        if transaction.closed {
            return Err(LuckError::InvalidArgument("transaction is already closed".into()));
        }
        if transaction.base_revision != self.revision {
            return Err(LuckError::Validation(format!(
                "stale transaction: base revision {} differs from store revision {}",
                transaction.base_revision, self.revision
            )));
        }
        transaction.closed = true;
        let diff = diff_collections(&transaction.base, &transaction.working);
        let parent_revision = self.revision;
        self.revision = self.revision.saturating_add(1);
        self.cookies = transaction
            .working
            .into_iter()
            .map(|cookie| (cookie.key(), cookie))
            .collect();
        let record = CommitRecord { revision: self.revision, parent_revision, metadata, diff };
        self.history.push_front(record.clone());
        while self.history.len() > self.history_limit {
            self.history.pop_back();
        }
        Ok(record)
    }

    pub fn apply_external_diff(
        &mut self,
        expected_revision: u64,
        diff: &CookieDiff,
        strategy: ConflictStrategy,
        metadata: CommitMetadata,
    ) -> Result<ApplyDiffReport> {
        if expected_revision != self.revision {
            return Err(LuckError::Validation(format!(
                "expected revision {expected_revision}, current revision is {}",
                self.revision
            )));
        }
        let base = self.collection();
        let report = apply_diff(&base, diff, strategy);
        if strategy == ConflictStrategy::Reject && !report.conflicts.is_empty() {
            return Ok(report);
        }
        let mut transaction = self.begin();
        transaction.working = report.collection.clone();
        self.commit(transaction, metadata)?;
        Ok(report)
    }

    pub fn restore(&mut self, snapshot: &StoreSnapshot, metadata: CommitMetadata) -> Result<CommitRecord> {
        let mut transaction = self.begin();
        transaction.working = snapshot.collection.clone();
        transaction.operations.push(TransactionOperation::Clear);
        self.commit(transaction, metadata)
    }

    pub fn rollback_last(&mut self, metadata: CommitMetadata) -> Result<Option<CommitRecord>> {
        let Some(last) = self.history.front().cloned() else {
            return Ok(None);
        };
        let inverse = last.diff.invert();
        let report = apply_diff(&self.collection(), &inverse, ConflictStrategy::Reject);
        if !report.conflicts.is_empty() {
            return Err(LuckError::Validation("cannot rollback because current data conflicts with last commit".into()));
        }
        let mut transaction = self.begin();
        transaction.working = report.collection;
        self.commit(transaction, metadata).map(Some)
    }
}

impl Default for CookieStore {
    fn default() -> Self {
        Self::new(100)
    }
}

#[derive(Debug, Clone)]
pub struct CookieTransaction {
    base_revision: u64,
    base: CookieCollection,
    working: CookieCollection,
    operations: Vec<TransactionOperation>,
    closed: bool,
}

impl CookieTransaction {
    pub fn base_revision(&self) -> u64 {
        self.base_revision
    }

    pub fn collection(&self) -> &CookieCollection {
        &self.working
    }

    pub fn operations(&self) -> &[TransactionOperation] {
        &self.operations
    }

    pub fn get(&self, key: &CookieKey) -> Option<&Cookie> {
        self.working.iter().find(|cookie| cookie.key() == *key)
    }

    pub fn insert(&mut self, cookie: Cookie) -> Option<Cookie> {
        let key = cookie.key();
        let mut cookies = self.working.clone().into_vec();
        let previous = cookies.iter().position(|entry| entry.key() == key).map(|position| cookies.remove(position));
        cookies.push(cookie);
        self.working = CookieCollection::new(cookies);
        self.operations.push(if previous.is_some() {
            TransactionOperation::Replace(key)
        } else {
            TransactionOperation::Insert(key)
        });
        previous
    }

    pub fn remove(&mut self, key: &CookieKey) -> Option<Cookie> {
        let mut cookies = self.working.clone().into_vec();
        let position = cookies.iter().position(|cookie| cookie.key() == *key)?;
        let removed = cookies.remove(position);
        self.working = CookieCollection::new(cookies);
        self.operations.push(TransactionOperation::Remove(key.clone()));
        Some(removed)
    }

    pub fn retain<F>(&mut self, mut predicate: F) -> usize
    where
        F: FnMut(&Cookie) -> bool,
    {
        let mut cookies = self.working.clone().into_vec();
        let original = cookies.len();
        let removed_keys: Vec<CookieKey> = cookies
            .iter()
            .filter(|cookie| !predicate(cookie))
            .map(Cookie::key)
            .collect();
        cookies.retain(|cookie| !removed_keys.contains(&cookie.key()));
        self.working = CookieCollection::new(cookies);
        self.operations.extend(removed_keys.into_iter().map(TransactionOperation::Remove));
        original - self.working.len()
    }

    pub fn clear(&mut self) -> usize {
        let removed = self.working.len();
        self.working = CookieCollection::default();
        self.operations.push(TransactionOperation::Clear);
        removed
    }

    pub fn replace_collection(&mut self, collection: CookieCollection) {
        self.working = collection;
        self.operations.push(TransactionOperation::Clear);
    }

    pub fn abort(mut self) {
        self.closed = true;
    }
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
