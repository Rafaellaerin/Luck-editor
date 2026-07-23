use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperation {
    Parse,
    Validate,
    Import,
    Export,
    Add,
    Update,
    Delete,
    BulkDelete,
    SnapshotCreate,
    SnapshotDelete,
    PolicyCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: u64,
    pub timestamp_millis: u128,
    pub operation: AuditOperation,
    pub domain: Option<String>,
    pub count: usize,
    pub success: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLog {
    maximum_events: usize,
    next_id: u64,
    events: VecDeque<AuditEvent>,
}

impl AuditLog {
    pub fn new(maximum_events: usize) -> Self {
        Self { maximum_events: maximum_events.max(1), next_id: 1, events: VecDeque::new() }
    }

    pub fn record(
        &mut self,
        operation: AuditOperation,
        domain: Option<String>,
        count: usize,
        success: bool,
        detail: Option<String>,
    ) -> &AuditEvent {
        let event = AuditEvent {
            id: self.next_id,
            timestamp_millis: now_millis(),
            operation,
            domain,
            count,
            success,
            detail: detail.map(|text| truncate(text, 500)),
        };
        self.next_id = self.next_id.saturating_add(1);
        self.events.push_front(event);
        while self.events.len() > self.maximum_events {
            self.events.pop_back();
        }
        self.events.front().expect("recorded event exists")
    }

    pub fn events(&self) -> impl Iterator<Item = &AuditEvent> {
        self.events.iter()
    }

    pub fn successful(&self) -> impl Iterator<Item = &AuditEvent> {
        self.events.iter().filter(|event| event.success)
    }

    pub fn failed(&self) -> impl Iterator<Item = &AuditEvent> {
        self.events.iter().filter(|event| !event.success)
    }

    pub fn by_operation(&self, operation: AuditOperation) -> impl Iterator<Item = &AuditEvent> {
        self.events.iter().filter(move |event| event.operation == operation)
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new(200)
    }
}

fn now_millis() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_millis()).unwrap_or_default()
}

fn truncate(value: String, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value;
    }
    value.chars().take(maximum.saturating_sub(1)).chain(std::iter::once('…')).collect()
}
