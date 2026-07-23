#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod audit;
pub mod binary;
pub mod canonical;
pub mod diff;
pub mod domain_index;
pub mod engine;
pub mod error;
pub mod model;
pub mod parse;
pub mod policy;
pub mod query;
pub mod redact;
pub mod serialize;
pub mod statistics;
pub mod store;
pub mod validation;

pub use audit::{AuditEvent, AuditLog, AuditOperation};
pub use binary::{decode_binary, encode_binary, BinaryDecodeReport, BinaryHeader, BinaryLimits};
pub use canonical::{
    normalize_path, CanonicalizationChange, CanonicalizationConfig, CanonicalizationReport,
    CollectionCanonicalizationReport, CookieCanonicalizer,
};
pub use diff::{
    apply_diff, diff_collections, ApplyDiffReport, ConflictStrategy, CookieDiff, CookieField,
    CookieModification, DiffConflict,
};
pub use domain_index::{DomainIndex, IndexValidationReport};
pub use engine::{EngineReport, LuckEngine, PipelineOptions, PipelineOutput};
pub use error::{LuckError, Result};
pub use model::{Cookie, CookieCollection, CookieKey, SameSite};
pub use parse::{detect_format, parse_cookies, InputFormat, ParseOptions, ParseReport, ParseWarning};
pub use policy::{CookiePolicy, PolicyDecision, PolicyViolation, RiskLevel};
pub use query::{CookieQuery, QueryExpr, SortField, SortOrder};
pub use redact::{RedactionMode, Redactor};
pub use serialize::{serialize_cookies, OutputFormat, SerializeOptions};
pub use statistics::{CookieStatistics, LengthDistribution, LifetimeStatistics, SameSiteStatistics};
pub use store::{
    CommitMetadata, CommitRecord, CookieStore, CookieTransaction, StoreSnapshot, TransactionOperation,
};
pub use validation::{validate_cookie, ValidationConfig, ValidationIssue, ValidationReport};
