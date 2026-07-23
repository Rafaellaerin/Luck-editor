use crate::canonical::{CollectionCanonicalizationReport, CookieCanonicalizer};
use crate::domain_index::DomainIndex;
use crate::error::Result;
use crate::model::CookieCollection;
use crate::parse::{parse_cookies, ParseOptions, ParseReport};
use crate::policy::{CookiePolicy, PolicyDecision};
use crate::query::CookieQuery;
use crate::redact::Redactor;
use crate::serialize::{serialize_cookies, SerializeOptions};
use crate::statistics::CookieStatistics;
use crate::validation::{validate_cookie, ValidationReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct LuckEngine {
    pub parse_options: ParseOptions,
    pub canonicalizer: CookieCanonicalizer,
    pub policy: CookiePolicy,
    pub redactor: Redactor,
}

impl Default for LuckEngine {
    fn default() -> Self {
        Self {
            parse_options: ParseOptions::default(),
            canonicalizer: CookieCanonicalizer::default(),
            policy: CookiePolicy::default(),
            redactor: Redactor::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineReport {
    pub parse: ParseReport,
    pub canonicalization: CollectionCanonicalizationReport,
    pub validation: Vec<ValidationReport>,
    pub policy: Vec<PolicyDecision>,
    pub statistics: CookieStatistics,
    pub index: DomainIndex,
}

impl EngineReport {
    pub fn valid_count(&self) -> usize {
        self.validation.iter().filter(|report| report.is_valid()).count()
    }

    pub fn denied_count(&self) -> usize {
        self.policy.iter().filter(|decision| !decision.is_allowed()).count()
    }

    pub fn warning_count(&self) -> usize {
        self.validation.iter().map(|report| report.warnings().count()).sum::<usize>()
            + self.parse.warnings.len()
    }

    pub fn is_clean(&self) -> bool {
        self.parse.rejected == 0
            && self.validation.iter().all(ValidationReport::is_valid)
            && self.policy.iter().all(PolicyDecision::is_allowed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineOptions {
    pub apply_query: Option<String>,
    pub redact_values: bool,
    pub remove_expired: bool,
    pub deny_policy_violations: bool,
}

impl Default for PipelineOptions {
    fn default() -> Self {
        Self {
            apply_query: None,
            redact_values: false,
            remove_expired: true,
            deny_policy_violations: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PipelineOutput {
    pub report: EngineReport,
    pub collection: CookieCollection,
    pub serialized: String,
    pub removed_expired: usize,
    pub removed_by_policy: usize,
}

impl LuckEngine {
    pub fn inspect(&self, input: &str) -> Result<EngineReport> {
        let mut parse = parse_cookies(input, &self.parse_options)?;
        let canonicalization = self.canonicalizer.canonicalize_collection(&mut parse.cookies);
        let validation: Vec<_> = parse
            .cookies
            .iter()
            .map(|cookie| validate_cookie(cookie, &self.parse_options.validation))
            .collect();
        let policy: Vec<_> = parse.cookies.iter().map(|cookie| self.policy.evaluate(cookie)).collect();
        let statistics = CookieStatistics::compute(&parse.cookies);
        let index = DomainIndex::build(&parse.cookies);
        Ok(EngineReport { parse, canonicalization, validation, policy, statistics, index })
    }

    pub fn run_pipeline(
        &self,
        input: &str,
        pipeline: &PipelineOptions,
        serialize_options: &SerializeOptions,
    ) -> Result<PipelineOutput> {
        let report = self.inspect(input)?;
        let mut collection = report.parse.cookies.clone();
        let removed_expired = if pipeline.remove_expired {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs_f64())
                .unwrap_or_default();
            collection.remove_expired_at(now)
        } else {
            0
        };
        let mut removed_by_policy = 0;
        if pipeline.deny_policy_violations {
            let original = collection.len();
            collection = CookieCollection::new(
                collection
                    .into_iter()
                    .filter(|cookie| self.policy.evaluate(cookie).is_allowed())
                    .collect(),
            );
            removed_by_policy = original - collection.len();
        }
        if let Some(query_text) = &pipeline.apply_query {
            collection = CookieQuery::parse(query_text)?.execute(&collection);
        }
        if pipeline.redact_values {
            collection = self.redactor.redact_collection(&collection);
        }
        let serialized = serialize_cookies(&collection, serialize_options)?;
        Ok(PipelineOutput { report, collection, serialized, removed_expired, removed_by_policy })
    }
}
