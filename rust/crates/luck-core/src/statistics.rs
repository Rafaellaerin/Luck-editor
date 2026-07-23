use crate::model::{CookieCollection, SameSite};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CookieStatistics {
    pub total: usize,
    pub domains: usize,
    pub names: usize,
    pub total_estimated_bytes: usize,
    pub average_estimated_bytes: f64,
    pub maximum_estimated_bytes: usize,
    pub secure: usize,
    pub insecure: usize,
    pub http_only: usize,
    pub script_readable: usize,
    pub session: usize,
    pub persistent: usize,
    pub expired: usize,
    pub host_only: usize,
    pub domain_scoped: usize,
    pub prefixed_host: usize,
    pub prefixed_secure: usize,
    pub partitioned: usize,
    pub empty_values: usize,
    pub same_site: SameSiteStatistics,
    pub by_domain: BTreeMap<String, usize>,
    pub by_path: BTreeMap<String, usize>,
    pub by_store: BTreeMap<String, usize>,
    pub value_length: LengthDistribution,
    pub name_length: LengthDistribution,
    pub lifetime: LifetimeStatistics,
}

impl CookieStatistics {
    pub fn compute(collection: &CookieCollection) -> Self {
        let now = unix_now();
        let mut stats = Self::default();
        let mut domains = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        let mut sizes = Vec::with_capacity(collection.len());
        let mut value_lengths = Vec::with_capacity(collection.len());
        let mut name_lengths = Vec::with_capacity(collection.len());
        let mut lifetimes = Vec::new();

        for cookie in collection {
            stats.total += 1;
            let domain = cookie.normalized_domain().to_ascii_lowercase();
            domains.insert(domain.clone());
            names.insert(cookie.name.clone());
            *stats.by_domain.entry(domain).or_default() += 1;
            *stats.by_path.entry(cookie.path.clone()).or_default() += 1;
            *stats.by_store.entry(cookie.store_id.clone().unwrap_or_default()).or_default() += 1;

            let size = cookie.estimated_bytes();
            sizes.push(size);
            value_lengths.push(cookie.value.len());
            name_lengths.push(cookie.name.len());
            stats.total_estimated_bytes += size;
            stats.maximum_estimated_bytes = stats.maximum_estimated_bytes.max(size);

            count_flag(cookie.secure, &mut stats.secure, &mut stats.insecure);
            count_flag(cookie.http_only, &mut stats.http_only, &mut stats.script_readable);
            count_flag(cookie.effective_session(), &mut stats.session, &mut stats.persistent);
            count_flag(cookie.host_only, &mut stats.host_only, &mut stats.domain_scoped);
            stats.expired += usize::from(cookie.is_expired_at(now));
            stats.prefixed_host += usize::from(cookie.is_host_prefix());
            stats.prefixed_secure += usize::from(cookie.is_secure_prefix());
            stats.partitioned += usize::from(cookie.partition_site.is_some() || cookie.metadata.contains_key("partitioned"));
            stats.empty_values += usize::from(cookie.value.is_empty());
            stats.same_site.increment(cookie.same_site);

            if let Some(expiry) = cookie.expiration_date {
                lifetimes.push((expiry - now).max(0.0));
            }
        }

        stats.domains = domains.len();
        stats.names = names.len();
        stats.average_estimated_bytes = mean_usize(&sizes);
        stats.value_length = LengthDistribution::from_values(&value_lengths);
        stats.name_length = LengthDistribution::from_values(&name_lengths);
        stats.lifetime = LifetimeStatistics::from_seconds(&lifetimes);
        stats
    }

    pub fn secure_ratio(&self) -> f64 {
        ratio(self.secure, self.total)
    }

    pub fn http_only_ratio(&self) -> f64 {
        ratio(self.http_only, self.total)
    }

    pub fn session_ratio(&self) -> f64 {
        ratio(self.session, self.total)
    }

    pub fn expired_ratio(&self) -> f64 {
        ratio(self.expired, self.total)
    }

    pub fn top_domains(&self, limit: usize) -> Vec<(String, usize)> {
        top_entries(&self.by_domain, limit)
    }

    pub fn top_paths(&self, limit: usize) -> Vec<(String, usize)> {
        top_entries(&self.by_path, limit)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SameSiteStatistics {
    pub none: usize,
    pub lax: usize,
    pub strict: usize,
    pub unspecified: usize,
}

impl SameSiteStatistics {
    fn increment(&mut self, value: SameSite) {
        match value {
            SameSite::None => self.none += 1,
            SameSite::Lax => self.lax += 1,
            SameSite::Strict => self.strict += 1,
            SameSite::Unspecified => self.unspecified += 1,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LengthDistribution {
    pub minimum: usize,
    pub maximum: usize,
    pub mean: f64,
    pub median: f64,
    pub p90: usize,
    pub p95: usize,
    pub p99: usize,
}

impl LengthDistribution {
    pub fn from_values(values: &[usize]) -> Self {
        if values.is_empty() {
            return Self::default();
        }
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        Self {
            minimum: sorted[0],
            maximum: *sorted.last().unwrap_or(&0),
            mean: mean_usize(&sorted),
            median: median(&sorted),
            p90: percentile(&sorted, 90),
            p95: percentile(&sorted, 95),
            p99: percentile(&sorted, 99),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LifetimeStatistics {
    pub persistent_count: usize,
    pub minimum_days: f64,
    pub maximum_days: f64,
    pub mean_days: f64,
    pub median_days: f64,
}

impl LifetimeStatistics {
    fn from_seconds(values: &[f64]) -> Self {
        if values.is_empty() {
            return Self::default();
        }
        let mut days: Vec<f64> = values.iter().map(|value| value / 86_400.0).collect();
        days.sort_by(|left, right| left.total_cmp(right));
        let middle = days.len() / 2;
        let median_days = if days.len() % 2 == 0 {
            (days[middle - 1] + days[middle]) / 2.0
        } else {
            days[middle]
        };
        Self {
            persistent_count: days.len(),
            minimum_days: days[0],
            maximum_days: *days.last().unwrap_or(&0.0),
            mean_days: days.iter().sum::<f64>() / days.len() as f64,
            median_days,
        }
    }
}

fn count_flag(value: bool, yes: &mut usize, no: &mut usize) {
    if value {
        *yes += 1;
    } else {
        *no += 1;
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 { 0.0 } else { numerator as f64 / denominator as f64 }
}

fn mean_usize(values: &[usize]) -> f64 {
    if values.is_empty() { 0.0 } else { values.iter().sum::<usize>() as f64 / values.len() as f64 }
}

fn median(values: &[usize]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let middle = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[middle - 1] + values[middle]) as f64 / 2.0
    } else {
        values[middle] as f64
    }
}

fn percentile(values: &[usize], percentile: usize) -> usize {
    if values.is_empty() {
        return 0;
    }
    let rank = ((values.len() - 1) * percentile + 99) / 100;
    values[rank.min(values.len() - 1)]
}

fn top_entries(map: &BTreeMap<String, usize>, limit: usize) -> Vec<(String, usize)> {
    let mut entries: Vec<_> = map.iter().map(|(key, value)| (key.clone(), *value)).collect();
    entries.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    entries.truncate(limit);
    entries
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or_default()
}
