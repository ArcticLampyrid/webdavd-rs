//! Caches for account lookups, authentication results and quota information.

use std::hash::Hash;
use std::time::Duration;

use moka::sync::Cache;

/// Upper limit of entries in one cache.
///
/// Entries are only inserted after a successful lookup, thus the number of keys is
/// usually small. The limit protects memory if many different keys occur within one
/// TTL, for example PAM logins from many remote addresses.
const MAX_ENTRIES: u64 = 10_000;

/// Timeout of a cache when the config file does not set one.
const DEFAULT_TIMEOUT_SECS: usize = 120;

/// Make a bounded cache. Entries expire `ttl` after insertion.
pub(crate) fn new_cache<K, V>(ttl: Duration) -> Cache<K, V>
where
    K: Hash + Eq + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    Cache::builder()
        .max_capacity(MAX_ENTRIES)
        .time_to_live(ttl)
        .build()
}

/// Make a cache for an optional timeout. `None` uses [`DEFAULT_TIMEOUT_SECS`];
/// a timeout of `0` disables the cache.
pub(crate) fn new_optional_cache<K, V>(timeout_secs: Option<usize>) -> Option<Cache<K, V>>
where
    K: Hash + Eq + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    let secs = timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    (secs > 0).then(|| new_cache(Duration::from_secs(secs as u64)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_timeout_disables_cache() {
        assert!(new_optional_cache::<u64, u64>(Some(0)).is_none());
    }

    #[test]
    fn default_timeout_enables_cache() {
        assert!(new_optional_cache::<u64, u64>(None).is_some());
    }

    #[test]
    fn configured_timeout_enables_cache() {
        assert!(new_optional_cache::<u64, u64>(Some(60)).is_some());
    }
}
