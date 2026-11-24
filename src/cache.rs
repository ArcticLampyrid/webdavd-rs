use std::borrow::Borrow;
use std::cmp::Eq;
use std::collections::vec_deque::VecDeque;
use std::collections::HashMap;
use std::hash::Hash;
use std::option::Option;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[allow(dead_code)]
pub struct Cache<K, V> {
    intern: Mutex<Intern<K, V>>,
}

/// The fifo has the newest entry at the front. A key that is inserted again
/// has a stale entry in the fifo; the sequence number makes sure that the
/// expiry of the stale entry does not remove the live value from the map.
struct Intern<K, V> {
    maxsize: usize,
    maxage:  Duration,
    nextseq: u64,
    map:     HashMap<K, (u64, Arc<V>)>,
    fifo:    VecDeque<(Instant, u64, K)>,
}

impl<K: Hash + Eq + Clone, V> Cache<K, V> {
    pub fn new() -> Cache<K, V> {
        let i = Intern {
            maxsize: 0,
            maxage:  Duration::new(0, 0),
            nextseq: 0,
            map:     HashMap::new(),
            fifo:    VecDeque::new(),
        };
        Cache {
            intern: Mutex::new(i),
        }
    }

    #[allow(dead_code)]
    pub fn maxsize(self, maxsize: usize) -> Self {
        self.intern.lock().unwrap().maxsize = maxsize;
        self
    }

    #[allow(dead_code)]
    pub fn maxage(self, maxage: Duration) -> Self {
        self.intern.lock().unwrap().maxage = maxage;
        self
    }

    fn expire(m: &mut Intern<K, V>) {
        let mut n = m.fifo.len();
        if m.maxsize > 0 && n > m.maxsize {
            n = m.maxsize;
        }
        if !m.maxage.is_zero() {
            let now = Instant::now();
            while n > 0 && now.duration_since(m.fifo[n - 1].0) > m.maxage {
                n -= 1;
            }
        }
        for (_, seq, key) in m.fifo.drain(n..) {
            if m.map.get(&key).is_some_and(|(live, _)| *live == seq) {
                m.map.remove(&key);
            }
        }
    }

    pub fn insert(&self, key: K, val: V) -> Arc<V> {
        let mut m = self.intern.lock().unwrap();
        let seq = m.nextseq;
        m.nextseq += 1;
        let av = Arc::new(val);
        m.map.insert(key.clone(), (seq, av.clone()));
        m.fifo.push_front((Instant::now(), seq, key));
        Self::expire(&mut m);
        av
    }

    // see https://doc.rust-lang.org/book/first-edition/borrow-and-asref.html
    pub fn get<Q>(&self, key: &Q) -> Option<Arc<V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut m = self.intern.lock().unwrap();
        Self::expire(&mut m);
        m.map.get(key).map(|(_, v)| v.clone())
    }
}

pub(crate) mod cached {
    //
    // Cached versions of Unix account lookup and Pam auth.
    //
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::cache;
    use crate::unixuser::{self, User};
    use lazy_static::lazy_static;

    struct Timeouts {
        pwcache:  Duration,
        #[cfg(feature = "pam")]
        pamcache: Duration,
    }

    lazy_static! {
        static ref TIMEOUTS: Mutex<Timeouts> = Mutex::new(Timeouts {
            pwcache:  Duration::new(120, 0),
            #[cfg(feature = "pam")]
            pamcache: Duration::new(120, 0),
        });
        static ref PWCACHE: cache::Cache<String, unixuser::User> = new_pwcache();
    }
    #[cfg(feature = "pam")]
    lazy_static! {
        static ref PAMCACHE: cache::Cache<u64, String> = new_pamcache();
    }

    fn new_pwcache() -> cache::Cache<String, unixuser::User> {
        let timeouts = TIMEOUTS.lock().unwrap();
        cache::Cache::new().maxage(timeouts.pwcache)
    }

    #[cfg(feature = "pam")]
    fn new_pamcache() -> cache::Cache<u64, String> {
        let timeouts = TIMEOUTS.lock().unwrap();
        cache::Cache::new().maxage(timeouts.pamcache)
    }

    pub(crate) fn set_pwcache_timeout(secs: usize) {
        let mut timeouts = TIMEOUTS.lock().unwrap();
        timeouts.pwcache = Duration::new(secs as u64, 0);
    }

    #[cfg(feature = "pam")]
    pub(crate) fn set_pamcache_timeout(secs: usize) {
        let mut timeouts = TIMEOUTS.lock().unwrap();
        timeouts.pamcache = Duration::new(secs as u64, 0);
    }

    #[cfg(feature = "pam")]
    pub async fn pam_auth<'a>(
        pam_auth: pam_sandboxed::PamAuth,
        service: &'a str,
        user: &'a str,
        pass: &'a str,
        remip: Option<&'a str>,
    ) -> Result<(), pam_sandboxed::PamError>
    {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut s = DefaultHasher::new();
        service.hash(&mut s);
        user.hash(&mut s);
        pass.hash(&mut s);
        remip.as_ref().hash(&mut s);
        let key = s.finish();

        if let Some(cache_user) = PAMCACHE.get(&key) {
            if user == cache_user.as_str() {
                return Ok(());
            }
        }

        let mut pam_auth = pam_auth;
        match pam_auth.auth(service, user, pass, remip).await {
            Err(e) => Err(e),
            Ok(()) => {
                PAMCACHE.insert(key, user.to_owned());
                Ok(())
            },
        }
    }

    pub async fn unixuser(username: &str, with_groups: bool) -> Result<Arc<User>, io::Error> {
        if let Some(pwd) = PWCACHE.get(username) {
            return Ok(pwd);
        }
        match User::by_name_async(username, with_groups).await {
            Err(e) => Err(e),
            Ok(pwd) => Ok(PWCACHE.insert(username.to_owned(), pwd)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;

    use super::*;

    #[test]
    fn insert_and_get() {
        let cache = Cache::new();
        assert_eq!(*cache.insert("a", 1), 1);
        assert_eq!(cache.get("a").as_deref(), Some(&1));
        assert_eq!(cache.get("b"), None);
    }

    #[test]
    fn maxsize_evicts_oldest() {
        let cache = Cache::new().maxsize(2);
        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.insert("c", 3);
        assert_eq!(cache.get("a"), None);
        assert_eq!(cache.get("b").as_deref(), Some(&2));
        assert_eq!(cache.get("c").as_deref(), Some(&3));
    }

    #[test]
    fn maxsize_keeps_reinserted_key() {
        let cache = Cache::new().maxsize(2);
        cache.insert("a", 1);
        cache.insert("a", 2);
        // Evicts the stale fifo entry of "a", but not the live value.
        cache.insert("b", 3);
        assert_eq!(cache.get("a").as_deref(), Some(&2));
        assert_eq!(cache.get("b").as_deref(), Some(&3));
    }

    #[test]
    fn maxage_expires() {
        let cache = Cache::new().maxage(Duration::from_millis(50));
        cache.insert("a", 1);
        sleep(Duration::from_millis(80));
        assert_eq!(cache.get("a"), None);
    }

    #[test]
    fn maxage_keeps_reinserted_key() {
        let cache = Cache::new().maxage(Duration::from_millis(300));
        cache.insert("a", 1);
        sleep(Duration::from_millis(200));
        cache.insert("a", 2);
        sleep(Duration::from_millis(200));
        // The first entry is expired, the second one is not.
        assert_eq!(cache.get("a").as_deref(), Some(&2));
        sleep(Duration::from_millis(200));
        assert_eq!(cache.get("a"), None);
    }
}
