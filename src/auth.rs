use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::{AuthType, Config, Location};
#[cfg(feature = "pam")]
use crate::pam::{BrokerOptions, PamAuth, PamError};

use headers::{authorization::Basic, Authorization, HeaderMapExt};
use http::status::StatusCode;

use crate::HttpRequest;

#[derive(Clone)]
pub struct Auth {
    config:    Arc<Config>,
    /// `None` when no location uses PAM.
    #[cfg(feature = "pam")]
    pam_auth:  Option<PamAuth>,
    /// `(submitted user, user after PAM)`, by [`pam_cache_key`]. `None`
    /// when the cache is disabled.
    #[cfg(feature = "pam")]
    pam_cache: Option<moka::sync::Cache<u64, (String, String)>>,
}

impl Auth {
    /// Starts the PAM broker if a location uses PAM. Call this before the
    /// server drops its privileges, so that the broker keeps them.
    ///
    /// The PAM processes use `pam_log_filter` as `RUST_LOG` if it is set.
    ///
    /// # Panics
    /// If the PAM broker does not start.
    pub async fn new(
        config: Arc<Config>,
        #[cfg_attr(not(feature = "pam"), allow(unused_variables))] pam_log_filter: Option<&str>,
    ) -> io::Result<Auth> {
        #[cfg(feature = "pam")]
        let pam_auth = if config.uses_pam() {
            let services = [config.pam.service.as_str()];
            let opts = BrokerOptions::new(config.pam.workers(), pam_log_filter, services)?;
            Some(PamAuth::new(opts).await)
        } else {
            None
        };

        Ok(Auth {
            #[cfg(feature = "pam")]
            pam_auth,
            #[cfg(feature = "pam")]
            pam_cache: crate::cache::new_optional_cache(config.pam.cache_timeout),
            config,
        })
    }

    // authenticate user.
    pub async fn auth<'a>(
        &'a self,
        req: &'a HttpRequest,
        location: &Location,
        _remote_ip: SocketAddr,
    ) -> Result<String, StatusCode> {
        // we must have a login/pass
        let basic = match req.headers().typed_get::<Authorization<Basic>>() {
            Some(Authorization(basic)) => basic,
            _ => return Err(StatusCode::UNAUTHORIZED),
        };
        let user = basic.username();
        let pass = basic.password();

        // match the auth type.
        match self.config.auth_type(location) {
            #[cfg(feature = "pam")]
            Some(&AuthType::Pam) => self.auth_pam(req, user, pass, _remote_ip).await,
            Some(AuthType::HtPasswd(ht)) => self.auth_htpasswd(user, pass, ht.as_str()).await,
            None => {
                debug!("need authentication, but auth-type is not set");
                Err(StatusCode::UNAUTHORIZED)
            },
        }
    }

    // authenticate user using PAM.
    #[cfg(feature = "pam")]
    async fn auth_pam<'a>(
        &'a self,
        req: &'a HttpRequest,
        user: &'a str,
        pass: &'a str,
        remote_ip: SocketAddr,
    ) -> Result<String, StatusCode> {
        // stringify the remote IP address.
        let ip = remote_ip.ip();
        let ip_string = if ip.is_loopback() {
            // if it's loopback, take the value from the x-forwarded-for
            // header, if present.
            req.headers()
                .get("x-forwarded-for")
                .and_then(|s| s.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_owned())
        } else {
            Some(match ip {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => ip.to_string(),
            })
        };
        let ip_ref = ip_string.as_deref();

        // A cache hit skips the PAM conversation.
        let service = self.config.pam.service.as_str();
        let key = pam_cache_key(service, user, pass, ip_ref);
        let cached = self.pam_cache.as_ref().and_then(|cache| cache.get(&key));
        if let Some((_, canonical)) = cached.filter(|(submitted, _)| submitted == user) {
            return Ok(canonical);
        }

        // authenticate.
        let Some(pam_auth) = &self.pam_auth else {
            return Err(StatusCode::UNAUTHORIZED);
        };
        match pam_auth.auth(service, user, pass, ip_ref).await {
            // A PAM module can map the user to another name (PAM_USER). The
            // server uses that name for routes, accounts and setuid.
            Ok(canonical) => {
                if canonical != user {
                    debug!(
                        "auth_pam({}): PAM mapped user {:?} to {:?}",
                        service, user, canonical
                    );
                }
                if let Some(cache) = &self.pam_cache {
                    cache.insert(key, (user.to_owned(), canonical.clone()));
                }
                Ok(canonical)
            },
            Err(PamError::Rejected(e)) => {
                debug!(
                    "auth_pam({}): authentication for {:?} ({:?}) failed: {}",
                    service, user, ip_ref, e
                );
                Err(StatusCode::UNAUTHORIZED)
            },
            Err(PamError::Unavailable(e)) => {
                warn!(
                    "auth_pam({}): authentication for {:?} ({:?}) unavailable: {}",
                    service, user, ip_ref, e
                );
                Err(StatusCode::SERVICE_UNAVAILABLE)
            },
        }
    }

    // authenticate user using htpasswd.
    async fn auth_htpasswd<'a>(
        &'a self,
        user: &'a str,
        pass: &'a str,
        section: &'a str,
    ) -> Result<String, StatusCode> {
        // Get the htpasswd.WHATEVER section from the config file.
        let file = match self.config.htpasswd.get(section) {
            Some(section) => section.htpasswd.as_str(),
            None => return Err(StatusCode::UNAUTHORIZED),
        };

        // Read the file and split it into a bunch of lines.
        tokio::task::block_in_place(move || {
            let data = match std::fs::read_to_string(file) {
                Ok(data) => data,
                Err(e) => {
                    debug!("{}: {}", file, e);
                    return Err(StatusCode::UNAUTHORIZED);
                },
            };
            let lines = data
                .split('\n')
                .map(|s| s.trim())
                .filter(|s| !s.starts_with('#') && !s.is_empty());

            // Check each line for a match.
            for line in lines {
                let mut fields = line.split(':');
                if let (Some(htuser), Some(htpass)) = (fields.next(), fields.next()) {
                    if htuser == user && pwhash::unix::verify(pass, htpass) {
                        return Ok(user.to_string());
                    }
                }
            }

            debug!("auth_htpasswd: authentication for {} failed", user);
            Err(StatusCode::UNAUTHORIZED)
        })
    }
}

// Key for the PAM cache. The submitted user name is stored in the value to
// detect hash collisions.
#[cfg(feature = "pam")]
fn pam_cache_key(service: &str, user: &str, pass: &str, remip: Option<&str>) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut s = DefaultHasher::new();
    service.hash(&mut s);
    user.hash(&mut s);
    pass.hash(&mut s);
    remip.hash(&mut s);
    s.finish()
}
