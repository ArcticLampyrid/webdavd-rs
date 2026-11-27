//!
//! Simple and stupid HTTP router.
//!
use std::default::Default;
use std::fmt::Debug;

use lazy_static::lazy_static;
use regex::bytes::{Match, Regex, RegexSet};
use dav_server::{DavMethod, DavMethodSet};

/// Every method that a [`DavMethodSet`] can hold, with its HTTP name.
///
/// `dav-server` does not let us iterate a `DavMethodSet`, so the router keeps
/// its own table. It is used for the `Allow` header of a "405 Method Not
/// Allowed" response. `test_all_methods` checks that the table is complete.
const METHODS: [(&str, DavMethod); 16] = [
    ("HEAD", DavMethod::Head),
    ("GET", DavMethod::Get),
    ("PUT", DavMethod::Put),
    ("PATCH", DavMethod::Patch),
    ("OPTIONS", DavMethod::Options),
    ("PROPFIND", DavMethod::PropFind),
    ("PROPPATCH", DavMethod::PropPatch),
    ("MKCOL", DavMethod::MkCol),
    ("COPY", DavMethod::Copy),
    ("MOVE", DavMethod::Move),
    ("DELETE", DavMethod::Delete),
    ("LOCK", DavMethod::Lock),
    ("UNLOCK", DavMethod::Unlock),
    ("REPORT", DavMethod::Report),
    ("MKCALENDAR", DavMethod::MkCalendar),
    ("MKADDRESSBOOK", DavMethod::MkAddressbook),
];

/// The HTTP names of the methods in `set`, in the order of [`METHODS`].
pub fn methods(set: DavMethodSet) -> impl Iterator<Item = &'static str> {
    METHODS
        .iter()
        .filter(move |(_, m)| set.contains(*m))
        .map(|(name, _)| *name)
}

/// The union of two method sets.
///
/// Bits that do not correspond to a method in [`METHODS`] are dropped: they
/// have no HTTP name, so they cannot be part of an `Allow` header.
fn union(a: DavMethodSet, b: DavMethodSet) -> DavMethodSet {
    let mut out = DavMethodSet::none();
    for (_, m) in METHODS {
        if a.contains(m) || b.contains(m) {
            out.add(m);
        }
    }
    out
}

// internal representation of a route.
#[derive(Debug)]
struct Route<T: Debug> {
    regex:   Regex,
    methods: Option<DavMethodSet>,
    data:    T,
}

/// A matched route.
#[derive(Debug)]
pub struct MatchedRoute<'t, 'p, T: Debug> {
    pub methods: Option<DavMethodSet>,
    pub params:  Vec<Option<Param<'p>>>,
    pub data:    &'t T,
}

/// All matching routes for a path, and the methods allowed on that path.
#[derive(Debug)]
pub struct RouteMatch<'t, 'p, T: Debug> {
    /// Routes whose path matched and whose methods allow the request method.
    pub routes:  Vec<MatchedRoute<'t, 'p, T>>,
    /// The union of the methods of every route whose path matched, or `None`
    /// if no route's path matched at all.
    pub allowed: Option<DavMethodSet>,
}

/// A parameter on a matched route.
pub struct Param<'p>(Match<'p>);

impl Debug for Param<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Param")
            .field("start", &self.0.start())
            .field("end", &self.0.end())
            .field("as_str", &std::str::from_utf8(self.0.as_bytes()).ok())
            .finish()
    }
}

impl<'p> Param<'p> {
    /// Returns the starting byte offset of the match in the path.
    #[inline]
    pub fn start(&self) -> usize {
        self.0.start()
    }

    /// Returns the ending byte offset of the match in the path.
    #[inline]
    pub fn end(&self) -> usize {
        self.0.end()
    }

    /// Returns the matched part of the path.
    #[inline]
    pub fn as_bytes(&self) -> &'p [u8] {
        self.0.as_bytes()
    }

    /// Returns the matched part of the path as a &str, if it is valid utf-8.
    #[inline]
    pub fn as_str(&self) -> Option<&'p str> {
        std::str::from_utf8(self.0.as_bytes()).ok()
    }
}

pub struct Builder<T: Debug> {
    routes: Vec<Route<T>>,
}

impl<T: Debug> Builder<T> {
    /// Add a route.
    ///
    /// Routes are matched in the order they were added.
    ///
    /// If a route starts with '^', it's assumed that it is a regular
    /// expression. Parameters are included as "named capture groups".
    ///
    /// Otherwise, it's a route-expression, with just the normal :params
    /// and *splat param, and parts between parentheses are optional.
    ///
    /// Example:
    ///
    /// - /api/get/:id
    /// - /files/*path
    /// - /users(/)
    /// - /users(/*path)
    ///
    pub fn add(
        &mut self,
        route: impl AsRef<str>,
        methods: Option<DavMethodSet>,
        data: T,
    ) -> Result<&mut Self, regex::Error>
    {
        let route = route.as_ref();
        // Might be a regexp
        if route.starts_with("^") {
            return self.add_re(route, methods, data);
        }
        // Ignore it if it does not start with /
        if !route.starts_with("/") {
            return Ok(self);
        }

        // First, replace special characters "()*" with unicode chars
        // from the private-use area, so that we can then regex-escape
        // the entire string.
        let re_route = route
            .chars()
            .map(|c| {
                match c {
                    '*' => '\u{e001}',
                    '(' => '\u{e002}',
                    ')' => '\u{e003}',
                    '\u{e001}' => ' ',
                    '\u{e002}' => ' ',
                    '\u{e003}' => ' ',
                    c => c,
                }
            })
            .collect::<String>();
        let re_route = regex::escape(&re_route);

        // Translate route expression into regexp.
        // We do a simple transformation:
        //    :ident -> (?P<ident>[^/]*)
        //    *ident -> (?P<ident>.*)
        //    (text) -> (?:text|)
        lazy_static! {
            static ref COLON: Regex = Regex::new(":([a-zA-Z0-9]+)").unwrap();
            static ref SPLAT: Regex = Regex::new("\u{e001}([a-zA-Z0-9]+)").unwrap();
            static ref MAYBE: Regex = Regex::new("\u{e002}([^\u{e002}]*)\u{e003}").unwrap();
        };
        let mut re_route = re_route.into_bytes();
        re_route = COLON.replace_all(&re_route, &b"(?P<$1>[^/]*)"[..]).to_vec();
        re_route = SPLAT.replace_all(&re_route, &b"(?P<$1>.*)"[..]).to_vec();
        re_route = MAYBE.replace_all(&re_route, &b"($1)?"[..]).to_vec();

        // finalize regex.
        let re_route = "^".to_string() + &String::from_utf8(re_route).unwrap() + "$";

        self.add_re(&re_route, methods, data)
    }

    // add route as regular expression.
    fn add_re(&mut self, s: &str, methods: Option<DavMethodSet>, data: T) -> Result<&mut Self, regex::Error> {
        // Set flags: enable ". matches everything", disable strict unicode.
        // We known 's' starts with "^", add it after that.
        let s2 = format!("^(?s){}", &s[1..]);
        let regex = Regex::new(&s2)?;
        self.routes.push(Route { regex, methods, data });
        Ok(self)
    }

    /// Combine all the routes and compile them into an internal RegexSet.
    pub fn build(&mut self) -> Router<T> {
        let set = RegexSet::new(self.routes.iter().map(|r| r.regex.as_str())).unwrap();
        Router {
            routes: std::mem::take(&mut self.routes),
            set,
        }
    }
}

/// Dead simple HTTP router.
#[derive(Debug)]
pub struct Router<T: Debug> {
    set:    RegexSet,
    routes: Vec<Route<T>>,
}

impl<T: Debug> Default for Router<T> {
    fn default() -> Router<T> {
        Router {
            set:    RegexSet::new(&[] as &[&str]).unwrap(),
            routes: Vec::new(),
        }
    }
}

impl<T: Debug> Router<T> {
    /// Return a builder.
    pub fn builder() -> Builder<T> {
        Builder { routes: Vec::new() }
    }

    /// See if the path matches a route in the set.
    ///
    /// The names of the parameters you want to be returned need to be passed in as an array.
    pub fn matches<'a>(
        &self,
        path: &'a [u8],
        method: DavMethod,
        param_names: &[&str],
    ) -> RouteMatch<'_, 'a, T>
    {
        let mut routes = Vec::new();
        let mut allowed: Option<DavMethodSet> = None;
        for idx in self.set.matches(path) {
            let route = &self.routes[idx];
            // No methods set means: all methods are allowed.
            let methods = route.methods.unwrap_or_else(DavMethodSet::all);
            allowed = Some(allowed.map_or(methods, |a| union(a, methods)));

            // Not for this request method, but the path is known.
            if !methods.contains(method) {
                continue;
            }

            let mut params = Vec::new();
            if let Some(caps) = route.regex.captures(path) {
                for name in param_names {
                    params.push(caps.name(name).map(Param));
                }
            } else {
                for _ in param_names {
                    params.push(None);
                }
            }
            routes.push(MatchedRoute {
                methods: route.methods,
                params,
                data: &route.data,
            });
        }
        RouteMatch { routes, allowed }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dav_server::DavMethod;

    fn test_match(rtr: &Router<usize>, p: &[u8], user: &str, path: &str) {
        let x = rtr.matches(p, DavMethod::Get, &["user", "path"]);
        assert!(!x.routes.is_empty());
        let x = &x.routes[0];
        if !user.is_empty() {
            assert!(x.params[0]
                .as_ref()
                .map(|b| b.as_bytes() == user.as_bytes())
                .unwrap_or(false));
        }
        if !path.is_empty() {
            assert!(x.params[1]
                .as_ref()
                .map(|b| b.as_bytes() == path.as_bytes())
                .unwrap_or(false));
        }
    }

    #[test]
    fn test_router() -> Result<(), Box<dyn std::error::Error>> {
        let rtr = Router::<usize>::builder()
            .add("/", None, 1)?
            .add("/users(/:user)", None, 2)?
            .add("/files/*path", None, 3)?
            .add("/files(/*path)", None, 4)?
            .build();

        test_match(&rtr, b"/", "", "");
        test_match(&rtr, b"/users", "", "");
        test_match(&rtr, b"/users/", "", "");
        test_match(&rtr, b"/users/mike", "mike", "");
        test_match(&rtr, b"/files/foo/bar", "", "foo/bar");
        test_match(&rtr, b"/files", "", "");
        Ok(())
    }

    /// The method table must map every method to its own HTTP name.
    #[test]
    fn test_all_methods() {
        let mut bits = 0;
        for (name, method) in METHODS {
            // The name must select exactly that method.
            let set = DavMethodSet::from_vec(vec![name]).unwrap();
            assert!(set.contains(method));
            assert_eq!(methods(set).collect::<Vec<_>>(), [name]);
            bits |= method as u32;
        }
        // `DavMethod` uses the bits 0x0001 ..= 0x8000, so the table must
        // cover all of 0xffff.
        assert_eq!(bits, 0xffff);
    }

    /// Routes are filtered by method, but a path that matched is reported as
    /// "known" even when no route allows the request method.
    #[test]
    fn test_method_filtering() -> Result<(), Box<dyn std::error::Error>> {
        let rtr = Router::<usize>::builder()
            .add("/files/*path", Some(DavMethodSet::WEBDAV_RO), 0)?
            .add("/files/*path", Some(DavMethodSet::HTTP_RW), 1)?
            .build();

        // A method that both locations allow matches both, in route order.
        let m = rtr.matches(b"/files/x", DavMethod::Get, &[]);
        assert_eq!(m.routes.iter().map(|r| *r.data).collect::<Vec<_>>(), [0, 1]);

        // A method that only the second location allows routes to that one.
        let m = rtr.matches(b"/files/x", DavMethod::Put, &[]);
        assert_eq!(m.routes.iter().map(|r| *r.data).collect::<Vec<_>>(), [1]);

        // A method that no location allows matches no route, but the path is
        // known: the allowed methods are the union over all matching routes.
        let m = rtr.matches(b"/files/x", DavMethod::Delete, &[]);
        assert!(m.routes.is_empty());
        assert_eq!(
            methods(m.allowed.unwrap()).collect::<Vec<_>>(),
            ["HEAD", "GET", "PUT", "OPTIONS", "PROPFIND"]
        );

        // A path that matches no location at all is not known.
        let m = rtr.matches(b"/other/x", DavMethod::Get, &[]);
        assert!(m.routes.is_empty());
        assert!(m.allowed.is_none());

        Ok(())
    }
}
