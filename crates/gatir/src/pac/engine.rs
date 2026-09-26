//! The script engine (QuickJS) and the threads it runs on.
//!
//! Every worker owns one engine on its own thread, with the PAC script loaded
//! in it. An evaluation is limited in time, memory and stack: a script that
//! loops for ever, recurses without end or eats memory is stopped and reported
//! as an error. One kind of runaway cannot be stopped from inside, a long loop
//! in a built-in such as `Array.prototype.join`, so a worker whose evaluation
//! is still going long after its time limit is given up on and replaced.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rquickjs::convert::Coerced;
use rquickjs::function::Rest;
use rquickjs::{CatchResultExt, Context, Ctx, FromJs, Function, Runtime, Value};
use tokio::sync::oneshot;

use super::helpers;
use super::resolver::Resolver;
use super::route::{self, Route};

const PRELUDE: &str = include_str!("prelude.js");

/// Workers given up on, past which the script is declared broken.
const MAX_STUCK: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum PacError {
    #[error("{0}")]
    Load(String),
    #[error("the PAC script failed: {0}")]
    Script(String),
    #[error("the PAC script took longer than {0:?}")]
    Timeout(Duration),
    #[error("the PAC script must return a string, and it returned {0}")]
    BadResult(String),
    #[error("the PAC script returned no proxy gatir can read: \"{0}\"")]
    NoRoutes(String),
    #[error("too many evaluations of the PAC script got stuck: restart gatir")]
    Broken,
    #[error("the PAC engine is not running")]
    Unavailable,
}

/// What a script may use.
#[derive(Debug, Clone)]
pub struct PacLimits {
    /// How long one evaluation may take, name lookups included.
    pub time: Duration,
    /// Memory one engine may use, in bytes.
    pub memory: usize,
    /// Stack one engine may use, in bytes.
    pub stack: usize,
    /// Engines, each on its own thread: the evaluations that can run at once.
    pub workers: usize,
    /// How long past `time` an evaluation that cannot be interrupted is waited
    /// for, before its worker is given up on.
    pub grace: Duration,
}

impl Default for PacLimits {
    fn default() -> Self {
        Self {
            time: Duration::from_secs(5),
            memory: 64 * 1024 * 1024,
            stack: 512 * 1024,
            workers: 4,
            grace: Duration::from_secs(2),
        }
    }
}

type Clock = dyn Fn() -> i64 + Send + Sync;

/// What the script's helper functions reach out to.
#[derive(Clone)]
pub struct PacEnv {
    pub resolver: Arc<dyn Resolver>,
    /// The time in milliseconds since the Unix epoch.
    pub clock: Arc<Clock>,
}

impl PacEnv {
    pub fn system(resolver: Arc<dyn Resolver>) -> Self {
        Self {
            resolver,
            clock: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_millis() as i64)
            }),
        }
    }
}

// ---- the engine ----

struct Engine {
    // The context is dropped before the runtime.
    context: Context,
    _runtime: Runtime,
    /// Nanoseconds since `base` at which the evaluation must stop; 0 for none.
    deadline: Arc<AtomicU64>,
    timed_out: Arc<AtomicBool>,
    base: Instant,
    ex: bool,
    /// Set after a failure that may leave the engine in a bad state: it is
    /// replaced before the next evaluation.
    replace: bool,
}

enum Failure {
    Script(String),
    Bad(String),
}

impl Engine {
    fn new(source: &str, limits: &PacLimits, env: &PacEnv) -> Result<Self, PacError> {
        let start = |what: &str, err: rquickjs::Error| {
            PacError::Load(format!("cannot start the script engine ({what}): {err}"))
        };
        let runtime = Runtime::new().map_err(|err| start("runtime", err))?;
        runtime.set_memory_limit(limits.memory);
        runtime.set_max_stack_size(limits.stack);

        let base = Instant::now();
        let deadline = Arc::new(AtomicU64::new(0));
        let timed_out = Arc::new(AtomicBool::new(false));
        {
            let (deadline, timed_out) = (deadline.clone(), timed_out.clone());
            runtime.set_interrupt_handler(Some(Box::new(move || {
                let limit = deadline.load(Ordering::Relaxed);
                let over = limit != 0 && base.elapsed().as_nanos() as u64 > limit;
                if over {
                    timed_out.store(true, Ordering::Relaxed);
                }
                over
            })));
        }
        let context = Context::full(&runtime).map_err(|err| start("context", err))?;

        let mut engine = Self {
            _runtime: runtime,
            context,
            deadline,
            timed_out,
            base,
            ex: false,
            replace: false,
        };
        engine.arm(limits.time);
        let loaded = engine.context.with(|ctx| -> Result<bool, String> {
            install(&ctx, env).map_err(|err| format!("cannot set up the PAC functions: {err}"))?;
            ctx.eval::<(), _>(PRELUDE)
                .catch(&ctx)
                .map_err(|err| format!("internal error in the PAC functions: {err}"))?;
            ctx.eval::<(), _>(source)
                .catch(&ctx)
                .map_err(|err| format!("the PAC file has an error: {err}"))?;
            let globals = ctx.globals();
            let is_function = |name: &str| {
                globals
                    .get::<_, Value>(name)
                    .is_ok_and(|value| value.is_function())
            };
            if is_function("FindProxyForURLEx") {
                Ok(true)
            } else if is_function("FindProxyForURL") {
                Ok(false)
            } else {
                Err("the PAC file does not define a function FindProxyForURL".to_owned())
            }
        });
        engine.disarm();
        if engine.timed_out.load(Ordering::Relaxed) {
            return Err(PacError::Load(format!(
                "the PAC file took longer than {:?} to load",
                limits.time
            )));
        }
        engine.ex = loaded.map_err(PacError::Load)?;
        Ok(engine)
    }

    fn arm(&self, limit: Duration) {
        self.timed_out.store(false, Ordering::Relaxed);
        let deadline = self.base.elapsed() + limit;
        self.deadline
            .store((deadline.as_nanos() as u64).max(1), Ordering::Relaxed);
    }

    fn disarm(&self) {
        self.deadline.store(0, Ordering::Relaxed);
    }

    fn call(&mut self, url: &str, host: &str, limit: Duration) -> Result<String, PacError> {
        self.arm(limit);
        let name = if self.ex {
            "FindProxyForURLEx"
        } else {
            "FindProxyForURL"
        };
        let outcome = self.context.with(|ctx| -> Result<String, Failure> {
            let function: Function = ctx
                .globals()
                .get(name)
                .catch(&ctx)
                .map_err(|err| Failure::Script(err.to_string()))?;
            let value: Value = function
                .call((url, host))
                .catch(&ctx)
                .map_err(|err| Failure::Script(err.to_string()))?;
            match value.as_string() {
                Some(text) => text
                    .to_string()
                    .map_err(|err| Failure::Script(err.to_string())),
                None => Err(Failure::Bad(describe(&value))),
            }
        });
        self.disarm();

        if self.timed_out.load(Ordering::Relaxed) {
            self.replace = true;
            return Err(PacError::Timeout(limit));
        }
        outcome.map_err(|failure| match failure {
            Failure::Bad(what) => PacError::BadResult(what),
            Failure::Script(message) => {
                let lower = message.to_ascii_lowercase();
                if lower.contains("out of memory") || lower.contains("stack overflow") {
                    self.replace = true;
                }
                PacError::Script(message)
            }
        })
    }
}

fn describe(value: &Value<'_>) -> String {
    if value.is_undefined() {
        "undefined".to_owned()
    } else if value.is_null() {
        "null".to_owned()
    } else {
        format!("a value of type {:?}", value.type_of()).to_ascii_lowercase()
    }
}

/// What a script passed, as text; `None` for `null` and `undefined`, which a
/// helper such as `isInNet(dnsResolve(host), ...)` may well be handed.
fn text<'js>(value: &Value<'js>) -> Option<String> {
    if value.is_null() || value.is_undefined() {
        return None;
    }
    if let Some(string) = value.as_string() {
        return string.to_string().ok();
    }
    Coerced::<String>::from_js(value.ctx(), value.clone())
        .ok()
        .map(|coerced| coerced.0)
}

/// The `n`th argument of a call as text, if the script passed one. Every
/// helper takes its arguments this way, so that a call with too few or too many
/// is not an error: browsers answer `false`, and so does this.
fn arg<'js>(args: &Rest<Value<'js>>, n: usize) -> Option<String> {
    args.0.get(n).and_then(text)
}

/// Defines the helper functions in the script's global scope.
fn install<'js>(ctx: &Ctx<'js>, env: &PacEnv) -> rquickjs::Result<()> {
    let global = ctx.globals();

    global.set(
        "dnsDomainIs",
        Function::new(ctx.clone(), |args: Rest<Value<'js>>| {
            matches!((arg(&args, 0), arg(&args, 1)), (Some(h), Some(d)) if helpers::dns_domain_is(&h, &d))
        })?,
    )?;
    global.set(
        "localHostOrDomainIs",
        Function::new(ctx.clone(), |args: Rest<Value<'js>>| {
            matches!((arg(&args, 0), arg(&args, 1)), (Some(h), Some(d)) if helpers::local_host_or_domain_is(&h, &d))
        })?,
    )?;
    global.set(
        "isPlainHostName",
        Function::new(ctx.clone(), |args: Rest<Value<'js>>| {
            arg(&args, 0).is_some_and(|h| helpers::is_plain_host_name(&h))
        })?,
    )?;
    global.set(
        "dnsDomainLevels",
        Function::new(ctx.clone(), |args: Rest<Value<'js>>| {
            arg(&args, 0).map_or(0, |h| helpers::dns_domain_levels(&h) as i32)
        })?,
    )?;
    global.set(
        "shExpMatch",
        Function::new(ctx.clone(), |args: Rest<Value<'js>>| {
            matches!((arg(&args, 0), arg(&args, 1)), (Some(t), Some(p)) if helpers::sh_exp_match(&t, &p))
        })?,
    )?;

    let resolver = env.resolver.clone();
    global.set(
        "isInNet",
        Function::new(ctx.clone(), move |args: Rest<Value<'js>>| {
            match (arg(&args, 0), arg(&args, 1), arg(&args, 2)) {
                (Some(h), Some(p), Some(m)) => helpers::is_in_net(&*resolver, &h, &p, &m),
                _ => false,
            }
        })?,
    )?;
    let resolver = env.resolver.clone();
    global.set(
        "isInNetEx",
        Function::new(ctx.clone(), move |args: Rest<Value<'js>>| {
            matches!((arg(&args, 0), arg(&args, 1)), (Some(h), Some(p)) if helpers::is_in_net_ex(&*resolver, &h, &p))
        })?,
    )?;
    let resolver = env.resolver.clone();
    // The context is taken as a parameter, not captured: a closure that held on
    // to it would keep the whole context alive from inside itself.
    global.set(
        "dnsResolve",
        Function::new(
            ctx.clone(),
            move |cx: Ctx<'js>, args: Rest<Value<'js>>| -> rquickjs::Result<Value<'js>> {
                match arg(&args, 0).and_then(|h| helpers::dns_resolve(&*resolver, &h)) {
                    Some(address) => {
                        rquickjs::String::from_str(cx.clone(), &address).map(|s| s.into_value())
                    }
                    None => Ok(Value::new_null(cx)),
                }
            },
        )?,
    )?;
    let resolver = env.resolver.clone();
    global.set(
        "dnsResolveEx",
        Function::new(ctx.clone(), move |args: Rest<Value<'js>>| {
            arg(&args, 0).map_or_else(String::new, |h| helpers::dns_resolve_ex(&*resolver, &h))
        })?,
    )?;
    let resolver = env.resolver.clone();
    global.set(
        "isResolvable",
        Function::new(ctx.clone(), move |args: Rest<Value<'js>>| {
            arg(&args, 0).is_some_and(|h| helpers::is_resolvable(&*resolver, &h))
        })?,
    )?;
    let resolver = env.resolver.clone();
    global.set(
        "isResolvableEx",
        Function::new(ctx.clone(), move |args: Rest<Value<'js>>| {
            arg(&args, 0).is_some_and(|h| helpers::is_resolvable_ex(&*resolver, &h))
        })?,
    )?;
    global.set(
        "myIpAddress",
        Function::new(ctx.clone(), |_args: Rest<Value<'js>>| {
            helpers::my_ip_address()
        })?,
    )?;
    global.set(
        "myIpAddressEx",
        Function::new(ctx.clone(), |_args: Rest<Value<'js>>| {
            helpers::my_ip_address_ex()
        })?,
    )?;
    global.set(
        "sortIpAddressList",
        Function::new(ctx.clone(), |args: Rest<Value<'js>>| {
            arg(&args, 0).map_or_else(String::new, |l| helpers::sort_ip_address_list(&l))
        })?,
    )?;
    global.set(
        "alert",
        Function::new(ctx.clone(), |args: Rest<Value<'js>>| {
            let message = arg(&args, 0).unwrap_or_default();
            tracing::debug!(target: "gatir::pac", %message, "alert() in the PAC file");
        })?,
    )?;
    let clock = env.clock.clone();
    global.set(
        "__gatirNow",
        Function::new(ctx.clone(), move |_args: Rest<Value<'js>>| clock() as f64)?,
    )?;
    Ok(())
}

// ---- the workers ----

struct Job {
    url: String,
    host: String,
    reply: oneshot::Sender<Result<String, PacError>>,
    /// Set by the worker when it begins the job.
    started: Arc<AtomicBool>,
    /// Set by the caller when it gave up on the worker running this job.
    given_up: Arc<AtomicBool>,
}

struct Recipe {
    source: String,
    limits: PacLimits,
    env: PacEnv,
    jobs: Mutex<mpsc::Receiver<Job>>,
}

#[derive(Default)]
struct Counts {
    /// Workers running, including any given up on.
    alive: AtomicUsize,
    /// Workers given up on that have not returned.
    stuck: AtomicUsize,
}

struct Inner {
    jobs: mpsc::Sender<Job>,
    recipe: Arc<Recipe>,
    counts: Arc<Counts>,
}

/// A loaded PAC script, ready to be asked about URLs.
#[derive(Clone)]
pub struct Pac(Arc<Inner>);

impl Pac {
    /// Loads `source`, failing if it does not compile or does not define
    /// `FindProxyForURL`.
    pub fn load(source: &str, limits: PacLimits, env: PacEnv) -> Result<Self, PacError> {
        let workers = limits.workers.max(1);
        let (jobs, receiver) = mpsc::channel();
        let recipe = Arc::new(Recipe {
            source: source.to_owned(),
            limits,
            env,
            jobs: Mutex::new(receiver),
        });
        let counts = Arc::new(Counts::default());

        // The first worker reports whether the script loads.
        let (ready, loaded) = mpsc::channel();
        spawn_worker(&recipe, &counts, Some(ready)).map_err(|err| {
            PacError::Load(format!("cannot start a thread for the PAC script: {err}"))
        })?;
        let wait = recipe.limits.time + recipe.limits.grace;
        match loaded.recv_timeout(wait) {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                return Err(PacError::Load(
                    "the PAC file took too long to load".to_owned(),
                ));
            }
        }
        for _ in 1..workers {
            if let Err(err) = spawn_worker(&recipe, &counts, None) {
                tracing::warn!(%err, "cannot start another thread for the PAC script");
                break;
            }
        }
        Ok(Self(Arc::new(Inner {
            jobs,
            recipe,
            counts,
        })))
    }

    /// Asks the script where to send a request for `url`, whose host is `host`.
    pub async fn find(&self, url: &str, host: &str) -> Result<Vec<Route>, PacError> {
        let inner = &self.0;
        if inner.counts.stuck.load(Ordering::Relaxed) >= MAX_STUCK {
            return Err(PacError::Broken);
        }
        if inner.counts.alive.load(Ordering::Relaxed) == 0 {
            return Err(PacError::Unavailable);
        }
        let (reply, receive) = oneshot::channel();
        let (started, given_up) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        inner
            .jobs
            .send(Job {
                url: url.to_owned(),
                host: host.to_owned(),
                reply,
                started: started.clone(),
                given_up: given_up.clone(),
            })
            .map_err(|_| PacError::Unavailable)?;

        let limits = &inner.recipe.limits;
        let text = match tokio::time::timeout(limits.time + limits.grace, receive).await {
            Ok(Ok(result)) => result?,
            Ok(Err(_)) => return Err(PacError::Unavailable),
            Err(_) => {
                // Only a job that began can have a worker stuck on it.
                if started.load(Ordering::Acquire) {
                    given_up.store(true, Ordering::Release);
                    inner.counts.stuck.fetch_add(1, Ordering::AcqRel);
                    tracing::error!(
                        "a PAC evaluation cannot be stopped: its worker is given up on and replaced"
                    );
                    if let Err(err) = spawn_worker(&inner.recipe, &inner.counts, None) {
                        tracing::error!(%err, "cannot replace the stuck PAC worker");
                    }
                }
                return Err(PacError::Timeout(limits.time));
            }
        };

        let parsed = route::parse(&text);
        if !parsed.ignored.is_empty() {
            tracing::warn!(ignored = ?parsed.ignored, %url, "the PAC script returned entries gatir cannot read");
        }
        if parsed.routes.is_empty() {
            return Err(PacError::NoRoutes(text));
        }
        Ok(parsed.routes)
    }
}

fn spawn_worker(
    recipe: &Arc<Recipe>,
    counts: &Arc<Counts>,
    ready: Option<mpsc::Sender<Result<(), PacError>>>,
) -> io::Result<()> {
    let (recipe, counts) = (recipe.clone(), counts.clone());
    counts.alive.fetch_add(1, Ordering::AcqRel);
    let spawned = std::thread::Builder::new()
        .name("gatir-pac".to_owned())
        .spawn({
            let counts = counts.clone();
            move || {
                let _running = Running(counts.clone());
                run_worker(&recipe, &counts, ready);
            }
        });
    if spawned.is_err() {
        counts.alive.fetch_sub(1, Ordering::AcqRel);
    }
    spawned.map(drop)
}

/// Counts a worker out when its thread ends, however it ends.
struct Running(Arc<Counts>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.alive.fetch_sub(1, Ordering::AcqRel);
    }
}

fn run_worker(recipe: &Recipe, counts: &Counts, ready: Option<mpsc::Sender<Result<(), PacError>>>) {
    let mut engine = match Engine::new(&recipe.source, &recipe.limits, &recipe.env) {
        Ok(engine) => {
            if let Some(ready) = ready {
                let _ = ready.send(Ok(()));
            }
            Some(engine)
        }
        Err(err) => {
            match ready {
                Some(ready) => {
                    let _ = ready.send(Err(err));
                }
                None => tracing::error!(%err, "a PAC worker cannot start"),
            }
            return;
        }
    };
    loop {
        let job = {
            let jobs = recipe.jobs.lock().unwrap_or_else(PoisonError::into_inner);
            match jobs.recv() {
                Ok(job) => job,
                Err(_) => return,
            }
        };
        // Nobody is waiting any more.
        if job.reply.is_closed() {
            continue;
        }
        job.started.store(true, Ordering::Release);
        if engine.is_none() {
            match Engine::new(&recipe.source, &recipe.limits, &recipe.env) {
                Ok(fresh) => engine = Some(fresh),
                Err(err) => {
                    let _ = job.reply.send(Err(err));
                    continue;
                }
            }
        }
        let Some(current) = engine.as_mut() else {
            continue;
        };
        let result = current.call(&job.url, &job.host, recipe.limits.time);
        if current.replace {
            engine = None;
        }
        let _ = job.reply.send(result);

        // This worker was given up on and has been replaced. It is free now,
        // and there are enough of them, so it stops.
        if job.given_up.load(Ordering::Acquire) {
            counts.stuck.fetch_sub(1, Ordering::AcqRel);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::IpAddr;

    use super::*;

    #[derive(Debug, Default)]
    struct Table(HashMap<&'static str, Vec<IpAddr>>);

    impl Resolver for Table {
        fn resolve(&self, host: &str) -> Vec<IpAddr> {
            if let Ok(address) = host.parse::<IpAddr>() {
                return vec![address];
            }
            self.0.get(host).cloned().unwrap_or_default()
        }
    }

    fn dns() -> Arc<dyn Resolver> {
        let mut table = Table::default();
        table
            .0
            .insert("intranet.example.com", vec!["10.1.2.3".parse().unwrap()]);
        table.0.insert(
            "dual.example.com",
            vec!["2001:db8::1".parse().unwrap(), "192.0.2.7".parse().unwrap()],
        );
        Arc::new(table)
    }

    /// 2020-01-15 (a Wednesday) 12:34:56 UTC.
    const NOON: i64 = 1_579_091_696_000;

    fn env(now: i64) -> PacEnv {
        PacEnv {
            resolver: dns(),
            clock: Arc::new(move || now),
        }
    }

    fn quick() -> PacLimits {
        PacLimits {
            time: Duration::from_millis(300),
            workers: 2,
            grace: Duration::from_millis(300),
            ..PacLimits::default()
        }
    }

    fn pac(body: &str) -> Pac {
        pac_at(body, NOON)
    }

    fn pac_at(body: &str, now: i64) -> Pac {
        Pac::load(
            &format!("function FindProxyForURL(url, host) {{ {body} }}"),
            quick(),
            env(now),
        )
        .expect("the script loads")
    }

    /// What the script returns, as text.
    async fn ask(pac: &Pac, url: &str, host: &str) -> Result<Vec<Route>, PacError> {
        pac.find(url, host).await
    }

    async fn answer(body: &str) -> String {
        let pac = pac(&format!("return ({body}) ? \"PROXY x:1\" : \"DIRECT\";"));
        ask(&pac, "http://www.example.com/", "www.example.com")
            .await
            .unwrap()[0]
            .to_string()
    }

    async fn is_true(expression: &str) -> bool {
        answer(expression).await == "PROXY x:1"
    }

    fn proxy(host: &str, port: u16) -> Route {
        Route::Proxy(super::super::route::ProxyAddr {
            host: host.to_owned(),
            port,
        })
    }

    #[tokio::test]
    async fn returns_what_the_script_says() {
        let pac = pac(
            r#"if (dnsDomainIs(host, ".example.com")) return "PROXY p1:8080; PROXY p2:3128; DIRECT"; return "DIRECT";"#,
        );
        assert_eq!(
            ask(&pac, "http://www.example.com/x", "www.example.com")
                .await
                .unwrap(),
            [proxy("p1", 8080), proxy("p2", 3128), Route::Direct]
        );
        assert_eq!(
            ask(&pac, "http://other.org/", "other.org").await.unwrap(),
            [Route::Direct]
        );
    }

    #[tokio::test]
    async fn the_url_and_the_host_are_passed_as_they_are() {
        let pac = pac(r#"return "PROXY " + host.length + ":" + url.length;"#);
        // Not glued into script text: a quote or a newline is just a character.
        let url = "http://a.example.com/\"; DIRECT //\n";
        let routes = ask(&pac, url, "a.example.com").await.unwrap();
        assert_eq!(routes, [proxy("13", url.len() as u16)]);
    }

    #[tokio::test]
    async fn every_helper_can_be_called() {
        for expression in [
            r#"dnsDomainIs("www.example.com", ".example.com")"#,
            r#"!dnsDomainIs("www.example.org", ".example.com")"#,
            r#"localHostOrDomainIs("www", "www.example.com")"#,
            r#"isPlainHostName("intranet")"#,
            r#"dnsDomainLevels("a.b.c") === 2"#,
            r#"shExpMatch("http://x.example.com/a", "*.example.com/*")"#,
            r#"isInNet("10.1.2.3", "10.0.0.0", "255.0.0.0")"#,
            r#"isInNet("intranet.example.com", "10.1.0.0", "255.255.0.0")"#,
            r#"isInNetEx("2001:db8::9", "2001:db8::/32")"#,
            r#"dnsResolve("intranet.example.com") === "10.1.2.3""#,
            r#"dnsResolve("dual.example.com") === "192.0.2.7""#,
            r#"dnsResolveEx("dual.example.com") === "2001:db8::1;192.0.2.7""#,
            r#"dnsResolve("unknown.example.com") === null"#,
            r#"isResolvable("intranet.example.com") && !isResolvable("unknown.example.com")"#,
            r#"isResolvableEx("dual.example.com")"#,
            r#"sortIpAddressList("10.0.0.1;2001:db8::1") === "2001:db8::1;10.0.0.1""#,
            r#"/^\d+\.\d+\.\d+\.\d+$/.test(myIpAddress())"#,
            r#"myIpAddressEx().length > 0"#,
            r#"getClientVersion() === "1.0""#,
            r#"alert("hello") === undefined"#,
        ] {
            assert!(is_true(expression).await, "{expression}");
        }
    }

    #[tokio::test]
    async fn helpers_given_nothing_say_no_instead_of_failing() {
        // `dnsResolve` gives null for a name that does not resolve, and a script
        // often passes that on.
        for expression in [
            "!isInNet(dnsResolve('unknown.example.com'), '10.0.0.0', '255.0.0.0')",
            "!dnsDomainIs(undefined, '.com')",
            "!shExpMatch(null, '*')",
            "!isPlainHostName(undefined)",
            "isInNet.length >= 0 && !isInNet('10.0.0.1')",
        ] {
            assert!(is_true(expression).await, "{expression}");
        }
    }

    #[tokio::test]
    async fn a_call_with_too_few_or_too_many_arguments_is_no_error() {
        for expression in [
            "!isInNet() && !isInNet('10.0.0.1') && !isInNet('10.0.0.1', '10.0.0.0')",
            "isInNet('10.0.0.1', '10.0.0.0', '255.0.0.0', 'extra', 'more')",
            "!dnsDomainIs() && !shExpMatch('x') && !localHostOrDomainIs()",
            "dnsDomainIs('a.example.com', '.example.com', 1, 2, 3)",
            "dnsResolve() === null && dnsResolveEx() === ''",
            "/^\\d+\\./.test(myIpAddress(1, 2, 3))",
            "sortIpAddressList() === ''",
            "alert() === undefined && alert(1, 2, 3) === undefined",
        ] {
            assert!(is_true(expression).await, "{expression}");
        }
    }

    #[tokio::test]
    async fn modern_and_legacy_javascript_both_work() {
        let pac = pac(r#"
            const twice = (x) => x * 2;
            var legacy = "abcdef".substr(1, 3);
            return "PROXY " + legacy + `${twice(2)}` + ":80";
            "#);
        assert_eq!(
            ask(&pac, "http://x/", "x").await.unwrap(),
            [proxy("bcd4", 80)]
        );
        // Old built-ins that scripts written years ago still call.
        for expression in [
            r#"escape("a b") === "a%20b" && unescape("%41") === "A""#,
            "new Date(2020, 0, 1).getYear() === 120",
            r#"new Date(0).toGMTString() === "Thu, 01 Jan 1970 00:00:00 GMT""#,
            r#"Date.parse("January 15, 2020 10:00:00 GMT") === 1579082400000"#,
        ] {
            assert!(is_true(expression).await, "{expression}");
        }
    }

    #[tokio::test]
    async fn ftp_style_ipv6_and_ex_function() {
        let pac = Pac::load(
            r#"function FindProxyForURLEx(url, host) { return "PROXY [2001:db8::1]:8080"; }
               function FindProxyForURL(url, host) { return "DIRECT"; }"#,
            quick(),
            env(NOON),
        )
        .unwrap();
        assert_eq!(
            ask(&pac, "http://x/", "x").await.unwrap(),
            [proxy("2001:db8::1", 8080)]
        );
    }

    // ---- date and time, at a fixed moment: Wednesday 2020-01-15 12:34:56 GMT ----

    #[tokio::test]
    async fn weekday_range() {
        for (expression, expected) in [
            (r#"weekdayRange("WED", "GMT")"#, true),
            (r#"weekdayRange("THU", "GMT")"#, false),
            (r#"weekdayRange("MON", "FRI", "GMT")"#, true),
            (r#"weekdayRange("THU", "SAT", "GMT")"#, false),
            // A range that runs past the end of the week.
            (r#"weekdayRange("FRI", "MON", "GMT")"#, false),
            (r#"weekdayRange("SAT", "WED", "GMT")"#, true),
            (r#"weekdayRange("wed", "gmt")"#, true),
            (r#"weekdayRange("NOPE", "GMT")"#, false),
            (r#"weekdayRange()"#, false),
        ] {
            assert_eq!(is_true(expression).await, expected, "{expression}");
        }
    }

    #[tokio::test]
    async fn time_range() {
        for (expression, expected) in [
            (r#"timeRange(12, "GMT")"#, true),
            (r#"timeRange(13, "GMT")"#, false),
            (r#"timeRange(9, 17, "GMT")"#, true),
            (r#"timeRange(13, 17, "GMT")"#, false),
            // The second hour is included in full, up to 12:59:59.
            (r#"timeRange(8, 12, "GMT")"#, true),
            (r#"timeRange(8, 11, "GMT")"#, false),
            (r#"timeRange(12, 30, 12, 40, "GMT")"#, true),
            (r#"timeRange(12, 35, 12, 40, "GMT")"#, false),
            (r#"timeRange(12, 34, 56, 12, 34, 56, "GMT")"#, true),
            (r#"timeRange(12, 34, 57, 12, 40, 0, "GMT")"#, false),
            // A range that runs past midnight.
            (r#"timeRange(22, 14, "GMT")"#, true),
            (r#"timeRange(13, 6, "GMT")"#, false),
            (r#"timeRange(22, 0, 6, 0, "GMT")"#, false),
            (r#"timeRange(1, 2, 3, "GMT")"#, false),
            (r#"timeRange()"#, false),
            // In local time the whole day is always in range.
            (r#"timeRange(0, 23)"#, true),
        ] {
            assert_eq!(is_true(expression).await, expected, "{expression}");
        }
    }

    #[tokio::test]
    async fn date_range() {
        for (expression, expected) in [
            (r#"dateRange(15, "GMT")"#, true),
            (r#"dateRange(16, "GMT")"#, false),
            (r#"dateRange("JAN", "GMT")"#, true),
            (r#"dateRange("FEB", "GMT")"#, false),
            (r#"dateRange(2020, "GMT")"#, true),
            (r#"dateRange(2019, "GMT")"#, false),
            (r#"dateRange(10, 20, "GMT")"#, true),
            (r#"dateRange(16, 20, "GMT")"#, false),
            (r#"dateRange("JAN", "MAR", "GMT")"#, true),
            (r#"dateRange("FEB", "MAR", "GMT")"#, false),
            // The end month counts to its last day, February included.
            (r#"dateRange("NOV", "FEB", "GMT")"#, true),
            (r#"dateRange("MAR", "OCT", "GMT")"#, false),
            (r#"dateRange(2019, 2021, "GMT")"#, true),
            (r#"dateRange(2021, 2022, "GMT")"#, false),
            (r#"dateRange(1, "JAN", 15, "JAN", "GMT")"#, true),
            (r#"dateRange(1, "JAN", 14, "JAN", "GMT")"#, false),
            (r#"dateRange("DEC", 2019, "FEB", 2020, "GMT")"#, true),
            (r#"dateRange("FEB", 2020, "DEC", 2020, "GMT")"#, false),
            (
                r#"dateRange(15, "JAN", 2020, 15, "JAN", 2020, "GMT")"#,
                true,
            ),
            (
                r#"dateRange(16, "JAN", 2020, 31, "DEC", 2020, "GMT")"#,
                false,
            ),
            (r#"dateRange("jan", "gmt")"#, true),
            (r#"dateRange()"#, false),
            (r#"dateRange(1, 2, 3, "GMT")"#, false),
            (r#"dateRange("NOPE", "GMT")"#, false),
        ] {
            assert_eq!(is_true(expression).await, expected, "{expression}");
        }
    }

    #[tokio::test]
    async fn the_last_day_of_a_month_is_in_a_range_that_ends_there() {
        // 2020-02-29 is a leap day.
        let leap = 1_582_977_600_000;
        let pac = pac_at(
            r#"return dateRange("JAN", "FEB", "GMT") ? "PROXY yes:1" : "DIRECT";"#,
            leap,
        );
        assert_eq!(
            ask(&pac, "http://x/", "x").await.unwrap(),
            [proxy("yes", 1)]
        );
    }

    // ---- errors ----

    #[tokio::test]
    async fn a_script_error_is_reported_with_its_message() {
        let throws = pac(r#"throw new Error("boom");"#);
        let error = ask(&throws, "http://x/", "x").await.unwrap_err();
        assert!(matches!(error, PacError::Script(_)), "{error}");
        assert!(error.to_string().contains("boom"), "{error}");

        let undefined = pac("return nope();");
        let error = ask(&undefined, "http://x/", "x").await.unwrap_err();
        assert!(error.to_string().contains("nope"), "{error}");
    }

    #[tokio::test]
    async fn a_result_that_is_not_a_string_is_an_error() {
        for (body, expected) in [
            ("return 42;", "a value of type"),
            ("return undefined;", "undefined"),
            ("return null;", "null"),
            ("", "undefined"),
        ] {
            let error = ask(&pac(body), "http://x/", "x").await.unwrap_err();
            assert!(matches!(error, PacError::BadResult(_)), "{body}: {error}");
            assert!(error.to_string().contains(expected), "{body}: {error}");
        }
    }

    #[tokio::test]
    async fn a_result_with_nothing_readable_is_an_error() {
        for body in [
            r#"return "";"#,
            r#"return "BANANA a:1";"#,
            r#"return " ; ";"#,
        ] {
            let error = ask(&pac(body), "http://x/", "x").await.unwrap_err();
            assert!(matches!(error, PacError::NoRoutes(_)), "{body}: {error}");
        }
    }

    #[test]
    fn a_script_that_does_not_load_is_refused_at_once() {
        for (source, expected) in [
            (
                "function FindProxyForURL(url, host) { return \"DIRECT\" ",
                "PAC file has an error",
            ),
            ("var x = 1;", "does not define a function FindProxyForURL"),
            ("throw new Error('at load');", "at load"),
            ("var FindProxyForURL = 5;", "does not define a function"),
        ] {
            let error = Pac::load(source, quick(), env(NOON)).err().expect(source);
            assert!(matches!(error, PacError::Load(_)), "{source}: {error}");
            assert!(error.to_string().contains(expected), "{source}: {error}");
        }
    }

    // ---- limits ----

    #[tokio::test]
    async fn a_script_that_loops_for_ever_is_stopped() {
        for body in ["while (true) {}", "for (;;) {}", "do { } while (1);"] {
            let started = Instant::now();
            let error = ask(&pac(body), "http://x/", "x").await.unwrap_err();
            assert!(matches!(error, PacError::Timeout(_)), "{body}: {error}");
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "{body}: {:?}",
                started.elapsed()
            );
        }
    }

    #[tokio::test]
    async fn a_script_that_never_stops_recursing_is_stopped() {
        let error = ask(
            &pac("function f() { return f(); } return f();"),
            "http://x/",
            "x",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, PacError::Script(_) | PacError::Timeout(_)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_script_that_eats_memory_is_stopped() {
        let started = Instant::now();
        let error = ask(
            &pac(r#"var s = "x"; for (var i = 0; i < 1000; i++) { s = s + s; } return "PROXY a:" + s.length;"#),
            "http://x/",
            "x",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, PacError::Script(_) | PacError::Timeout(_)),
            "{error}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_pathological_regular_expression_is_stopped() {
        let error = ask(
            &pac(r#"return /(a+)+$/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab") ? "DIRECT" : "DIRECT";"#),
            "http://x/",
            "x",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, PacError::Timeout(_)), "{error}");
    }

    #[tokio::test]
    async fn the_engine_works_again_after_a_script_was_stopped() {
        let pac = pac(
            r#"if (host === "loop") { while (true) {} } if (host === "eat") { var s = "x"; for (;;) { s = s + s; } } return "PROXY ok:1";"#,
        );
        for _ in 0..2 {
            for host in ["loop", "eat"] {
                assert!(ask(&pac, "http://x/", host).await.is_err(), "{host}");
                assert_eq!(
                    ask(&pac, "http://x/", "fine").await.unwrap(),
                    [proxy("ok", 1)]
                );
            }
        }
    }

    #[tokio::test]
    async fn evaluations_run_side_by_side() {
        let pac = pac(
            r#"var start = new Date().getTime(); while (new Date().getTime() - start < 100) {} return "PROXY x:1";"#,
        );
        let started = Instant::now();
        let all = futures_join(&pac, 6).await;
        assert!(all.iter().all(Result::is_ok), "{all:?}");
        // Six evaluations of 100 ms each on two workers: about 300 ms, not 600.
        assert!(
            started.elapsed() < Duration::from_millis(550),
            "{:?}",
            started.elapsed()
        );
    }

    async fn futures_join(pac: &Pac, count: usize) -> Vec<Result<Vec<Route>, PacError>> {
        let mut tasks = Vec::new();
        for _ in 0..count {
            let pac = pac.clone();
            tasks.push(tokio::spawn(
                async move { pac.find("http://x/", "x").await },
            ));
        }
        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.unwrap());
        }
        results
    }
}
