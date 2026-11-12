//! The PAC script in use, and the task that keeps it up to date.
//!
//! A script is read from its file or address when gatir starts and again every
//! `refresh` seconds. A version that cannot be read, or does not load, is
//! reported and forgotten: the last version that worked stays in use, because
//! a proxy that stops answering when the network hiccups is worse than one
//! that answers from a script a few hours old.
//!
//! The overrides of the configuration are added to the script as it is loaded.
//! What is kept, to tell a script that changed from one that was only fetched
//! again, is the script as it was read, so that the overrides can change
//! without fetching it again.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use super::fetch::{Fetched, Trust, Validators, fetch};
use super::{
    MAX_SCRIPT_BYTES, Pac, PacEnv, PacError, PacLimits, PacOverride, SystemResolver, load_script,
    wrap,
};
use crate::config::{PacConfig, PacLocation};

/// How long a script waits for a name lookup.
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
/// How long an answer to a name lookup is remembered.
const DNS_TTL: Duration = Duration::from_secs(60);

/// The wait after a first failure. It doubles with every one that follows,
/// up to the refresh interval.
const FIRST_RETRY: Duration = Duration::from_secs(5);

#[derive(Default)]
struct State {
    pac: Option<Pac>,
    /// The script as it was read, without the overrides: what `pac` was loaded
    /// from, to tell a script that changed from one that was only fetched again.
    bytes: Vec<u8>,
    /// What is added to the script when it is loaded.
    overrides: Vec<PacOverride>,
    validators: Validators,
    /// Why the latest attempt failed, if it did.
    failed: Option<String>,
    /// Attempts that failed in a row.
    failures: u32,
}

pub struct PacSource {
    settings: PacConfig,
    limits: PacLimits,
    env: PacEnv,
    trust: Trust,
    state: Mutex<State>,
    /// Held while the script is looked at, so that two looks never overlap.
    looking: tokio::sync::Mutex<()>,
}

impl PacSource {
    /// Reads the script for the first time.
    ///
    /// A file that cannot be used is an error, so that a wrong path or a typo
    /// shows up when gatir starts. An address that cannot be used is not: the
    /// network may simply not be there yet, and gatir keeps trying while
    /// requests are told why nothing is chosen.
    pub async fn start(settings: &PacConfig) -> io::Result<Arc<Self>> {
        Self::start_with(settings, Trust::system()).await
    }

    /// Like [`PacSource::start`], with `trust` deciding which certificate
    /// authorities an `https://` address may chain to.
    pub async fn start_with(settings: &PacConfig, trust: Trust) -> io::Result<Arc<Self>> {
        let resolver = Arc::new(SystemResolver::new(DNS_TIMEOUT, DNS_TTL));
        let source = Arc::new(Self {
            limits: PacLimits::default(),
            env: PacEnv::system(resolver),
            trust,
            settings: settings.clone(),
            state: Mutex::new(State {
                overrides: settings.overrides.clone(),
                ..State::default()
            }),
            looking: tokio::sync::Mutex::new(()),
        });
        if let Err(reason) = source.refresh().await {
            match settings.location {
                PacLocation::File(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("cannot use the PAC file {}: {reason}", settings.location),
                    ));
                }
                PacLocation::Url(_) => tracing::warn!(
                    pac = %settings.location,
                    %reason,
                    "cannot load the PAC script yet, trying again in the background"
                ),
            }
        }
        // It looks again for as long as anything uses the script, and no longer.
        tokio::spawn(Self::keep_fresh(Arc::downgrade(&source)));
        Ok(source)
    }

    /// The script to ask, or why there is none.
    pub fn current(&self) -> Result<Pac, PacError> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.pac.clone().ok_or_else(|| {
            PacError::NotLoaded(
                state
                    .failed
                    .clone()
                    .unwrap_or_else(|| "the first attempt has not finished".to_owned()),
            )
        })
    }

    /// Reads the script again at the configured interval, until nothing holds
    /// the source any more.
    async fn keep_fresh(source: Weak<Self>) {
        loop {
            let Some(wait) = source.upgrade().map(|source| source.next_wait()) else {
                return;
            };
            tokio::time::sleep(wait).await;
            let Some(source) = source.upgrade() else {
                return;
            };
            source.refresh_and_report().await;
        }
    }

    /// Looks at the script now, and says in the log what came of it.
    async fn refresh_and_report(&self) {
        if let Err(reason) = self.refresh().await {
            let kept = self.lock().pac.is_some();
            tracing::warn!(
                pac = %self.settings.location,
                %reason,
                retry_in_secs = self.next_wait().as_secs(),
                "cannot refresh the PAC script{}",
                if kept { ", keeping the previous version" } else { "" }
            );
        }
    }

    /// Looks at the script now instead of at the next time, in the
    /// background. What it finds, or why it found nothing, goes to the log.
    pub fn refresh_soon(self: &Arc<Self>) {
        let source = self.clone();
        tokio::spawn(async move { source.refresh_and_report().await });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn next_wait(&self) -> Duration {
        let failures = self.lock().failures;
        let refresh = self.settings.refresh;
        match failures {
            0 => refresh,
            n => FIRST_RETRY
                .saturating_mul(1 << (n - 1).min(16))
                .min(refresh),
        }
    }

    /// One look at the script. What it finds replaces what is in use only if
    /// it loads.
    async fn refresh(&self) -> Result<(), String> {
        let _alone = self.looking.lock().await;
        let outcome = self.read_and_load().await;
        let mut state = self.lock();
        match outcome {
            Ok(update) => {
                state.failed = None;
                state.failures = 0;
                if let Some((pac, bytes, validators)) = update {
                    let first = state.pac.is_none();
                    tracing::info!(
                        pac = %self.settings.location,
                        size = bytes.len(),
                        overrides = state.overrides.len(),
                        "PAC script {}",
                        if first { "loaded" } else { "updated" }
                    );
                    state.pac = Some(pac);
                    state.bytes = bytes;
                    state.validators = validators;
                }
                Ok(())
            }
            Err(reason) => {
                state.failed = Some(reason.clone());
                state.failures = state.failures.saturating_add(1);
                Err(reason)
            }
        }
    }

    /// Loads `script` with `overrides` added to it, as it would be used.
    async fn load(&self, script: &[u8], overrides: &[PacOverride]) -> Result<Pac, String> {
        let wrapped = wrap(script, overrides, &self.settings.location.to_string());
        // Scripts written years ago are not always UTF-8: `load_script` reads
        // them as well as it can.
        load_script(&wrapped, self.limits.clone(), self.env.clone())
            .await
            .map_err(|err| format!("the script is not usable: {err}"))
    }

    /// Changes the overrides, and loads again the script that is in use with
    /// them, without reading it again from where it is. Until a script has been
    /// read there is nothing to load: the next one gets them.
    ///
    /// If the script does not load with them, nothing changes and the reason is
    /// returned.
    pub async fn set_overrides(&self, overrides: &[PacOverride]) -> Result<(), String> {
        // Not while a look at the script is under way: it would finish with the
        // overrides that it started with.
        let _alone = self.looking.lock().await;
        let bytes = {
            let state = self.lock();
            if state.overrides == overrides {
                return Ok(());
            }
            state.pac.is_some().then(|| state.bytes.clone())
        };
        let loaded = match bytes {
            Some(bytes) => Some(self.load(&bytes, overrides).await?),
            None => None,
        };
        let mut state = self.lock();
        state.overrides = overrides.to_vec();
        if loaded.is_some() {
            state.pac = loaded;
            tracing::info!(
                pac = %self.settings.location,
                overrides = overrides.len(),
                "PAC script loaded again with new overrides"
            );
        }
        Ok(())
    }

    /// The script to switch to, if what was read is not the one in use.
    async fn read_and_load(&self) -> Result<Option<(Pac, Vec<u8>, Validators)>, String> {
        let (known, current) = {
            let state = self.lock();
            (state.validators.clone(), state.bytes.clone())
        };
        let (bytes, validators) = match &self.settings.location {
            PacLocation::File(path) => (read_script_file(path).await?, Validators::default()),
            PacLocation::Url(address) => {
                match fetch(address, self.settings.fetch_timeout, &known, &self.trust)
                    .await
                    .map_err(|err| err.to_string())?
                {
                    Fetched::Unchanged => return Ok(None),
                    Fetched::Script { bytes, validators } => (bytes, validators),
                }
            }
        };
        if bytes == current {
            // Same script, possibly with new validators: nothing to load.
            self.lock().validators = validators;
            return Ok(None);
        }

        let overrides = self.lock().overrides.clone();
        let loaded = self.load(&bytes, &overrides).await?;
        Ok(Some((loaded, bytes, validators)))
    }
}

/// Reads a script from a file, up to the size a script may have.
pub async fn read_script_file(path: &Path) -> Result<Vec<u8>, String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut bytes = Vec::new();
        File::open(&path)
            .and_then(|file| {
                // One more byte than allowed, to tell a script at the limit from one over it.
                file.take(MAX_SCRIPT_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
            })
            .map_err(|err| err.to_string())?;
        if bytes.len() > MAX_SCRIPT_BYTES {
            return Err(format!(
                "it is more than the {MAX_SCRIPT_BYTES} bytes allowed"
            ));
        }
        Ok(bytes)
    })
    .await
    .map_err(|err| err.to_string())?
}
