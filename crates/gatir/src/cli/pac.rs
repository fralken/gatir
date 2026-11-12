//! `gatir pac export` and `gatir pac test`: writing the PAC script that gatir
//! runs, with the overrides of the configuration in it, and seeing what a
//! script answers.

use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use hyper::Uri;

use super::Source;
use crate::config::{Overrides, PacConfig, PacLocation, pac_dir};
use crate::pac::{
    Fetched, OperatingSystem, PacEnv, PacOverride, Route, SystemPac, SystemResolver, Trust,
    Validators, check, fetch, load_script, read_script_file, tool_limits, wrap,
};

#[derive(Debug, Subcommand)]
pub enum PacCommand {
    /// Write the PAC script that gatir runs, with its overrides in it
    ///
    /// gatir adds the `[[pac.overrides]]` of the configuration to the script
    /// itself, as it loads it, so there is no file to keep up to date. This
    /// writes the result as a file, to read it or to give it to another
    /// program (a browser, say): the script of the configuration as it is,
    /// followed by a block that sends the hosts of the overrides to their
    /// proxies. The result is checked before it is written. Without --output it
    /// goes to the standard output.
    Export(ExportArgs),

    /// Say which proxies a PAC script gives for some URLs
    ///
    /// Without --script it asks the script of the configuration, and when the
    /// configuration has overrides it shows the answer without them next to the
    /// answer with them, which is how to see what they change. The names a
    /// script looks up are looked up for real.
    Test(TestArgs),
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Where to write the script: a file name alone goes in the `pac` folder
    /// next to the configuration file, anything with a folder in it is the path
    /// as written. Without it, the standard output
    #[arg(long, value_name = "NAME|PATH")]
    pub output: Option<PathBuf>,

    /// Replace the file if it exists (the old one is kept as NAME.prev)
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct TestArgs {
    /// What to ask the script about: a URL, or a host name, which is taken as
    /// https://HOST/, the way gatir asks for a tunnel
    #[arg(required = true, value_name = "URL")]
    pub urls: Vec<String>,

    /// A script to ask, as it is, without the overrides: a file, or an address.
    /// A file name alone is looked for in the `pac` folder. Repeat it to
    /// compare. Without it, the script of the configuration
    #[arg(long = "script", value_name = "FILE|URL")]
    pub scripts: Vec<PacLocation>,
}

pub(super) fn run(
    command: PacCommand,
    config: Option<PathBuf>,
    overrides: Overrides,
    password_prompt: bool,
) -> anyhow::Result<()> {
    // Read, not started: these are tools, with nothing to log.
    let configured = |config: &Option<PathBuf>, overrides| -> anyhow::Result<PacConfig> {
        let source = Source::new(config.clone(), overrides, password_prompt)?;
        source.read()?.pac.context(
            "the configuration has no PAC script: add a [pac] table to it, or name one with --pac",
        )
    };
    match command {
        PacCommand::Export(args) => {
            let pac = configured(&config, overrides)?;
            export(&args, &pac, config.as_deref())
        }
        PacCommand::Test(args) => {
            let asked = if args.scripts.is_empty() {
                let pac = configured(&config, overrides)
                    .map_err(|err| anyhow::anyhow!("{err}; or ask a script with --script"))?;
                vec![asked_by_configuration(pac)]
            } else {
                asked_by_name(args.scripts, config.as_deref())?
            };
            test(&args.urls, asked)
        }
    }
}

/// How long a script may take to be fetched from an address.
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")
}

/// Whether `path` is a file name and nothing more: no folder, not even `./`.
fn is_bare_name(path: &Path) -> bool {
    let mut parts = path.components();
    matches!(
        (parts.next(), parts.next()),
        (Some(Component::Normal(_)), None)
    )
}

/// Where the file `name` is, for what is given as a file: a bare name is in the
/// PAC folder, and anything with a folder in it is the path as written.
fn in_pac_dir(name: &Path, config: Option<&Path>) -> anyhow::Result<PathBuf> {
    if !is_bare_name(name) {
        return Ok(name.to_path_buf());
    }
    let dir = pac_dir(config)
        .context("cannot tell where the configuration folder is (no HOME): give the whole path")?;
    Ok(dir.join(name))
}

/// A script to read, with whether it was named by a file name alone.
struct Located {
    location: PacLocation,
    bare: bool,
}

fn located(location: PacLocation, config: Option<&Path>) -> anyhow::Result<Located> {
    match location {
        PacLocation::File(path) => {
            let bare = is_bare_name(&path);
            Ok(Located {
                location: PacLocation::File(in_pac_dir(&path, config)?),
                bare,
            })
        }
        other @ (PacLocation::Url(_) | PacLocation::System) => Ok(Located {
            location: other,
            bare: false,
        }),
    }
}

impl Located {
    async fn read(&self) -> anyhow::Result<Vec<u8>> {
        read_script(&self.location).await.map_err(|err| {
            if self.bare {
                anyhow::anyhow!(
                    "{err} (a file name alone is looked for in the pac folder: write ./NAME \
                     for a file in the current folder)"
                )
            } else {
                err
            }
        })
    }
}

/// Where a script is: the address that the system gives, for the script of the
/// system, and `location` itself for any other.
fn resolve(location: &PacLocation) -> anyhow::Result<PacLocation> {
    match location {
        PacLocation::System => Ok(OperatingSystem.location()?),
        other => Ok(other.clone()),
    }
}

async fn read_script(location: &PacLocation) -> anyhow::Result<Vec<u8>> {
    let location = &resolve(location)?;
    match location {
        PacLocation::File(path) => read_script_file(path)
            .await
            .map_err(|err| anyhow::anyhow!("cannot read {}: {err}", path.display())),
        PacLocation::Url(address) => {
            match fetch(
                address,
                FETCH_TIMEOUT,
                &Validators::default(),
                &Trust::system(),
            )
            .await
            .map_err(|err| anyhow::anyhow!("cannot fetch {location}: {err}"))?
            {
                Fetched::Script { bytes, .. } => Ok(bytes),
                Fetched::Unchanged => bail!("{location} answered that nothing had changed"),
            }
        }
        PacLocation::System => bail!("the system did not say where the script is"),
    }
}

fn export(args: &ExportArgs, pac: &PacConfig, config: Option<&Path>) -> anyhow::Result<()> {
    let output = args
        .output
        .as_deref()
        .map(|name| in_pac_dir(name, config))
        .transpose()?;
    if let Some(output) = &output {
        if output.is_dir() {
            bail!("{} is a folder: name the file", output.display());
        }
        // Before anything is fetched: a file is not to be lost by mistake.
        if output.exists() && !args.force {
            bail!(
                "{} exists already: name another file, or give --force to replace it (the old \
                 one is kept as {}.prev)",
                output.display(),
                output.display()
            );
        }
    }

    let (from, script, answers) = runtime()?.block_on(async {
        let from = resolve(&pac.location)?;
        let original = read_script(&from).await?;
        let script = wrap(&original, &pac.overrides, &from.to_string());
        let answers = check(&script, &pac.overrides).await?;
        anyhow::Ok((from, script, answers))
    })?;

    let Some(output) = output else {
        return std::io::stdout()
            .write_all(&script)
            .context("cannot write to the standard output");
    };
    let kept = write_script(&output, &script, args.force)?;

    println!("from:        {from}");
    for over in &pac.overrides {
        println!(
            "override:    {} -> {}",
            over.hosts().join(", "),
            over.proxy()
        );
    }
    if pac.overrides.is_empty() {
        println!("override:    none (the script is copied as it is)");
    }
    for (host, routes) in &answers {
        println!("checked:     {host} -> {}", describe(routes));
    }
    let unused: Vec<String> = pac.overrides.iter().flat_map(PacOverride::unused).collect();
    if !unused.is_empty() {
        println!(
            "note:        gatir does not use {}; a browser may",
            unused.join(", ")
        );
    }
    println!("written:     {} ({} bytes)", output.display(), script.len());
    if let Some(previous) = kept {
        println!("previous:    kept as {}", previous.display());
    }
    Ok(())
}

/// Writes `script` to `path` in one go, creating the folder if needed. A file
/// that is there is kept as `.prev` first (only with `force`: otherwise it was
/// refused before). Returns where the old one went.
fn write_script(path: &Path, script: &[u8], force: bool) -> anyhow::Result<Option<PathBuf>> {
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let name = path
        .file_name()
        .context("the output has no file name")?
        .to_string_lossy()
        .into_owned();

    let mut kept = None;
    if path.exists() {
        if !force {
            bail!("{} exists already", path.display());
        }
        let previous = dir.join(format!("{name}.prev"));
        fs::copy(path, &previous)
            .with_context(|| format!("cannot keep the old file as {}", previous.display()))?;
        kept = Some(previous);
    }

    // Written aside and moved into place, so that a reader never sees half of it.
    let temporary = dir.join(format!(".{name}.tmp"));
    let written = fs::File::create(&temporary).and_then(|mut file| {
        file.write_all(script)?;
        file.sync_all()
    });
    if let Err(err) = written {
        let _ = fs::remove_file(&temporary);
        return Err(err).with_context(|| format!("cannot write {}", temporary.display()));
    }
    fs::rename(&temporary, path).map_err(|err| {
        let _ = fs::remove_file(&temporary);
        anyhow::anyhow!("cannot put the file in place at {}: {err}", path.display())
    })?;
    Ok(kept)
}

/// A URL to ask a script about, with the host it is asked with.
struct Target {
    url: String,
    host: String,
}

/// `https://example.com/x`, `http://example.com/`, or a bare host, which is
/// what gatir gives a script for a tunnel: `https://host/`.
fn target(text: &str) -> anyhow::Result<Target> {
    let text = text.trim();
    let given = if text.contains("://") {
        text.to_owned()
    } else {
        format!("https://{text}/")
    };
    let uri: Uri = given
        .parse()
        .with_context(|| format!("{text:?} is not a URL"))?;
    let scheme = uri.scheme_str().unwrap_or_default();
    if !matches!(scheme, "http" | "https") {
        bail!("{text:?} is not an http:// or https:// URL (a bare host name is taken as https)");
    }
    let host = uri
        .host()
        .filter(|host| !host.is_empty())
        .with_context(|| format!("{text:?} has no host"))?
        .to_ascii_lowercase();
    let authority = uri.authority().map_or("", |authority| authority.as_str());
    let path = uri.path_and_query().map_or("/", |path| path.as_str());
    Ok(Target {
        url: format!("{scheme}://{authority}{path}"),
        host,
    })
}

/// What a script answered, as it is read: the entries gatir cannot use are
/// said to be such.
fn describe(routes: &[Route]) -> String {
    if routes.is_empty() {
        return "(nothing usable)".to_owned();
    }
    routes
        .iter()
        .map(|route| match route {
            Route::Direct | Route::Proxy(_) => route.to_string(),
            other => format!("{other} (not used by gatir)"),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// A short name for each script, to tell them apart in the output: the file
/// name, or the whole address, or the whole path if two files share a name.
fn labels(scripts: &[PacLocation]) -> Vec<String> {
    let short = |location: &PacLocation| match location {
        PacLocation::File(path) => path.file_name().map_or_else(
            || path.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        ),
        PacLocation::Url(_) => location.to_string(),
        PacLocation::System => "system".to_owned(),
    };
    let shorts: Vec<String> = scripts.iter().map(short).collect();
    scripts
        .iter()
        .zip(&shorts)
        .map(|(location, short)| {
            if shorts.iter().filter(|other| *other == short).count() > 1 {
                location.to_string()
            } else {
                short.clone()
            }
        })
        .collect()
}

/// A script to ask, and the ways of asking it: each has a label to show, and the
/// overrides that are added to the script for it.
struct Asked {
    script: Located,
    ways: Vec<(String, Vec<PacOverride>)>,
}

/// The script of the configuration: as it is, and with the overrides added if
/// there are any, to see what they change.
fn asked_by_configuration(pac: PacConfig) -> Asked {
    let ways = if pac.overrides.is_empty() {
        let label = labels(std::slice::from_ref(&pac.location)).remove(0);
        vec![(label, Vec::new())]
    } else {
        vec![
            ("original".to_owned(), Vec::new()),
            ("with overrides".to_owned(), pac.overrides),
        ]
    };
    Asked {
        script: Located {
            location: pac.location,
            bare: false,
        },
        ways,
    }
}

/// The scripts that were named, each as it is.
fn asked_by_name(scripts: Vec<PacLocation>, config: Option<&Path>) -> anyhow::Result<Vec<Asked>> {
    let scripts = scripts
        .into_iter()
        .map(|location| located(location, config))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let labels = labels(
        &scripts
            .iter()
            .map(|script| script.location.clone())
            .collect::<Vec<_>>(),
    );
    Ok(scripts
        .into_iter()
        .zip(labels)
        .map(|(script, label)| Asked {
            script,
            ways: vec![(label, Vec::new())],
        })
        .collect())
}

fn test(urls: &[String], asked: Vec<Asked>) -> anyhow::Result<()> {
    let targets = urls
        .iter()
        .map(|text| target(text))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let width = asked
        .iter()
        .flat_map(|asked| asked.ways.iter().map(|(label, _)| label.len()))
        .max()
        .unwrap_or(0);

    let failures = runtime()?.block_on(async {
        // The names a script looks up are looked up for real: what is shown is
        // what gatir would do, here and now.
        let env = PacEnv::system(Arc::new(SystemResolver::new(
            Duration::from_secs(2),
            Duration::from_secs(60),
        )));
        let mut loaded = Vec::new();
        for asked in &asked {
            // Read once, whatever the ways of asking it.
            let bytes = asked.script.read().await.map_err(|err| err.to_string());
            for (label, overrides) in &asked.ways {
                let pac = match &bytes {
                    Ok(bytes) => {
                        let from = asked.script.location.to_string();
                        load_script(&wrap(bytes, overrides, &from), tool_limits(), env.clone())
                            .await
                            .map_err(|err| format!("the script is not usable: {err}"))
                    }
                    Err(err) => Err(err.clone()),
                };
                loaded.push((label.clone(), pac));
            }
        }

        let mut failures = 0usize;
        for target in &targets {
            let mut answers = Vec::new();
            for (label, pac) in &loaded {
                let answer = match pac {
                    Ok(pac) => pac
                        .find(&target.url, &target.host)
                        .await
                        .map_err(|err| err.to_string()),
                    Err(err) => Err(err.clone()),
                };
                answers.push((label, answer));
            }
            failures += answers.iter().filter(|(_, answer)| answer.is_err()).count();

            let shown = |answer: &Result<Vec<Route>, String>| match answer {
                Ok(routes) => describe(routes),
                Err(err) => format!("error: {err}"),
            };
            if let [(_, only)] = answers.as_slice() {
                println!("{}  ->  {}", target.url, shown(only));
                continue;
            }
            let first = &answers[0].1;
            let differs = answers.iter().any(|(_, answer)| answer != first);
            println!(
                "{}{}",
                target.url,
                if differs { "   (differs)" } else { "" }
            );
            for (label, answer) in &answers {
                println!("  {label:<width$}  {}", shown(answer));
            }
        }
        failures
    });

    if failures > 0 {
        bail!("{failures} answer(s) could not be had");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_file_name_is_not_a_path() {
        assert!(is_bare_name(Path::new("zscaler-local.pac")));
        for path in ["./a.pac", "dir/a.pac", "/abs/a.pac", "../a.pac", ".", ""] {
            assert!(!is_bare_name(Path::new(path)), "{path}");
        }
        #[cfg(windows)]
        for path in ["C:\\pac\\a.pac", "dir\\a.pac", "C:a.pac"] {
            assert!(!is_bare_name(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn a_bare_name_goes_to_the_pac_folder_and_a_path_stays_where_it_is() {
        let config = Path::new("/srv/gatir/gatir.toml");
        assert_eq!(
            in_pac_dir(Path::new("a.pac"), Some(config)).unwrap(),
            Path::new("/srv/gatir").join("pac").join("a.pac")
        );
        assert_eq!(
            in_pac_dir(Path::new("/tmp/a.pac"), Some(config)).unwrap(),
            PathBuf::from("/tmp/a.pac")
        );
        assert_eq!(
            in_pac_dir(Path::new("./a.pac"), Some(config)).unwrap(),
            PathBuf::from("./a.pac")
        );
    }

    #[test]
    fn urls_and_bare_hosts_are_read_the_way_gatir_asks_scripts() {
        let t = target("https://GHCR.io/v2/x?y=1").unwrap();
        assert_eq!(
            (t.url.as_str(), t.host.as_str()),
            ("https://GHCR.io/v2/x?y=1", "ghcr.io")
        );
        let t = target("ghcr.io").unwrap();
        assert_eq!(
            (t.url.as_str(), t.host.as_str()),
            ("https://ghcr.io/", "ghcr.io")
        );
        let t = target("http://example.com").unwrap();
        assert_eq!(t.url, "http://example.com/");
        let t = target("example.com:8443").unwrap();
        assert_eq!(t.url, "https://example.com:8443/");
        assert!(target("ftp://example.com/").is_err());
        assert!(target("").is_err());
    }

    #[test]
    fn two_files_with_the_same_name_are_told_apart_by_their_path() {
        let a = PacLocation::File(PathBuf::from("/x/proxy.pac"));
        let b = PacLocation::File(PathBuf::from("/y/proxy.pac"));
        let c = PacLocation::File(PathBuf::from("/y/other.pac"));
        assert_eq!(labels(&[a.clone(), c.clone()]), ["proxy.pac", "other.pac"]);
        assert_eq!(labels(&[a, b]), ["/x/proxy.pac", "/y/proxy.pac"]);
    }

    #[test]
    fn a_file_is_written_whole_and_the_old_one_is_kept_only_when_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("a.pac");

        assert_eq!(write_script(&path, b"one", false).unwrap(), None);
        assert_eq!(fs::read(&path).unwrap(), b"one");

        assert!(write_script(&path, b"two", false).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"one");

        let kept = write_script(&path, b"two", true).unwrap().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(fs::read(&kept).unwrap(), b"one");
        // Nothing else is left behind.
        let mut names: Vec<_> = fs::read_dir(dir.path().join("sub"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["a.pac", "a.pac.prev"]);
    }
}
