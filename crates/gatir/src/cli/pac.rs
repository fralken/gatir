//! `gatir pac generate` and `gatir pac test`: making a local copy of a PAC
//! script in which some hosts go to other proxies, and seeing what a script
//! answers.

use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use hyper::Uri;

use super::Source;
use crate::config::{Overrides, PacLocation, pac_dir};
use crate::pac::{
    Fetched, PacEnv, Route, Rule, SystemResolver, Trust, Validators, check, fetch, load_script,
    read_script_file, tool_limits, wrap,
};

#[derive(Debug, Subcommand)]
pub enum PacCommand {
    /// Make a copy of a PAC script that sends some hosts to other proxies
    ///
    /// The hosts you name go to the proxies you name, and every other host is
    /// left to the original script, which is kept as it is. It is for giving a
    /// few destinations to another proxy without losing the rest of a script
    /// that belongs to somebody else. The copy is a plain file: add hosts to it
    /// by hand afterwards.
    Generate(GenerateArgs),

    /// Say which proxies a PAC script gives for some URLs
    ///
    /// With several --script they are shown side by side, which is how to see
    /// what a copy changes. The names a script looks up are looked up for real.
    Test(TestArgs),
}

#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// The script to start from: a file, or an http:// or https:// address
    #[arg(long, value_name = "FILE|URL")]
    pub from: PacLocation,

    /// A host that goes to the proxy list, repeated or separated by commas. A
    /// name covers its sub-domains; * and ? match any text
    #[arg(
        long = "host",
        required = true,
        value_delimiter = ',',
        value_name = "HOST"
    )]
    pub hosts: Vec<String>,

    /// What those hosts get: DIRECT, or PROXY host:port, several separated by
    /// semicolons, tried in order
    #[arg(long, value_name = "LIST")]
    pub proxy: String,

    /// Where to write the copy: a file name alone goes in the `pac` folder next
    /// to the configuration file, anything with a folder in it is the path as
    /// written
    #[arg(long, value_name = "NAME|PATH")]
    pub output: PathBuf,

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

    /// A script to ask: a file, or an address. A file name alone is looked for
    /// in the `pac` folder. Repeat it to compare. Without it, the script of the
    /// configuration
    #[arg(long = "script", value_name = "FILE|URL")]
    pub scripts: Vec<PacLocation>,
}

pub(super) fn run(
    command: PacCommand,
    config: Option<PathBuf>,
    overrides: Overrides,
    password_prompt: bool,
) -> anyhow::Result<()> {
    match command {
        PacCommand::Generate(args) => generate(&args, config.as_deref()),
        PacCommand::Test(args) => {
            let scripts = if args.scripts.is_empty() {
                // Read, not started: this is a tool, with nothing to log.
                let source = Source::new(config.clone(), overrides, password_prompt)?;
                match source.read()?.pac {
                    Some(pac) => vec![pac.location],
                    None => {
                        bail!("the configuration has no PAC script to ask: name one with --script")
                    }
                }
            } else {
                args.scripts.clone()
            };
            test(&args.urls, scripts, config.as_deref())
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
        url @ PacLocation::Url(_) => Ok(Located {
            location: url,
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

async fn read_script(location: &PacLocation) -> anyhow::Result<Vec<u8>> {
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
    }
}

/// A string for a TOML file: a literal one where it can be, so that a Windows
/// path needs no escapes.
fn toml_string(text: &str) -> String {
    if text.contains('\'') {
        format!("{text:?}")
    } else {
        format!("'{text}'")
    }
}

fn generate(args: &GenerateArgs, config: Option<&Path>) -> anyhow::Result<()> {
    let rule = Rule::new(&args.hosts, &args.proxy)?;
    let output = in_pac_dir(&args.output, config)?;
    if output.is_dir() {
        bail!("{} is a folder: name the file", output.display());
    }
    // Before anything is fetched: an edited copy is not to be lost by mistake.
    if output.exists() && !args.force {
        bail!(
            "{} exists already, and may have been edited by hand: name another file, or give \
             --force to replace it (the old one is kept as {}.prev)",
            output.display(),
            output.display()
        );
    }
    let Located {
        location: from,
        bare,
    } = located(args.from.clone(), config)?;
    let source = Located {
        location: from.clone(),
        bare,
    };

    let (script, answers) = runtime()?.block_on(async {
        let original = source.read().await?;
        let script = wrap(&original, &rule, &from.to_string());
        let answers = check(&script, &rule).await?;
        anyhow::Ok((script, answers))
    })?;

    let kept = write_script(&output, &script, args.force)?;

    println!("from:        {from}");
    println!(
        "rule:        {} -> {}",
        rule.hosts().join(", "),
        rule.proxy()
    );
    for (host, routes) in &answers {
        let shown = routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        println!("checked:     {host} -> {shown}");
    }
    let unused = rule.unused();
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
    println!();
    println!("To use it, in the configuration file:");
    println!("    [pac]");
    println!("    file = {}", toml_string(&output.display().to_string()));
    if pac_dir(config).is_some_and(|dir| output.parent() == Some(dir.as_path())) {
        println!(
            "(a path relative to the configuration file works too: file = 'pac/{}')",
            output
                .file_name()
                .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
        );
    }
    println!(
        "To see what changed:  gatir pac test --script <the original> --script <this one> URL..."
    );
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

fn test(urls: &[String], scripts: Vec<PacLocation>, config: Option<&Path>) -> anyhow::Result<()> {
    let targets = urls
        .iter()
        .map(|text| target(text))
        .collect::<anyhow::Result<Vec<_>>>()?;
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
    let width = labels.iter().map(String::len).max().unwrap_or(0);

    let failures = runtime()?.block_on(async {
        // The names a script looks up are looked up for real: what is shown is
        // what gatir would do, here and now.
        let env = PacEnv::system(Arc::new(SystemResolver::new(
            Duration::from_secs(2),
            Duration::from_secs(60),
        )));
        let mut loaded = Vec::new();
        for (script, label) in scripts.iter().zip(&labels) {
            let pac = match script.read().await {
                Ok(bytes) => load_script(&bytes, tool_limits(), env.clone())
                    .await
                    .map_err(|err| format!("the script is not usable: {err}")),
                Err(err) => Err(err.to_string()),
            };
            loaded.push((label.clone(), pac));
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
            PathBuf::from("/srv/gatir/pac/a.pac")
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
    fn toml_strings_need_no_escapes_for_a_windows_path() {
        assert_eq!(toml_string("C:\\Users\\a\\x.pac"), "'C:\\Users\\a\\x.pac'");
        assert_eq!(toml_string("it's.pac"), "\"it's.pac\"");
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
