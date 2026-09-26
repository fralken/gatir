//! The manual pages of gatir, written from its command-line definition, so that
//! what they say of the options is what the program accepts. What the
//! definition cannot say (the files, the environment, the signals, the exit
//! status) is written here, by hand.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::CommandFactory;
use clap_mangen::Man;
use gatir::cli::Cli;

/// What the page of the program says after its one-line description.
const DESCRIPTION: &str = r#".PP
gatir is a local proxy that logs in to the proxy of a company for programs that cannot: a browser, \fBcurl\fR(1), \fBgit\fR(1), a build tool. The program is pointed at gatir, an HTTP proxy on the loopback (127.0.0.1:3128 by default), and gatir authenticates to the corporate proxy, the \fIparent\fR, on its behalf, so that nobody has to type a password. It can also serve SOCKS5 and forward local ports to fixed destinations.
.PP
To the parent gatir authenticates with NTLM, using a password, or a hash of it, kept in the configuration, or with Negotiate, using the identity of the logged\-in user: Kerberos when the system can use it, and NTLM inside Negotiate when it cannot (SSPI on Windows, the GSS\-API elsewhere). A PAC script, from a file or an address, can choose the parent for each request.
.PP
The configuration is a TOML file. An option on the command line takes the place of the same setting in the file.
"#;

/// The sections after the options and the commands.
const SECTIONS: &str = r#".SH EXAMPLES
Serve the programs of this computer through a proxy that wants NTLM, asking for the password once:
.PP
.RS 4
.nf
\fBgatir run \-\-parent proxy.example.com:8080 \-u alice \-d EXAMPLE \-\-password\-prompt\fR
.fi
.RE
.PP
Let the ticket of the logged\-in user do it, with the proxy chosen by a PAC script, and a SOCKS5 server as well:
.PP
.RS 4
.nf
\fBgatir run \-m negotiate \-\-pac https://pac.example.com/proxy.pac \-\-socks5 127.0.0.1:1080\fR
.fi
.RE
.PP
Print the line that puts the hash of a password in the configuration, in place of the password:
.PP
.RS 4
.nf
\fBgatir hash\fR
.fi
.RE
.PP
Find out why single sign\-on does not work:
.PP
.RS 4
.nf
\fBgatir negotiate \-\-service HTTP@proxy.example.com\fR
.fi
.RE
.SH FILES
.TP
\fI$XDG_CONFIG_HOME/gatir/gatir.toml\fR, \fI~/.config/gatir/gatir.toml\fR, \fI/etc/gatir/gatir.toml\fR
The configuration file, when \fB\-\-config\fR is not given: the first of them that exists is read. On Windows, \fI%APPDATA%\\gatir\\gatir.toml\fR takes the place of the first two. The file may hold a password, so gatir warns when other users can read it, and when they can change it.
.TP
\fI/usr/share/doc/gatir/\fR
An example configuration (\fIexamples/gatir.example.toml\fR) and the documentation.
.SH ENVIRONMENT
.TP
\fBRUST_LOG\fR
The log filter, for instance \fBgatir=debug\fR. It takes the place of \fB\-\-log\-level\fR.
.TP
\fBNO_COLOR\fR
When it is set the log has no colors. It has none either when it does not go to a terminal.
.TP
\fBXDG_CONFIG_HOME\fR, \fBHOME\fR
Where the configuration file is looked for.
.TP
\fBKRB5CCNAME\fR, \fBKRB5_CONFIG\fR
Read by the Kerberos library of the system, on the systems where Negotiate uses it.
.SH SIGNALS
.TP
\fBSIGINT\fR, \fBSIGTERM\fR
Stop. gatir stops accepting connections and lets the active requests and tunnels finish, for at most the grace period (\fBshutdown_grace_secs\fR); a second \fBSIGINT\fR closes everything at once.
.TP
\fBSIGHUP\fR
Read the configuration again (not on Windows). The parents, the PAC script, \fBno_proxy\fR, the access rules, the header fields, the credentials, the timeouts and the password of the SOCKS5 server are replaced, and what is in flight finishes under the old ones. Where gatir listens, the tunnels, the addresses of the SOCKS5 server and the log level change only when gatir is started again, and gatir says so. A configuration that is not valid changes nothing.
.SH EXIT STATUS
.TP
\fB0\fR
Stopped by \fBSIGINT\fR or \fBSIGTERM\fR; or, for the other commands, done.
.TP
\fB1\fR
An error: the configuration is not valid, an address could not be used, or the command failed. The message says which.
.SH SEE ALSO
\fBgatir\-run\fR(1), \fBgatir\-hash\fR(1), \fBgatir\-config\fR(1), \fBgatir\-negotiate\fR(1)
.PP
The documents in \fI/usr/share/doc/gatir/docs/\fR: configuration, authentication, PAC scripts, ports forwarded through the proxy, the SOCKS5 server.
"#;

/// A day as `YYYY-MM-DD`, from seconds since the Unix epoch (UTC).
fn date_of(seconds: u64) -> String {
    // Civil date from a day count, as in Howard Hinnant's `civil_from_days`.
    let days = i64::try_from(seconds / 86_400).unwrap_or(0) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// The date of the pages: `SOURCE_DATE_EPOCH` when it is set, so that building
/// twice gives the same pages, else today.
fn date() -> String {
    let seconds = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs())
        });
    date_of(seconds)
}

/// Every page, as its file name and its text.
pub fn pages() -> io::Result<Vec<(String, String)>> {
    let mut command = Cli::command().disable_help_subcommand(true);
    command.build();
    let mut pages = Vec::new();
    collect(&command, true, &mut pages)?;
    Ok(pages)
}

fn collect(
    command: &clap::Command,
    is_program: bool,
    pages: &mut Vec<(String, String)>,
) -> io::Result<()> {
    for sub in command.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        collect(sub, false, pages)?;
    }
    let man = Man::new(command.clone())
        .date(date())
        .source(format!("gatir {}", env!("CARGO_PKG_VERSION")))
        .manual("gatir Manual");
    let mut text = Vec::new();
    if is_program {
        program_page(&man, &mut text)?;
    } else {
        man.render(&mut text)?;
    }
    let text = String::from_utf8(text).map_err(io::Error::other)?;
    pages.push((man.get_filename(), text));
    Ok(())
}

/// The page of the program itself: what the definition gives, and the rest.
fn program_page(man: &Man, out: &mut Vec<u8>) -> io::Result<()> {
    man.render_title(out)?;
    man.render_name_section(out)?;
    man.render_synopsis_section(out)?;
    man.render_description_section(out)?;
    out.extend_from_slice(DESCRIPTION.as_bytes());
    man.render_options_section(out)?;
    man.render_subcommands_section(out)?;
    out.extend_from_slice(SECTIONS.as_bytes());
    man.render_version_section(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page<'a>(pages: &'a [(String, String)], name: &str) -> &'a str {
        pages
            .iter()
            .find(|(file, _)| file == name)
            .unwrap_or_else(|| {
                panic!(
                    "no page {name}: {:?}",
                    pages.iter().map(|p| &p.0).collect::<Vec<_>>()
                )
            })
            .1
            .as_str()
    }

    #[test]
    fn a_date_is_written_as_year_month_day() {
        assert_eq!(date_of(0), "1970-01-01");
        assert_eq!(date_of(951_782_400), "2000-02-29");
        assert_eq!(date_of(1_000_000_000), "2001-09-09");
        assert_eq!(date_of(1_782_432_000), "2026-06-26");
        assert_eq!(date_of(4_102_444_799), "2099-12-31");
    }

    #[test]
    fn every_page_has_a_title_a_date_a_source_and_a_manual() {
        for (name, text) in pages().unwrap() {
            let title = text
                .lines()
                .find(|line| line.starts_with(".TH "))
                .unwrap_or_else(|| panic!("{name} has no .TH"));
            let stem = name.trim_end_matches(".1");
            let expected_source = format!("\"gatir {}\"", env!("CARGO_PKG_VERSION"));
            assert!(title.starts_with(&format!(".TH {stem} 1 ")), "{title}");
            assert!(title.contains(&expected_source), "{title}");
            assert!(title.contains("\"gatir Manual\""), "{title}");
            // The third field is a date.
            let date = title.split_whitespace().nth(3).unwrap_or_default();
            assert!(date.len() == 10 && date.as_bytes()[4] == b'-', "{title}");
        }
    }

    #[test]
    fn there_is_a_page_for_the_program_and_for_each_command() {
        let pages = pages().unwrap();
        let names: Vec<&str> = pages.iter().map(|(name, _)| name.as_str()).collect();
        for expected in [
            "gatir.1",
            "gatir-run.1",
            "gatir-hash.1",
            "gatir-config.1",
            "gatir-config-check.1",
            "gatir-negotiate.1",
        ] {
            assert!(names.contains(&expected), "{expected} in {names:?}");
        }
    }

    #[test]
    fn the_page_of_the_program_has_the_sections_of_a_manual() {
        let pages = pages().unwrap();
        let text = page(&pages, "gatir.1");
        for section in [
            "NAME",
            "SYNOPSIS",
            "DESCRIPTION",
            "OPTIONS",
            "SUBCOMMANDS",
            "EXAMPLES",
            "FILES",
            "ENVIRONMENT",
            "SIGNALS",
            "EXIT STATUS",
            "SEE ALSO",
        ] {
            assert!(
                text.contains(&format!(".SH {section}")),
                "{section}\n{text}"
            );
        }
        // Each section once.
        assert_eq!(text.matches(".SH FILES").count(), 1);
    }

    #[test]
    fn what_the_pages_say_of_the_options_is_what_the_program_accepts() {
        let mut command = Cli::command();
        command.build();
        let run = command.find_subcommand("run").expect("run");
        let pages = pages().unwrap();
        let text = page(&pages, "gatir-run.1");
        let mut checked = 0;
        for argument in run.get_arguments().filter(|a| !a.is_hide_set()) {
            if let Some(long) = argument.get_long() {
                // roff writes a hyphen as \-.
                assert!(
                    text.contains(&format!("\\-\\-{}", long.replace('-', "\\-"))),
                    "--{long}\n{text}"
                );
                checked += 1;
            }
        }
        assert!(checked >= 10, "only {checked} options were checked");
        // The ones added in the later steps are there.
        for long in ["pac", "socks5", "tunnel", "parent", "method", "log\\-level"] {
            assert!(text.contains(&format!("\\-\\-{long}")), "--{long}");
        }
    }

    #[test]
    fn the_hand_written_parts_name_what_the_program_reads_and_reacts_to() {
        let pages = pages().unwrap();
        let text = page(&pages, "gatir.1");
        for what in [
            "gatir.toml",
            "/etc/gatir/gatir.toml",
            "RUST_LOG",
            "NO_COLOR",
            "SIGHUP",
            "SIGTERM",
            "shutdown_grace_secs",
        ] {
            assert!(text.contains(what), "{what}");
        }
    }

    #[test]
    fn a_line_never_starts_with_a_dot_by_accident() {
        // In roff a line that starts with a dot is a request, so a sentence that
        // began with one would vanish from the page.
        let requests = [
            ".TH", ".SH", ".SS", ".PP", ".TP", ".IP", ".RS", ".RE", ".nf", ".fi", ".br", ".sp",
            ".B", ".I", ".BR", ".RB", ".IR", ".SB", ".ie", ".el", ".if", ".\\\"", ".ad", ".na",
            ".hy", ".nh", ".ta", ".ti", ".de", ".ds", ".nr", ".so", ".ft", ".ne", ".in",
        ];
        for (name, text) in pages().unwrap() {
            for (number, line) in text.lines().enumerate() {
                if line.starts_with('.') && !line.starts_with("..") {
                    let word = line.split_whitespace().next().unwrap_or(line);
                    assert!(
                        requests.iter().any(|request| word == *request),
                        "{name}:{}: an unknown request {word:?}",
                        number + 1
                    );
                }
            }
        }
    }
}
