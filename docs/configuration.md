# Configuration

This page covers where the configuration file is, who may read it, the log, and
how to reload a running gatir. [Settings](settings.md) lists what the file can
say.

## Where the file is

The commands that read the configuration (`run`, `config check`, `detect` and
`pac`) use the file named with `--config`. Without that option, they use the
first of these that exists:

1. `$XDG_CONFIG_HOME/gatir/gatir.toml`, or `~/.config/gatir/gatir.toml` when
   `XDG_CONFIG_HOME` is not set. A relative `XDG_CONFIG_HOME` is ignored, as the
   XDG specification says.
2. `/etc/gatir/gatir.toml` (Linux and macOS).
3. `%APPDATA%\gatir\gatir.toml` (Windows).

If none exists, gatir uses its built-in defaults: a proxy on `127.0.0.1:3128`
that connects directly, plus whatever the command line says. A file named with
`--config` that does not exist is an error; gatir does not look elsewhere.

`gatir config check` prints which file it read, and `gatir run` logs it when it
starts.

## File permissions

The file can hold secrets: a password or hash, the password of the SOCKS5
server, header values. When gatir starts on Linux or macOS, it checks who else
can get at the file:

- If the file holds a secret and other users can read it, gatir warns and tells
  you to `chmod 600` it.
- If other users can change it, gatir warns even when it holds no secret: the
  file decides where your traffic goes.

The warning does not stop gatir. Windows is not checked yet.

## The log

gatir logs to standard error, at the level of `[log] level` or `--log-level`.
The `RUST_LOG` environment variable replaces both. The log has colors only when
standard error is a terminal and `NO_COLOR` is not set, so a log written to a
file, a pipe or a service manager has no escape sequences in it.

## Reloading

On Linux and macOS, `kill -HUP <pid>` makes gatir read its configuration again,
from the same file and with the same command-line options. Requests, tunnels and
SOCKS5 clients already in progress finish with the old settings; new ones use
the new settings.

A reload applies:

- the parents, the PAC location, `refresh_secs`, `fetch_timeout_secs` and the
  overrides, and `no_proxy`;
- `[access]` and `[headers]`;
- the credentials, and the SOCKS5 user name and password;
- `[timeouts]`.

What happens to what gatir already holds:

- **Pooled connections** to parents are closed: they may have been
  authenticated as someone else, or lead to another parent.
- **The PAC script**: if its location and settings did not change, gatir keeps
  the loaded script, applies the new overrides, and checks the script for
  changes at once. So a reload is also a way to force a PAC refresh. If the
  script cannot be read at that moment, the previous one stays in use.
- **A refusal of the credentials**: if the credentials did not change, gatir
  still waits out the cooldown, since reloading the same file is no reason to
  try the account again.

Some settings apply only when gatir starts: `listen`, `[[tunnels]]`, the
`listen` addresses of `[socks5]`, and `[log] level`. If one of them changed,
gatir logs which, keeps the value it started with, and applies the rest.

If the file cannot be read, is not valid, or names a PAC file that cannot be
used, nothing changes: gatir logs why at the `error` level and keeps its current
settings.

gatir handles `SIGHUP` from the moment it starts, so the signal never
terminates it.
