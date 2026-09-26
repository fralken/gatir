# Where the configuration is, and what gatir says

## Which file is read

`gatir run` and `gatir config check` read the file named with `--config`. Without
it they look, in this order, for

1. `$XDG_CONFIG_HOME/gatir/gatir.toml`, or `~/.config/gatir/gatir.toml` when that
   variable is not set (a relative `XDG_CONFIG_HOME` is ignored, as the XDG
   specification says);
2. `/etc/gatir/gatir.toml` (Linux and macOS);
3. on Windows, `%APPDATA%\gatir\gatir.toml`.

The first one that exists is used. If there is none, the built-in defaults apply
(a proxy on `127.0.0.1:3128` that connects directly), together with whatever the
command line says. A file that is named and is not there is an error, not a
reason to look elsewhere.

gatir says which file it read: `gatir config check` prints it, and `gatir run` logs
it when it starts.

## Who may read it

The file can hold a password, a hash, the password of the SOCKS5 server and header
values, so gatir looks at who can get at it when it starts, on Linux and macOS:

- if it holds any of those and other users can read it, it warns and says to
  `chmod 600` it;
- if other users can change it, it warns whether it holds secrets or not, since
  what the file says is where the traffic goes.

The warning does not stop gatir. Nothing is checked on Windows yet.

## The log

gatir logs to its standard error, at the level of `[log] level` or `--log-level`
(`RUST_LOG` overrides both). Colors are used only when standard error is a
terminal and `NO_COLOR` is not set, so a log that goes to a file, a pipe or a
service manager has no escape sequences in it.

## Changing the configuration while gatir runs

On Linux and macOS, `kill -HUP <pid>` makes gatir read its configuration again,
from the same file and with the same command-line options, and apply it. Every
request, tunnel and SOCKS5 client already being served finishes under the
settings it began with; the ones that come after use the new.

What a reload applies:

- the parents, the PAC script and its limits, and `no_proxy`;
- the `[access]` rules and the `[headers]` table;
- the credentials for the parent, and the user name and password of the SOCKS5
  server;
- the `[timeouts]`.

Connections to a parent that were kept for reuse are closed, since they may have
been authenticated as someone else, or lead to another parent. A PAC script whose
settings did not change is kept, and looked at again at once, so a reload is also
how to say that it changed; if it cannot be read just then, the last version that
worked stays. If the credentials did not change, the record of a parent that
refused them is kept too: reading the same file again is no reason to try the
account once more.

What only a new start applies is `listen`, the `[[tunnels]]`, the addresses of
`[socks5]`, and `[log] level`. If they changed, gatir says which, and goes on with
the values it started with; everything else in the file is applied.

A file that cannot be read, or is not valid, or names a PAC file that cannot be
used, changes nothing: gatir logs why, at the `error` level, and keeps the settings
it has. Without this signal a `SIGHUP` would end the process, so gatir catches it
from the start.
