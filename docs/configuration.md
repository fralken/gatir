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
