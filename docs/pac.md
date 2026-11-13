# PAC scripts

A PAC (proxy auto-configuration) script is a JavaScript function,
`FindProxyForURL(url, host)`, that says for each request whether to go direct or
through which proxies. gatir can use one instead of a fixed list of parents.

```toml
[pac]
file = "proxy.pac"        # relative to the configuration file, or absolute
# or, instead of a file:
url = "http://wpad.example.com/proxy.pac"
# or, on macOS and Windows, the script your system's proxy settings use:
system = true
```

On the command line, `gatir run --pac proxy.pac` does the same: a value that
starts with `http://` or `https://` is an address, anything else is a file,
relative to the current folder. A PAC script and `parents` are two ways of
choosing the proxy, so only one can be set; naming one on the command line
replaces the other from the file.

The credentials apply to whichever proxy the script chooses. `no_proxy` comes
first: what it lists goes direct without asking the script.

## Where the script is read from

### A file or an address

gatir fetches an address with a plain `GET`, directly from the server and never
through a parent: the parents are what the script chooses, so they are not
known until it has been read.

- Up to 5 redirects are followed. A redirect from `https` to `http` is refused,
  and so is one to an address with a user name in it.
- The script may be at most 16 MB, and the server is asked not to compress it.
- When it checks for changes, gatir sends back the `ETag` and `Last-Modified` it
  was given, so the server can answer `304` and nothing is downloaded again.
- A query string in the address may hold a token, so it is left out of the log
  and of error messages.
- `fetch_timeout_secs` (default 15) limits the whole fetch, redirects included.

The operating system checks an `https://` address: the server's certificate must
be valid for the name (or IP address) in the address, not expired, and issued by
an authority the system trusts. A corporate authority installed in the system's
store therefore works with no configuration. On Linux, `SSL_CERT_FILE` or
`SSL_CERT_DIR` point OpenSSL at other authorities. gatir sends nothing to a
server whose certificate is refused, and the error says what to check.

### Your system's setting (macOS and Windows)

`system = true` uses the script that your system's proxy settings name, so you do
not have to copy its address into the configuration:

- **macOS**: "Automatic Proxy Configuration" in System Settings, Network,
  Proxies, read through the SystemConfiguration framework.
- **Windows**: "Use setup script" in Settings, Network, Proxy, for the user that
  gatir runs as, read through WinHTTP. A setting that only says "Automatically
  detect settings" (WPAD) gives no address, so gatir cannot follow it yet: it
  says so, and you need to set `url` instead.
- **Linux**: there is no single place for this setting (it depends on the
  desktop), so `system = true` is refused when the configuration is read.

gatir asks the system for the address before every check for changes. If the
address changes (some company tools serve the script under a name with a hash in
it), the next check fetches the new script, and the `ETag` of the old address is
not sent to the new one.

If the system names no script, or gives an address that is not `http://` or
`https://`, gatir says so in the log and in the `502` it answers while it has no
script, and keeps the last script that worked. Starting gatir before the setting
is made is not an error. `gatir pac test` and `gatir pac export` use the address
the system gives at that moment (`export` names it in its `from:` line).

## Keeping it current

gatir reads the script when it starts, and checks it for changes every
`refresh_secs`. If you leave that out, it depends on where the script is: every
60 seconds for a file or the system's script, every hour for an address.

A new version that cannot be read, or does not load, never replaces the one in
use. gatir logs the problem, keeps the last version that worked, and tries again
after 5 seconds, then 10, 20 and so on, up to `refresh_secs`. A new version that
loads applies to the requests that begin after it.

At start-up, the two kinds of script behave differently:

- **A file** that is missing, too large, has a syntax error or does not define
  `FindProxyForURL` stops gatir with an error.
- **An address** that cannot be fetched does not stop gatir, since the network
  may not be up yet. Until a fetch succeeds, every request gets a `502` that
  says why no proxy could be chosen.

## What the script is asked

- For a plain HTTP request: the URL, with the host in lower case and without
  user information, and the host.
- For a tunnel (`CONNECT`): `https://host/`, with `:port` when it is not 443.

The script may look at the whole URL or at the time, so gatir asks it again for
every request. Only the answers of name lookups are cached.

## What it may return

`DIRECT`, `PROXY host:port` (or `HTTP host:port`), and lists of them separated
by semicolons. gatir tries the entries in order. One that cannot be reached, or
that closes the connection without answering, is tried last for a minute: see
[When a parent proxy does not work](failover.md).

`HTTPS`, `SOCKS`, `SOCKS4` and `SOCKS5` entries are understood but not used yet:
gatir skips them, and if nothing else is left, the program gets a `502` that
says so.

## Hosts that go to other proxies than the script says

You usually cannot edit your company's script, and some destinations need
another proxy than the one it chooses: a download that its proxy blocks and
another lets through, say. `[[pac.overrides]]` names those hosts and the proxies
they get. Every other host is left to the script.

```toml
[pac]
url = "https://pac.example.com/proxy.pac"

[[pac.overrides]]
hosts = ["downloads.example.com", "cdn.example.net"]
proxy = "PROXY a.example.com:80; PROXY b.example.com:80"

[[pac.overrides]]
hosts = ["*.intranet.example.com"]
proxy = "DIRECT"
```

- `hosts` is a list of names. A name covers the domain and its sub-domains:
  `cdn.example.net` covers `pkg.cdn.example.net`, but not `notcdn.example.net`.
  `*` and `?` make a pattern. Only the host is matched, never the path.
- `proxy` is what those hosts get: `DIRECT`, or `PROXY host:port`; separate
  several with semicolons to try them in order.
- The first entry that lists a host decides, so put a specific name before a
  pattern that also covers it.
- `no_proxy` comes first: what it lists goes direct without asking the script or
  the overrides.

gatir adds the overrides to the script when it loads it, as a block of
JavaScript that wraps `FindProxyForURL` (and `FindProxyForURLEx`, if there is
one) and answers first. The script on disk is not changed, and a new version of
it gets the overrides too. If you change only the overrides and reload
(`SIGHUP`), they apply at once, without fetching the script again. An override
that is not valid (a name that is not a host, a proxy that is not one) is
refused with its number, like any other mistake in the file.

### Seeing what they change

`gatir pac test` asks the configured script about some URLs, without starting the
proxy, and shows the answer without and with the overrides:

```
gatir pac test downloads.example.com https://pkg.cdn.example.net/ www.example.org
```

```
https://downloads.example.com/   (differs)
  original        PROXY 127.0.0.1:9000
  with overrides  PROXY a.example.com:80; PROXY b.example.com:80
https://pkg.cdn.example.net/   (differs)
  original        PROXY 127.0.0.1:9000
  with overrides  PROXY a.example.com:80; PROXY b.example.com:80
https://www.example.org/
  original        PROXY 127.0.0.1:9000
  with overrides  PROXY 127.0.0.1:9000
```

- A host name alone stands for `https://HOST/`, which is what gatir asks for a
  tunnel.
- `--script FILE|URL` asks another script, as it is and without the overrides.
  Repeat it to compare several.
- The names a script looks up are looked up for real, so the answer is the one
  gatir would get here and now.
- The exit status is not zero if a script could not be used.

### Writing the script to a file

`gatir pac export` writes the script that gatir runs, overrides included, for you
to read or for another program, such as a browser, to use:

```
gatir pac export --output local.pac
gatir pac export > local.pac
```

- `--output` is a path, relative to the current folder; missing folders are
  created. Without it, the script goes to standard output.
- An existing file is replaced only with `--force`, which keeps the old one as
  `local.pac.prev`.
- Before writing, gatir loads the script and asks it about one host of each
  override, so an override hidden by an earlier one is reported.

## The functions a script can call

The classic ones: `dnsDomainIs`, `localHostOrDomainIs`, `isPlainHostName`,
`isResolvable`, `isInNet`, `dnsResolve`, `dnsDomainLevels`, `shExpMatch`,
`myIpAddress`, `weekdayRange`, `dateRange`, `timeRange` and `alert`. The IPv6
ones: `isResolvableEx`, `isInNetEx`, `dnsResolveEx`, `myIpAddressEx`,
`sortIpAddressList` and `getClientVersion`. A script may define
`FindProxyForURLEx` instead of `FindProxyForURL`.

- A call with too few or too many arguments, or with `null` (what `dnsResolve`
  returns for a name that does not resolve), returns false instead of failing.
- Host names are compared without regard to case; `shExpMatch` is case
  sensitive.
- `myIpAddress` is the address of the network interface that would be used to
  reach the network, not the address the computer's name resolves to.
- Ranges may wrap around the end of the week, the day or the year:
  `weekdayRange("FRI", "MON")`, `timeRange(22, 6)`, `dateRange("NOV", "FEB")`.
- `timeRange(9, 17)` includes the whole of the last hour, until 17:59:59. A
  range that ends in a month ends on that month's last day.

## Limits

A script that loops for ever, recurses without end, uses too much memory or runs
a pathological regular expression is stopped. The limits are fixed:

- one evaluation may take 5 seconds and 64 MB;
- four evaluations can run at once;
- a name lookup is waited for 2 seconds, and its answer is remembered for 60.

Some work cannot be interrupted from inside: a loop inside a built-in function,
or a name lookup that does not end. gatir waits 2 more seconds for such an
evaluation, then gives up on it and replaces its worker. While four given-up
workers are still busy, every evaluation fails, until one of them is done.

When a running script fails (an error, a result that is not a string or names no
proxy gatir can use, or a timeout), the request gets a `502` that says what went
wrong. gatir never sends a request direct because a script is broken or could
not be fetched.

## Comparing with another engine

`crates/gatir/tests/pac_file.rs` compares the answers of a PAC file with those
of another engine on a list of URLs, with made-up name lookups so that only the
script and the functions are compared. You run it by hand on a file that is not
part of the repository; the comments in that file say how.

## The engine

Scripts run under QuickJS-ng, through the `rquickjs` crate. Why, what it was
compared with, and what it costs: see [The PAC script engine](pac-engine.md).
