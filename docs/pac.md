# Choosing the proxy with a PAC file

A PAC (proxy auto-configuration) file is a JavaScript function,
`FindProxyForURL(url, host)`, that says for each request whether to go direct
or through which proxies. gatir runs it in place of a fixed list of parents.

```toml
[pac]
file = "proxy.pac"        # relative to this file, or absolute
# or, instead of a file:
url = "http://wpad.example.com/proxy.pac"
# or, on macOS and Windows, the address the system is set to use:
system = true
```

or `gatir run --pac proxy.pac`, where anything that starts with `http://` or
`https://` is an address and anything else is a file. A PAC script and
`parents` are two ways of finding the proxy, so they exclude each other: naming
one on the command line replaces the other in the configuration file.

The credentials apply to whichever proxy the script picks. `no_proxy` is asked
first: what it lists goes direct without asking the script.

## Where the script comes from, and keeping it current

The script is read when gatir starts and again at a fixed interval:

```toml
[pac]
url = "http://wpad.example.com/proxy.pac"
refresh_secs = 3600       # how often to look again (60 for a file, and for the system's)
fetch_timeout_secs = 15   # for the whole fetch, redirects included
```

### The script of the system (macOS and Windows)

`system = true` takes the address from the proxy settings of the system, which
gatir asks of it, so that the address does not have to be copied into the
configuration. On macOS it is the "Automatic Proxy Configuration" of the network
settings (System Settings, Network, Proxies), read through the SystemConfiguration
framework. On Windows it is the "setup script" of the proxy settings of the user
(Settings, Network, Proxy), read through WinHTTP, which takes group policy into
account. It is asked again at every look at the script, and a script that
the company's tools serve from an address that changes (a name with a hash in
it, say) is followed: the next look fetches the new one, and what the old
address said about its script (its `ETag`) is not sent to the new. The
interval is the one of a file, 60 seconds, because asking the system costs
nothing and a script that has not changed is not fetched again.

`system` is one of `file`, `url` and `system`: naming two is refused. If the
system is not set to use a script, or gives no address, or one that is not
`http://` or `https://`, gatir says so in the log and in the 502 it answers
while it has no script, and keeps the last script that worked. Starting gatir
before the setting is made is not an error. The overrides work as with any
script, and `gatir pac test` and `gatir pac export` use the address the system
gives at that moment (`export` says which in its `from:` line).

On Windows the setting is the one of the user that gatir runs as. If it only
says "Automatically detect settings" (WPAD), with no address, gatir cannot follow
it yet: it says so, and the address has to be given with `url`.

A Linux desktop has no one place for the setting (it depends on the desktop), so
there `system = true` is refused when the configuration is read, which says to
name the script with `file` or `url`.

A version of the script that cannot be read, or does not load, never replaces
the one in use. The problem is logged, the last version that worked stays in
service, and gatir looks again after 5 seconds, then 10, 20 and so on, up to
`refresh_secs`. A new version that loads takes over for the requests that
begin after it.

An address is fetched with a plain `GET` on a connection of its own, straight
to the server, and never through a parent proxy: the parents are what the
script is for, so they are not known until it has been read. Up to 5 redirects are followed (a
redirect from `https` to `http` is refused, and so is one to an address with a
user name in it), the script may weigh 16 MB at most, and the server is asked
to send it uncompressed. The server may answer `304` when nothing changed:
gatir sends back the `ETag` and `Last-Modified` it was given. A query string in
the address, which may hold a token, is left out of the log and of error
messages.

An `https://` address is checked by the operating system: the server's
certificate must be valid for the name in the address (or the IP address, if
that is what the address has), unexpired, and issued by an authority the system
trusts. A corporate authority installed in the system's store therefore works
with no configuration; on Linux, `SSL_CERT_FILE` or `SSL_CERT_DIR` point OpenSSL
at another set of authorities. A server whose certificate is refused is sent
nothing, and the error says what to check.

If the script cannot be fetched when gatir starts, gatir starts anyway, since
the network may not be up yet: every request is answered with a 502 that says
why nothing could choose a proxy, until a fetch succeeds. A file that cannot be
read at start-up stops gatir, as it did before.

## What the script is asked

- For a plain HTTP request: the URL, with the host in lower case and no user
  information, and the host.
- For a tunnel (`CONNECT`): `https://host/`, with `:port` when it is not 443.

Nothing is remembered between requests: the script may look at the whole URL or
at the time, so its answer is asked for every time. What is worth caching, the
answers of name lookups, is cached.

## Hosts that go elsewhere than the script says

A script that belongs to the company cannot be edited, and some destinations
need another proxy than the one it picks (a download its proxy blocks, say, that
another lets through). The `[[pac.overrides]]` tables of the configuration name
those hosts and the proxies they get, and every other host is left to the
script:

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

- `hosts` is a list of names. A name covers the domain and its sub-domains
  (`cdn.example.net` covers `pkg.cdn.example.net`, and not
  `notcdn.example.net`); `*` and `?` make a pattern. They are matched against
  the host, never the path.
- `proxy` is what those hosts get: `DIRECT`, or `PROXY host:port`, several
  separated by semicolons, tried in order.
- The first entry that lists a host decides, so a specific name goes before a
  pattern that also covers it.
- `no_proxy` is asked first: what it lists goes direct without asking the script
  or the overrides.

gatir adds them to the script as it loads it, and keeps the script as it was
read: the script is not changed on disk, and a new version of it, found at the
next look, gets the overrides too. Changing only the overrides and reloading
(`SIGHUP`) applies them at once, without reading the script again, so a script
that cannot be fetched just then is not lost. A configuration whose overrides
are not valid (a name that is not a host, a proxy that is not one) is refused
with the number of the entry, like any other mistake in the file.

The overrides are added as a block of JavaScript after the script, which wraps
`FindProxyForURL` (and `FindProxyForURLEx`, if there is one) and answers first.
Nothing depends on how the script writes its function.

### Seeing what they change

`gatir pac test` asks the script of the configuration about URLs, without
starting the proxy, and shows the answer without the overrides next to the
answer with them:

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

A host name alone is `https://HOST/`, which is what gatir asks for a tunnel.
`--script FILE|URL` asks a script of your choosing, as it is, without the
overrides, and may be repeated to compare. The names a script looks up are
looked up for real, so the answer is the one gatir would get here and now. The
exit status is not zero if a script could not be used.

### Writing the script as a file

`gatir pac export` writes the script that gatir runs, with the overrides in it,
for you to read or for another program (a browser) to use:

```
gatir pac export --output local.pac
gatir pac export > local.pac
```

`--output` is a path, used as it is written (a relative one is from the current
folder, and a folder that is missing is made); without it the script goes to the
standard output. An existing file is not replaced without `--force`, which keeps
the old one as `name.pac.prev`. The
script is checked before it is written: it is loaded with the engine of gatir,
and each host of the overrides is asked what it answers, so an entry that an
earlier one hides is reported.

## What it may return

`DIRECT`, `PROXY host:port` (also `HTTP`), and lists of them separated by
semicolons. Entries are tried in order, and one that cannot be reached, or that
ends the connection without answering, is tried last for a minute (see
[a parent that does not work](failover.md)). `HTTPS`, `SOCKS`, `SOCKS4` and `SOCKS5` entries are read but
not used yet: they are skipped, and if nothing else is left the client gets a
502 that says so.

## The functions the script can call

The classic list: `dnsDomainIs`, `localHostOrDomainIs`, `isPlainHostName`,
`isResolvable`, `isInNet`, `dnsResolve`, `dnsDomainLevels`, `shExpMatch`,
`myIpAddress`, `weekdayRange`, `dateRange`, `timeRange`, `alert`; and the IPv6
variants `isResolvableEx`, `isInNetEx`, `dnsResolveEx`, `myIpAddressEx`,
`sortIpAddressList`, `getClientVersion`. A script may define
`FindProxyForURLEx` instead of `FindProxyForURL`.

A call with too few or too many arguments, or with `null` (which `dnsResolve`
gives for a name that does not resolve), answers false instead of failing.
Host names are compared without regard to case; `shExpMatch` is case sensitive.
`myIpAddress` is the address of the interface that would be used to reach the
network, not the one the host name resolves to.

Ranges of time run past the end of the week, the day or the year: `weekdayRange("FRI",
"MON")`, `timeRange(22, 6)`, `dateRange("NOV", "FEB")`. The second hour of
`timeRange(9, 17)` is included in full, and a range that ends in a month ends
on its last day.

## Limits, and what happens when they are hit

A script that loops for ever, recurses without end, eats memory or runs a
pathological regular expression is stopped. The limits are fixed: one
evaluation may take 5 seconds (name lookups included) and 64 MB, and four
evaluations can run at once. A name lookup is waited for 2 seconds, and its
answer is remembered for 60. A loop inside a built-in function cannot be
interrupted from inside; its worker is given up on and replaced, and after four
of them the script is declared broken.

What is wrong with a file is found at start-up: gatir does not start if the
file is missing, too large (over 16 MB), has a syntax error or does not define
`FindProxyForURL`. Once running, an error in the script, a result that is not a
string or has no proxy gatir can read, or a script that runs too long is
answered with a 502 that says what went wrong. A request is never sent direct
on the strength of a broken script, or of a script that could not be fetched.

## Checking a PAC file

`crates/gatir/tests/pac_file.rs` compares the results of a PAC file with those
of another engine, on a list of URLs, with fake name lookups so that only the
script and the helpers are compared. It is run by hand on a file that is not part
of the repository; the comments in the file say how.

## The engine

Scripts run under QuickJS, through the `rquickjs` crate: why, what was measured
against the alternatives, and what it costs, are in
[docs/pac-engine.md](pac-engine.md).
