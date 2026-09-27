# Choosing the proxy with a PAC file

A PAC (proxy auto-configuration) file is a JavaScript function,
`FindProxyForURL(url, host)`, that says for each request whether to go direct
or through which proxies. gatir runs it in place of a fixed list of parents.

```toml
[pac]
file = "proxy.pac"        # relative to this file, or absolute
# or, instead of a file:
url = "http://wpad.example.com/proxy.pac"
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
refresh_secs = 3600       # how often to look again (60 for a file)
fetch_timeout_secs = 15   # for the whole fetch, redirects included
```

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

## What it may return

`DIRECT`, `PROXY host:port` (also `HTTP`), and lists of them separated by
semicolons. Entries are tried in order, and one that cannot be reached is tried
last for a minute. `HTTPS`, `SOCKS`, `SOCKS4` and `SOCKS5` entries are read but
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

```toml
[pac]
file = "proxy.pac"
time_limit_ms = 5000      # one evaluation, name lookups included
memory_limit_mb = 64      # per script engine
workers = 4               # evaluations that can run at once
dns_timeout_ms = 2000     # how long a lookup is waited for
dns_ttl_secs = 60         # how long an answer is remembered
```

A script that loops for ever, recurses without end, eats memory or runs a
pathological regular expression is stopped. A loop inside a built-in function
cannot be interrupted from inside; its worker is given up on and replaced, and
after four of them the script is declared broken.

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
