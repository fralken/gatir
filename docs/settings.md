# Settings

Every setting of the configuration file, with its default. Every setting is
optional: an empty file, or no file at all, gives a proxy on `127.0.0.1:3128`
that connects directly. [Configuration](configuration.md) says where the file is
looked for and how to reload it, and [`gatir.example.toml`](../gatir.example.toml)
is a commented example.

A command-line option replaces the same setting from the file. Settings marked
**restart** are read only when gatir starts; a reload (`SIGHUP`) applies all
the others.

## Top level

| Setting | Type | Default | Option |
|---|---|---|---|
| `listen` | list of `"address:port"` | `["127.0.0.1:3128"]` | `--listen` |
| `parents` | list of `"host:port"` | none | `--parent` |
| `no_proxy` | list of patterns | none | `--no-proxy` |

- **`listen`** (restart): where gatir accepts HTTP proxy clients. Write IP
  addresses, not names: `localhost` is rejected. IPv4 and IPv6 are separate, so
  for both write `["127.0.0.1:3128", "[::1]:3128"]`. Keep it on the loopback:
  anyone who can connect uses your identity. If you do listen on other
  addresses, set `[access]`.
- **`parents`**: the corporate proxies, tried in order. Without parents and
  without `[pac]`, gatir connects directly. `parents` and `[pac]` cannot both be
  set.
- **`no_proxy`**: destinations reached directly, without a parent. Each entry is
  one of:
  - a host name, with `*` for any text and `?` for one character, matched
    without regard to case. A name matches only itself: write
    `*.example.com` for the sub-domains of `example.com`;
  - an IP address or a CIDR range (`10.0.0.0/8`, `fd00::/8`). It matches only
    when the client asks for an IP address, never for a name that resolves to
    one.

  Ports are never part of the match.

## `[credentials]`

How gatir authenticates to the parent. Without this table, it sends no
credentials.

| Setting | Type | Default | Option |
|---|---|---|---|
| `method` | `"ntlmv2"`, `"ntlm2sr"`, `"nt"` or `"negotiate"` | `"ntlmv2"` | `-m`, `--method` |
| `username` | text | none | `-u`, `--username` |
| `domain` | text | empty | `-d`, `--domain` |
| `password` | text, secret | none | `--password-prompt` |
| `nt_hash` | 32 hexadecimal digits, secret | none | |
| `ntlmv2_hash` | 32 hexadecimal digits, secret | none | |
| `workstation` | text | this computer's name | |
| `spn` | text | `HTTP@` and the parent's host | |
| `origin_hosts` | list of patterns | none | |

- **`method`**: `ntlmv2` is what current Windows domains expect. `ntlm2sr` and
  `nt` are older forms of NTLM, for proxies that refuse NTLMv2. `negotiate` uses
  the Kerberos ticket of the logged-in user (SSPI on Windows) and takes no
  password. If you are not sure which one your proxy accepts, run `gatir detect`.
- **`username`**, **`domain`**: the account. `username` is required by the NTLM
  methods.
- **`password`**, **`nt_hash`**, **`ntlmv2_hash`**: the secret, one of the three.
  Use `gatir hash` to print an `nt_hash` line, so that the password itself is not
  kept in the file. An `ntlmv2_hash` works only with `method = "ntlmv2"`. With
  `negotiate`, set none of them. `--password-prompt` asks for the password when
  gatir starts, and replaces any secret from the file.
- **`workstation`**: the computer name sent in NTLM messages. By default, the
  first part of this computer's host name, at most 15 characters.
- **`spn`** (`negotiate` only): the service to ask a Kerberos ticket for, when
  it is not `HTTP@` followed by the parent's host name. For example
  `HTTP/proxy.example.com` or `HTTP/proxy.example.com@EXAMPLE.COM`.
- **`origin_hosts`**: servers reached directly that ask for NTLM themselves
  (`401`), such as an intranet site with Windows-integrated authentication.
  gatir answers them with the same credentials. Same patterns as `no_proxy`.
  It needs an NTLM secret, so it cannot be used with `negotiate`. See
  [Authentication](authentication.md).

## `[pac]`

A PAC script that chooses the proxy for each request. See
[PAC scripts](pac.md).

| Setting | Type | Default | Option |
|---|---|---|---|
| `file` | path | none | `--pac` |
| `url` | `http://` or `https://` address | none | `--pac` |
| `system` | `true` or `false` | `false` | |
| `refresh_secs` | 1 to 604800 | 3600 for `url`, 60 for `file` and `system` | |
| `fetch_timeout_secs` | 1 to 300 | 15 | |

- **`file`**, **`url`**, **`system`**: where the script is; set exactly one.
  A relative `file` is relative to the configuration file. `system = true` uses
  the script your system's proxy settings name (macOS and Windows only).
  `--pac` replaces the location, and keeps the other settings of the table.
- **`refresh_secs`**: how often gatir checks whether the script changed.
- **`fetch_timeout_secs`**: how long gatir waits for a script from an address.

### `[[pac.overrides]]`

Hosts that go to other proxies than the script says. Repeat the table for each
group of hosts; the first table that lists a host decides.

| Setting | Type |
|---|---|
| `hosts` | list of names or patterns |
| `proxy` | `"DIRECT"`, or `"PROXY host:port"`, several separated by `;` |

Unlike `no_proxy`, a name in `hosts` also covers its sub-domains.

## `[access]`

Which clients may use gatir, by their IP address. Without this table, every
client is allowed, which is safe only while gatir listens on the loopback.

| Setting | Type | Default |
|---|---|---|
| `default` | `"allow"` or `"deny"` | `"allow"` |
| `rules` | list of `{ allow = "..." }` or `{ deny = "..." }` | none |

Each rule names an IP address, a CIDR range, or `*` for any. The first rule that
matches decides; if none matches, `default` does. For example:

```toml
[access]
default = "deny"
rules = [{ allow = "127.0.0.1" }, { allow = "192.168.0.0/16" }]
```

## `[headers]`

Header fields added to every request that goes through a parent proxy (plain
HTTP requests, and the `CONNECT` that opens an HTTPS tunnel), replacing the ones
the client sent. They are never sent to a server reached directly. Values are
treated as secrets and never logged.

```toml
[headers]
User-Agent = "corp-browser/1.0"
X-Api-Key = "..."
```

These fields cannot be set, because gatir manages them: `Host`,
`Content-Length`, `Transfer-Encoding`, `Connection`, `Proxy-Connection`,
`Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Proxy-Authorization`,
`Proxy-Authenticate`.

## `[[tunnels]]`

A local port forwarded to a fixed destination through the proxy, like
`ssh -L`. Repeat the table for each port. See [Tunnels](tunnels.md).

| Setting | Type | Option |
|---|---|---|
| `listen` | `"address:port"` | `-L`, `--tunnel` |
| `target` | `"host:port"` | `-L`, `--tunnel` |

Tunnels are set up only when gatir starts (restart). On the command line, write
`-L [BIND:]PORT:HOST:HOSTPORT`.

## `[socks5]`

A SOCKS5 server, for programs that do not use HTTP proxies. See
[SOCKS5](socks5.md).

| Setting | Type | Default | Option |
|---|---|---|---|
| `listen` | list of `"address:port"` | required | `--socks5` |
| `username` | text, 1 to 255 bytes | none | |
| `password` | text, 1 to 255 bytes, secret | none | |

- **`listen`** (restart): where the SOCKS5 server accepts clients.
- **`username`**, **`password`**: set both to require them from clients, or
  neither.

## `[timeouts]`

In seconds, each from 1 to 86400.

| Setting | Default | What it limits |
|---|---|---|
| `connect_secs` | 10 | Opening a connection to a server or a parent. |
| `client_idle_secs` | 60 | A client connection that sends nothing. |
| `response_secs` | 120 | Waiting for the head of a response, and each step of the authentication. |
| `tunnel_idle_secs` | 600 | A tunnel with no traffic in either direction. |
| `shutdown_grace_secs` | 10 | On shutdown, waiting for requests and tunnels to finish. |

## `[log]`

| Setting | Type | Default | Option |
|---|---|---|---|
| `level` | `"error"`, `"warn"`, `"info"`, `"debug"` or `"trace"` | `"info"` | `--log-level` |

`level` is read only when gatir starts (restart). The `RUST_LOG` environment
variable replaces it, and can also show the logging of the libraries gatir
uses.
