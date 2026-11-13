# A SOCKS5 server

gatir can also act as a SOCKS5 server, for programs that use a SOCKS proxy
instead of an HTTP one: browsers, SSH (`ProxyCommand`), database and chat
clients. gatir carries each connection to its destination like any tunnel,
through the parent proxy the configuration chooses, authenticating as usual.

```toml
[socks5]
listen = ["127.0.0.1:1080"]
# username = "bob"           # optional: without them, anyone [access] lets in can use it
# password = "..."
```

On the command line, `gatir run --socks5 127.0.0.1:1080` replaces the addresses
from the file and keeps the rest of the table. gatir does not start if an
address is taken, or is used by another of its listeners.

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

## Supported requests

Only the `CONNECT` command is served, to an IPv4 address, an IPv6 address or a
host name. `BIND` and `UDP ASSOCIATE` are answered with "command not supported".

Send host names, not addresses. A program that passes the name to the server
(`socks5h://`, or curl's `--socks5-hostname`) lets gatir and the PAC script see
it. A program that looks the name up itself (`socks5://`) sends only the
address, so rules written for names cannot match.

gatir chooses the way exactly as for a tunnel or a `CONNECT` request: `no_proxy`
first, then the PAC script (asked about `https://host/`, or `https://host:port/`
when the port is not 443), then the parents in order. The `[headers]` fields go
in the `CONNECT` sent to a parent. `[access]` is checked first, and a program it
refuses is disconnected.

## Access and authentication

Without `username` and `password`, every program that `[access]` lets in can use
the server, and with it your identity. Keep it on the loopback, or narrow
`[access]`.

With them, a program must use the user name and password method of RFC 1929 and
get both right; nothing else is accepted. The comparison takes the same time
whichever byte differs, and the password is never printed or logged. RFC 1929
sends both in clear text: it keeps others from using the server, but anyone who
can watch the traffic can read them.

## Reply codes

A program that cannot be given a tunnel is told why with the closest code of
RFC 1928. The full reason is in the log at `warn` level, with the program's
address and the destination:

| Code | Meaning | When |
|---|---|---|
| 1 | general failure | the PAC script failed, the credentials were rejected by the parent, or anything else |
| 2 | not allowed | the parent refused with `403`, or the request has port 0 |
| 3 | network unreachable | no parent is reachable |
| 4 | host unreachable | the name does not exist, or is not a host name, or the parent said `502` or `503` |
| 5 | connection refused | nobody listens at the destination |
| 6 | TTL expired | the connection or the parent took too long |
| 7 | command not supported | anything but `CONNECT` |
| 8 | address type not supported | an unknown type of address |

A program that does not speak SOCKS5, offers no method gatir accepts, or gives a
wrong user name or password is disconnected, with the replies RFC 1928 and
RFC 1929 prescribe.

A program has `client_idle_secs` to finish asking for a tunnel. After that, a
tunnel that carries nothing for `tunnel_idle_secs` is closed, and on shutdown
gatir waits up to `shutdown_grace_secs` for active tunnels.
