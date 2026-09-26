# A SOCKS5 server

gatir can also speak SOCKS5, for the programs that use a SOCKS proxy instead of
an HTTP one: browsers, SSH (`ProxyCommand`), database and chat clients. What a
client asks for is carried to its destination as for any tunnel, through the
parent proxy that the configuration chooses, authenticated as usual.

```toml
[socks5]
listen = ["127.0.0.1:1080"]
# username = "bob"           # optional: without them, anyone let in by [access] may use it
# password = "..."
```

or `gatir run --socks5 127.0.0.1:1080`, which takes the place of the addresses
in the file and keeps the rest of the table. gatir does not start if an address
is taken, or is the address of another listener.

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

## What it does, and does not

Only the `CONNECT` command is served, to an IPv4 address, an IPv6 address or a
host name. `BIND` and `UDP ASSOCIATE` are answered with "command not supported".

A client that gives the host name to the server (`socks5h://`, or curl's
`--socks5-hostname`) lets gatir, and a PAC script, see the name. A client that
looks the name up itself and sends an address (`socks5://`) shows them only the
address, so rules that depend on names cannot match.

The destination is chosen exactly as for a tunnel or a `CONNECT` request:
`no_proxy` first, then the PAC script (asked about `https://host/`, or
`https://host:port/` when the port is not 443), then the parents in order. The
`[headers]` table applies to the request a parent is sent. The client's address
is checked against `[access]`, and a client that is refused is disconnected.

## Who may use it

With no `username` and `password`, every client the access rules let in may
use the server, which means it spends the identity gatir authenticates with. Keep
it on the loopback, or narrow `[access]`. With them, the client must offer the
user name and password method of RFC 1929 and get both right; nothing else is
accepted. The comparison takes the same time whichever byte differs, and the
password is never printed or logged. The method sends them unencrypted, so it
protects a server that is reachable by others, not one that others can listen in on.

## The answer to a request

A client that cannot be given a tunnel is told why with the nearest of the codes
of RFC 1928, and the full reason is in the log, at `warn` level, with the client's
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

A client that does not speak SOCKS5, offers no method gatir accepts, or gives a
wrong user name or password is dropped, with the answers RFC 1928 and RFC 1929
prescribe. A client has `client_idle_secs` to complete its part; after that, a
tunnel that carries nothing for `tunnel_idle_secs` is closed, and on shutdown
gatir waits for active tunnels for `shutdown_grace_secs`.
