# Forwarding a port through the proxy

A tunnel makes one local port lead to one fixed destination, the way
`ssh -L` does. Whatever connects to the port is carried to the destination
through the parent proxy that the configuration chooses, authenticated as usual.
It is for programs that cannot use a proxy themselves: an SSH client, a database
client, a Git remote.

```toml
[[tunnels]]
listen = "127.0.0.1:2222"
target = "git.example.com:22"

[[tunnels]]
listen = "[::1]:5432"
target = "[2001:db8::1]:5432"
```

or on the command line, in the OpenSSH form `[BIND:]PORT:HOST:HOSTPORT`, with
IPv6 addresses in square brackets:

```sh
gatir run -L 2222:git.example.com:22 -L [::1]:5432:[2001:db8::1]:5432
```

Without `BIND` a tunnel listens on the loopback only, so that a forwarded port is
not offered to the network by accident. `BIND` may be an IP address, `*` (every
IPv4 interface) or `localhost`. Tunnels named on the command line replace those
of the file. gatir does not start if a tunnel's address is taken, or is the
address of another listener.

## Which way the bytes go

The destination is chosen exactly as for a `CONNECT` request:

- `no_proxy` is asked first, and what it lists is reached directly.
- With a PAC script, the script is asked about `https://host/` (`https://host:port/`
  when the port is not 443), like any other tunnel.
- Otherwise the parents are tried in order. A parent is asked to open a tunnel
  with `CONNECT host:port`, carrying the header fields of the `[headers]` table,
  and authenticates as it does for browsers.

The client's own access rules (`[access]`) apply.

## When something is wrong

A tunnel has no protocol of its own, so there is nothing to tell the client with:
a client that cannot be served is disconnected at once. The reason (the parent
refused, no parent is reachable, the PAC script failed, the credentials were
rejected) is in the log, at `warn` level, with the client's address and the
destination.

A tunnel that carries nothing in either direction for `tunnel_idle_secs` is closed.
On shutdown gatir waits for active tunnels for `shutdown_grace_secs`, and closes
them after that.
