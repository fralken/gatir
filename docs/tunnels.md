# Forwarding a port through the proxy

A tunnel makes one local port lead to one fixed destination, like `ssh -L`.
gatir carries whatever connects to the port to the destination, through the
parent proxy the configuration chooses, authenticating as usual. It is for
programs that cannot use a proxy themselves: an SSH client, a database client, a
Git remote.

```toml
[[tunnels]]
listen = "127.0.0.1:2222"
target = "git.example.com:22"

[[tunnels]]
listen = "[::1]:5432"
target = "[2001:db8::1]:5432"
```

On the command line, use the OpenSSH form `[BIND:]PORT:HOST:HOSTPORT`, with IPv6
addresses in square brackets:

```sh
gatir run -L 2222:git.example.com:22 -L [::1]:5432:[2001:db8::1]:5432
```

- Without `BIND`, a tunnel listens on the loopback only, so a forwarded port is
  not offered to the network by accident. `BIND` may be an IP address, `*`
  (every IPv4 interface) or `localhost`.
- Tunnels given on the command line replace those in the file.
- gatir does not start if a tunnel's address is taken, or is used by another
  of its listeners.

## How the destination is reached

gatir chooses the way exactly as for a `CONNECT` request:

- `no_proxy` is asked first, and what it lists is reached directly.
- With a PAC script, the script is asked about `https://host/` (`https://host:port/`
  when the port is not 443), like any other tunnel.
- Otherwise the parents are tried in order. gatir asks a parent to open a
  tunnel with `CONNECT host:port`, which carries the `[headers]` fields, and
  authenticates as it does for any other program.

`[access]` applies to the programs that connect to a tunnel too.

## Errors and timeouts

A tunnel has no protocol of its own, so gatir has no way to tell the program
what went wrong: it disconnects it at once. The reason (the parent refused, no
parent is reachable, the PAC script failed, the credentials were rejected) is in
the log at `warn` level, with the program's address and the destination.

A tunnel that carries nothing in either direction for `tunnel_idle_secs` is
closed. On shutdown, gatir waits up to `shutdown_grace_secs` for active tunnels,
then closes them.
