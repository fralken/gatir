# When a parent proxy does not work

Parents come as a list: the `parents` of the configuration, or what a PAC script
returns (`PROXY a; PROXY b; DIRECT`). A request is sent through the first one
that works. gatir moves on to the next in two cases:

- **It cannot be reached**: the connection is refused, or times out.
- **It accepts the connection and ends it before answering the first request on
  it**: closed (FIN) or reset (RST). A listener with nothing behind it does
  that. It is what a browser does too: Chromium goes on to the next proxy when a
  connection is reset or closed, and does not when the proxy answers.

Anything the parent *says* is not a failure, so nothing moves on: a `403` from
its policy or a `407` for credentials is the answer, and it is passed on or
dealt with as such. A parent that never answers is not a case either; the
`response_secs` timeout ends the wait (a `504`).

## What is remembered

A parent that failed is tried last for **one minute**. This is what keeps a
script that returns the same list every time from trying the dead proxy first on
every request. When the parent answers again, it takes its place back. If every
parent failed lately, they are tried in the order of the list anyway.

A parent is not known to work because it accepted the connection, only because
it answered.

## When the request cannot go to the next one

The next parent is given the same request when nothing of it was delivered: for
a tunnel (`CONNECT`, SOCKS5, `-L`) always, and for a request when the parent
failed during authentication (only a probe or the head of the request went out),
or when the request has no body. A request with a body that was already being
sent, to a parent that wants no authentication, cannot be sent twice: that one
gets a `502`, and the next request does go to the next parent.

If none is left, the client gets a `502` that names every parent and how it
failed, and the log has a `warn` line for each:

```
No parent proxy is reachable: a.example.com:80 (closed the connection without
answering: Connection reset by peer (os error 54)); b.example.com:80 (timed out)
```

A tunnel client that does not speak HTTP (SOCKS5, a forwarded port) is just
disconnected, and the reason is in the log.

Nothing is proved to a parent that ends the connection before answering, so
trying the next one does not count as a failed logon: the lock-out protection of
[authentication](authentication.md) is not involved.
