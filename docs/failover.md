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

A parent that ends the connection after reading a request may have passed it on
first, so the next parent is given the same request only when doing it twice is
harmless:

- **A tunnel** (`CONNECT`, SOCKS5, `-L`): always. Nothing goes through it
  before the parent answers.
- **A request without a body whose method is idempotent** (`GET`, `HEAD`,
  `OPTIONS`, `TRACE`, `PUT`, `DELETE`, as defined by RFC 9110).
- **Any request, when the parent fails during authentication.** Only a probe
  (a `GET`) has gone out by then, or the request itself if it is one of the
  above.

Any other request, such as a `POST`, gets a `502`, and the next request goes to
the next parent.

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
