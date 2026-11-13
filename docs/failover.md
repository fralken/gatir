# When a parent proxy does not work

Parents come as a list: `parents` in the configuration, or what a PAC script
returns (`PROXY a; PROXY b; DIRECT`). gatir sends a request through the first
one that works, and moves on to the next in two cases:

- **The parent cannot be reached**: the connection is refused, or times out.
- **The parent accepts the connection and closes it before answering the first
  request**, with a FIN or a reset. A listener with nothing behind it does
  this. Browsers behave the same way: Chromium moves on to the next proxy when
  a connection is reset or closed, and not when the proxy answers.

Anything the parent *says* is an answer, not a failure, so gatir does not move
on: a `403` from its policy or a `407` for credentials is passed on or handled
as such. A parent that never answers is not a failure either; the
`response_secs` timeout ends the wait, with a `504`.

## What gatir remembers

A parent that failed is tried last for **one minute**. So a PAC script that
returns the same list every time does not make gatir try the dead proxy first
on every request. Once the minute is over, the parent takes its place in the
list back. If every parent failed recently, gatir tries them in list order
anyway.

A parent counts as working only once it answers, not when it accepts a
connection.

## When a request cannot go to the next parent

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

If no parent is left, the program gets a `502` that names every parent and how
it failed, and the log has a `warn` line for each:

```
No parent proxy is reachable: a.example.com:80 (closed the connection without
answering: Connection reset by peer (os error 54)); b.example.com:80 (timed out)
```

A program connected through SOCKS5 or a forwarded port does not speak HTTP, so
it is simply disconnected, and the reason is in the log.

A parent that closes the connection before answering has been sent no
credentials yet, so moving on to the next one costs no failed logon: the
lockout protection described in [Authentication](authentication.md) is not
involved.
