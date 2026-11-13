# Authentication

gatir authenticates to whichever parent proxy a request goes to: one of
`parents`, or the one a PAC script chooses. What the `[credentials]` table needs
depends on `method`. The same credentials can also answer a few named servers
directly: see [Servers that ask for NTLM
themselves](#servers-that-ask-for-ntlm-themselves).

## NTLM: `ntlmv2` (the default), `ntlm2sr`, `nt`

Set `username`, `domain`, and one secret:

- `password`;
- `nt_hash`, the hash that `gatir hash` prints, which keeps the password itself
  out of the file;
- `ntlmv2_hash`, the hash that some other tools call the NTLMv2 password hash.

NTLM authenticates a connection, not a request. gatir authenticates each new
connection to the parent once, and reuses it for later requests.

Every attempt with wrong credentials counts as a failed logon, and a few of them
lock the account. So, until the credentials have worked once, gatir sends one
attempt at a time. After the parent refuses them, gatir stays away for five
minutes, and requests get an error that says so. To try again sooner, fix the
credentials and reload or restart gatir.

## Negotiate: `method = "negotiate"`

Negotiate uses the identity of the logged-in user, so nothing is kept in the
file. It uses Kerberos when the system can, and falls back to NTLM inside
Negotiate when it cannot: away from the domain, say, or for a proxy name with no
registered service.

The first request on a new connection carries no credentials. gatir asks the
system for a ticket only when the parent answers `407` and offers Negotiate,
because getting a ticket may contact the domain controller. So a parent that
needs no authentication, such as a local relay that a PAC script chooses for
some requests, is never sent a ticket. When the system falls back to NTLM, the
exchange takes one more round: the parent answers the ticket with a `407` and a
token of its own, and gatir answers that.

The system's NTLM answer is derived from the logged-on user's password, so gatir
guards it like a configured password: one attempt at a time until it has worked,
and five minutes away from a parent that refuses it. The usual cause of a
refusal is a password changed on another computer; signing out and in again
gives the session the new one.

If the parent offers NTLM but not Negotiate, it says so in that first `407`.
On Windows, gatir then uses SSPI's own NTLM with the identity of the logged-on
user: no password is needed, and the messages use the `NTLM` scheme. Linux and
macOS have no NTLM without a password; there, gatir reports what the parent
offers, and you need `method = "ntlmv2"` with a password or a hash.

The Kerberos service is `HTTP@` followed by the parent's host name, unless
`credentials.spn` names another, such as `HTTP/proxy.example.com` or
`HTTP/proxy.example.com@EXAMPLE.COM`. Name the parent by the name its service is
registered under: an IP address or another alias may have no service.

### By system

- **Linux and macOS** use the system's GSS-API and the user's ticket cache.
  There must be a ticket before gatir asks for one: from `kinit`, or from
  logging in to a computer in the domain. gatir loads the library
  (`libgssapi_krb5.so.2` on Linux, the GSS framework on macOS) only when
  Negotiate is configured. Without it, NTLM still works, and Negotiate stops at
  start-up with an error that names the library to install.
- **Windows** uses SSPI (`secur32.dll`) with the credentials of the logged-on
  session. It has been tried on a domain computer against a corporate proxy
  that offers Negotiate and NTLM: Kerberos worked for `GET`, `HEAD`, `POST` and
  `CONNECT`, and so did the fallback to NTLM inside Negotiate (forced by naming
  the proxy by its address, which has no Kerberos service). SSPI's NTLM for a
  parent that offers only NTLM has been tested against a mock parent, not yet
  against a real one.

## Servers that ask for NTLM themselves

Some servers ask for NTLM themselves, with a `401` and `WWW-Authenticate`
instead of the parent's `407`: an intranet site with Windows sign-in, for
example. List them in `credentials.origin_hosts`, and gatir answers them with
the same credentials:

```toml
[credentials]
username = "alice"
domain = "CORP"
password = "change-me"
origin_hosts = ["intranet.example.com", "*.corp.example.com"]
```

- This works only for servers reached directly: not through a parent, and not
  inside an HTTPS tunnel, which gatir cannot see into.
- Entries are matched like `no_proxy`: names with `*` and `?`, IP addresses and
  CIDR ranges, without regard to case.
- gatir never sends the credentials to a server that is not listed. A `401`
  from any other server goes to the program, as does a `401` that does not offer
  NTLM (only `Basic`, say).
- It needs an NTLM secret (`password`, `nt_hash` or `ntlmv2_hash`): Negotiate
  has no password to answer a server with, so gatir refuses this setting with
  `method = "negotiate"`.

A wrong password counts as a failed logon here too, so gatir sends one attempt
at a time until the credentials have worked once. After a server refuses them:

- **If they have not worked yet**, the password may be wrong: gatir stops using
  them for five minutes, with the parent too.
- **If they have worked** (with the parent, or another server), the server
  most likely knows the user but does not let them in: gatir keeps away from
  that server alone for five minutes.

A server that asks for credentials only for some requests (a `POST` but not a
`GET`) is not supported. A request with a body is preceded by a `GET`; if only
the request itself is refused, gatir cannot send it again.

## Troubleshooting

### What the system would send: `gatir negotiate`

```sh
gatir negotiate --service HTTP@proxy.example.com
```

This asks the system for the first token for that service, without contacting
the proxy, and describes it:

```
service:     HTTP@proxy.example.com
token:       2081 bytes
mechanisms:  Kerberos
answer:      gatir asks nothing until the parent's 407 asks for Negotiate; then this
             token goes with the request, and nothing more is needed
```

- `mechanisms` lists what the token offers, in the order the system prefers.
  **Kerberos** is what you want. **NTLM** alone means the system found no way
  to use Kerberos for that name.
- If no token could be made, the error says why. On Windows it includes the
  code and its meaning, for example:
  - `SEC_E_TARGET_UNKNOWN`: the service is not known. Check the name of the
    parent, or set `credentials.spn`.
  - `SEC_E_NO_AUTHENTICATING_AUTHORITY`: no domain controller could be reached.
    Is the computer on the company network, or its VPN?
  - `SEC_E_NO_CREDENTIALS`: nobody is logged on with a domain identity.

### What the parent accepts: `gatir detect`

```sh
gatir detect --parent proxy.example.com:8080 --url http://example.com/
```

This sends a request without credentials, to see whether the parent asks for
authentication and what it offers. Then, if credentials are configured and the
parent offers their scheme, it tries them: once for Negotiate, and for NTLM one
method at a time (`ntlmv2`, `ntlm2sr`, `nt`) until one is accepted.

```
parent:      proxy.example.com:8080
url:         http://example.com/
probe:       HTTP 407 (authentication required)
offers:      Negotiate, NTLM
trying ntlmv2... rejected
trying ntlm2sr... rejected
trying nt... accepted
----------------------------------------
gatir can authenticate to this parent with the configured credentials using
method = "nt".
```

Each method tried is a real login. With a wrong password, all three are
rejected: three failed logons, not one. `detect` tests only the first of
`parents` (or `--parent`), never a PAC script: to test the parent a script would
choose, name it with `--parent`.

### The log

`RUST_LOG=gatir=debug` shows the steps of each authentication: when the parent
asks for Negotiate and gatir asks the system for a ticket, when it uses the
system's NTLM instead, and when the parent accepts the credentials.
