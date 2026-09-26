# Authenticating to the parent proxy

The credentials apply to whichever parent proxy a request goes to: the ones in
`parents`, or the one a PAC script chooses. What the `[credentials]` table needs
depends on `method`.

## NTLM: `ntlmv2` (the default), `ntlm2sr`, `nt`

The user name, the domain, and a secret: the `password`, or a hash of it so that
the password is not kept in the file (`gatir hash` prints an `nt_hash` line;
`ntlmv2_hash` is the hash some other tools call the NTLMv2 password hash). NTLM
authenticates a connection, not a request, so every new connection to the parent
is authenticated once, and pooled connections already are.

Every attempt with wrong credentials counts as a failed logon against the account,
and a few of them lock it. So gatir lets one attempt at a time through until the
credentials have worked once, and after the parent refuses them it stays away for
five minutes: requests get an error that says so, and reading a configuration
that has changed credentials (a reload, or a restart) is the way to try again.

## Negotiate: `method = "negotiate"`

The identity of the logged-in user, and nothing to keep in the file: Kerberos
when the system can use it, and NTLM inside Negotiate when it cannot (away from
the domain, or for a name that no service is registered under). The exchange
takes a second round when the system falls back to NTLM: the parent answers the
first token with a `407` and a token of its own, and gatir answers that.

What the system answers an NTLM challenge with is made from the password of the
logged-on user, so it is guarded like a configured password: one attempt at a
time until it has worked once, and five minutes away from a parent that refuses
it. A password changed on another computer is the usual cause of a refusal, and
signing out and in again gives the session the new one.

A parent that offers NTLM and not Negotiate answers the first token with a `407`
that names only NTLM. Where the system can do NTLM by itself (Windows can, with
the NTLM package of SSPI), gatir starts that exchange on the same connection,
with the identity of the logged-on user: no password is configured, and the
messages go with the `NTLM` scheme instead of `Negotiate`. It costs one more
round trip on each new connection to that parent, as the Negotiate token is
tried first. Linux and macOS have no NTLM without a password, so there the error
says what the parent offers, and `method = "ntlmv2"` with a password or a hash is
the way.

The service is `HTTP@` and the host name of the parent, or what
`credentials.spn` says: `HTTP/proxy.example.com`, or with a realm,
`HTTP/proxy.example.com@EXAMPLE.COM`. Name the parent by the name its service is
registered under; an address, or another alias, may have none.

- **Linux and macOS** use the GSS-API of the system, with the ticket cache of the
  user: there must be a ticket (`kinit`, or the login of a computer that is in the
  domain) before gatir asks for one. Nothing needs to be typed at gatir. gatir opens
  the library (`libgssapi_krb5.so.2` on Linux, the GSS framework on macOS) when
  Negotiate is configured, and not before: on a computer that lacks it, NTLM works, and
  Negotiate stops at the start with an error that names the library to install.
- **Windows** uses SSPI (`secur32.dll`) with the credentials of the session the
  user is logged on with. It has been tried on a computer of the domain against a
  corporate proxy that offers Negotiate and NTLM: Windows made a Kerberos token,
  the proxy accepted it, and `GET`, `HEAD`, `POST` and `CONNECT` worked. So did the fall
  back to NTLM inside Negotiate, forced by naming the proxy by its address, for which no
  Kerberos service is registered. The NTLM of SSPI for a parent that offers only NTLM
  is written and tested against a mock parent, and has not yet been tried against a
  real one.

## Finding out why it does not work

```sh
gatir negotiate --service HTTP@proxy.example.com
```

asks the system for the first token for that service, without contacting the proxy,
and says what came back:

```
service:     HTTP@proxy.example.com
token:       2081 bytes
mechanisms:  Kerberos
answer:      gatir sends the token with the first request, and answers a
             challenge if the parent sends one (...)
```

- `mechanisms` lists what the token offers, in the order the system prefers: **Kerberos**
  is what is wanted; **NTLM** alone means the system found no way to use Kerberos
  for that name.
- An error says why no token could be made. On Windows it carries the number
  Windows gave and a sentence about it: `SEC_E_TARGET_UNKNOWN` (the service is not
  known: check the name of the parent, or set `credentials.spn`),
  `SEC_E_NO_AUTHENTICATING_AUTHORITY` (no domain controller could be reached:
  is the computer on the network of the company, or its VPN?),
  `SEC_E_NO_CREDENTIALS` (nobody is logged on with a domain identity).
- `RUST_LOG=gatir=debug` shows, for each new connection to the parent, whether an
  answer from the parent was waited for.
