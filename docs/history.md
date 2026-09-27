# How gatir was built

gatir was written between 24 and 27 September 2026, in English, from a blank
repository, as a ground-up Rust rewrite inspired by CNTLM: not a fork, not a
port, and not a drop-in replacement. It reads no CNTLM source and copies no
CNTLM text; where the two must agree — the bytes of an NTLM message, the
behavior of a PAC script — gatir was written from the public specification and
checked against CNTLM's own output, not against its code.

It was built by its maintainer working with Claude Code, Anthropic's coding
agent (the model was Claude Sonnet 5 throughout); every one of the repository's
commits carries a `Co-Authored-By: Claude Sonnet 5` trailer, so the git history
itself is the most exact record of who wrote what. This document tells the
story that the commits alone do not: which choices were made, why, and what
went wrong along the way. An earlier, larger attempt at the same rewrite (in a
different repository) had been abandoned after growing unverifiable all at
once; this one was deliberately kept small — one working, tested piece at a
time — from the start.

## Ground rules, set before the first line of code

Three decisions were made before anything else, and held for the rest of the
project. Windows, macOS and Linux would be supported from the first commit, not
bolted on at the end: the CI matrix covered all three from day one, and
Windows-specific work (SSPI, later the installer) was never treated as a final
phase, only as work that had to wait for a Windows machine to test on.
Configuration would be a new TOML file, with no compatibility with CNTLM's
`cntlm.conf` and no migration tool: gatir is inspired by CNTLM, not a
replacement for it, so there was nothing to migrate away from. And the two
places that ended up mattering most for a working proxy — a corporate NTLM
parent proxy and a real PAC script — were the maintainer's own, tried by hand
at almost every milestone; nothing about them (hostnames, hashes, the PAC's
contents) was ever kept in this repository or in the assistant's own notes,
which is why this history can be specific about how things were tested without
being specific about where.

## A proxy that forwards, before it authenticates

The first working pieces had nothing to do with credentials. A `tokio`-based
listener, `hyper`'s low-level HTTP/1 connections on both sides, and a small
test harness of mock origin servers came first, proven with real `curl`
requests — chunked bodies both ways, `HEAD`, keep-alive, a gigabyte download
streamed through without ever holding more than a few megabytes of it in
memory at once, graceful shutdown that let an in-flight transfer finish before
a second `Ctrl-C` cut it short. Only once a client could
reach an origin server directly did a parent proxy enter the picture: forwarding
and `CONNECT` through it, failover between several, and a connection pool keyed
by parent, all without a single credential yet. Access control (which client
addresses may connect at all) and `no_proxy` were built early too, as the pure,
easily-tested logic they are.

## NTLM: the part that had to match, byte for byte

NTLM was the first place where "well-known crate" and "does what CNTLM does"
pulled in different directions. The obvious dependency turned out to
explicitly not support the older NTLMv1 and LM dialects that a legacy corporate
proxy might still ask for, so gatir grew its own implementation instead: about
enough code to build the three message types and derive the responses from
RustCrypto's MD4, MD5, HMAC and DES, checked against the worked examples in the
MS-NLMP specification and, independently, against the hashes CNTLM itself
produced for the same test credentials. A `gatir hash` command let the
maintainer pre-compute the hash of their own password once and never store it
in a file. Wiring this into a live connection to a real parent proxy was its
own step — the handshake happens on the same TCP connection as the request it
authenticates, so a request with a body needs a probe request that opens the
exchange without sending that body twice — and it came with a rule that has
stayed load-bearing ever since: every attempt with the wrong credentials is a
failed logon against the account, and enough of them lock it, so gatir lets one
handshake happen at a time and, once a parent has rejected the credentials,
waits five minutes before trying again. The first time this reached the
maintainer's real proxy, it worked: plain requests, `POST`, `CONNECT`, and,
soon after, a whole session of Gmail, WhatsApp Web and Spotify through a
browser pointed at gatir.

## Kerberos, and a platform gap that stayed open for a while

A quick feasibility check found a Kerberos ticket already sitting in the
maintainer's machine, unused — proof that single sign-on was possible without
ever asking for a password. What followed was Negotiate/SPNEGO on Unix through
the system's own GSS-API, exercised first against the maintainer's real
corporate proxy from the command line (a two-thousand-byte token, accepted at
once), then wired into the same connection-pooled request path as NTLM. Windows
support waited much longer, on purpose, until there was a real Windows machine
to test it on: a domain-joined corporate PC, reached only by copying a
cross-compiled `gatir.exe` over the maintainer's cloud storage, since nothing
in this project ever had direct access to a Windows environment. When that
machine finally ran it, it confirmed two things at once: that a proxy which
accepts Kerberos may still silently fall back to NTLM inside the same
Negotiate exchange (macOS's GSS-API had already hinted at this; Windows made it
certain), and that the fallback worked end to end, extra round trip and all.

## Choosing how a PAC script runs

Proxy auto-configuration scripts are ordinary, if often ancient, JavaScript,
and the question was never whether an engine could parse them — it was
whether an embedder could survive a script that loops forever, allocates
without bound, or runs a catastrophic regular expression, since a PAC file is
configuration, and a bug in someone else's configuration must not be able to
hang the proxy. Two engines were benchmarked against each other and against a
real reference implementation, using a purpose-built harness fed the
maintainer's own 1,000-plus-URL production PAC script alongside synthetic
adversarial ones. The comparison briefly gave the pure-Rust candidate an unfair
loss — it had been built without an optional legacy-JavaScript feature it
needed — and correcting that, once it was noticed, changed the numbers but not
the conclusion: the engine written in C had genuine interrupt, memory and stack
limits the pure-Rust one did not, was smaller, and was faster. That C engine
(QuickJS, through the `rquickjs` crate) is the one exception the project's own
rule against unaudited or unnecessary C makes, and it stays fenced behind one
module. Around it: native Rust implementations of every PAC helper function,
a worker pool of engines with a watchdog that abandons and replaces one stuck
inside an uninterruptible native loop, and, once local files worked, fetching a
script from an `http(s)` address with the operating system's own TLS
verification, periodic refresh, and the last good script kept in service if a
refetch ever fails.

## SOCKS5 and local port forwarding, written rather than imported

By the time SOCKS5 came up, the project had a habit of comparing an available
crate against writing the thing itself, and a leading SOCKS5 crate lost that
comparison for reasons familiar from the NTLM decision: it would have added a
handful of dependencies, including a duplicate of one gatir already used at a
different version, for a protocol whose useful subset (`CONNECT` only,
optional username/password) fits in a few hundred lines once written against
the RFCs directly, with full control over timeouts and constant-time credential
comparison. Static local-port tunnels, the `-L` of an SSH client, followed the
same destination-resolution path as everything else — direct, or through
whichever parent the PAC script or the configuration named.

## Living with a running proxy: reload, packaging, a Windows installer

A `SIGHUP` came to mean "read the configuration again without restarting":
credentials, parents, access rules, header rewriting and the PAC source can all
change live, while the five-minute NTLM lockout survives a reload of unchanged
credentials rather than resetting it by accident. Packaging turned out to be
buildable and, more importantly, testable from a single Mac: Linux `.deb` and
`.rpm` packages were built and installed in disposable Linux containers,
Homebrew's own strict formula checker was run against a temporary local tap
before anything real existed to publish, and — once asked for directly — a
Windows `.msi` installer was built and inspected table by table using a
from-scratch, cross-platform reimplementation of the Windows Installer format
that needs neither Windows nor a copy of WiX to run. None of these tools were
taken on faith: each was exercised against a real, disposable install before
being trusted.

One piece of packaging was started and then dropped: a command to install
gatir as a service that starts at login. An early attempt at it was interrupted
partway through by an automatic safety check, and rather than push through it
the maintainer decided a login service was not a priority for a first release;
gatir still has no such command today, on purpose.

## Hardening, and the questions that only a real CI run could answer

Late in the project, two changes made gatir lighter without changing what it
does: the authentication code was reorganized by protocol instead of growing
one large file, and the Kerberos library — until then linked into the binary,
so its absence stopped gatir from starting even for plain NTLM use — was
changed to load only when Negotiate is actually configured, the same way a
plugin would. A home-grown alternative to fuzz testing came next: rather than
the usual tool for the job, which needs an unstable compiler and does not run
on Windows, gatir's parsers are tested by a small mutation engine, built for
this project, that runs inside the ordinary test suite on every supported
platform. Proving that it worked meant deliberately breaking eleven small
things in the code under test — a missing bounds check here, an accepted port
zero there — and confirming that the tests noticed every one of them; two
did not, on the first try, and were fixed by adding the one input that
exercised the gap.

Publishing the repository on GitHub and running its CI for the first time
surfaced exactly one failure, and it was an instructive one: a test written
before Windows had Kerberos support at all still expected Windows to have
none, and nothing short of an actual Windows test run — not cross-compiling,
not linting against the Windows target, not even building the test binary for
it — could have caught that the assumption had quietly gone stale.

## Where it stands

Every one of the plan's original steps — configuration, access control, the
plain proxy, parent authentication with both NTLM and Kerberos, PAC scripts
from a file or a URL, SOCKS5 and port forwarding, reload, and packaging for all
three operating systems — is done, tested, and, for the parts that could only
be proven on real infrastructure, tried against a real corporate proxy and a
real domain-joined Windows PC. A short list of optional extensions was
deliberately left for later, because nothing about them was ever decided:
authenticating to an origin server rather than a parent, a setup helper that
probes a proxy to say what authentication it wants (CNTLM's `-M`), `Expect:
100-continue`, and a side-by-side load comparison against CNTLM itself.
