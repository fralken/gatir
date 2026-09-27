# Load-testing gatir

`gatir-loadgen`, a small tool in this workspace (`crates/loadgen`, run as
`cargo run --release -p gatir-loadgen --` or the built `gatir-loadgen`
binary), measures gatir's own throughput and latency as a plain HTTP proxy,
and gives it something real to authenticate to while doing it. It exists
because the obvious choices for this turned out not to fit:

- **curl**, run in a loop, is subject to the shell's `no_proxy`/`NO_PROXY`
  environment variable even when the proxy is named explicitly with `-x`: a
  destination on `127.0.0.1` (a natural choice for a local load test) is
  likely to be in that list already, in which case curl quietly bypasses the
  proxy under test and talks to the destination directly — nothing in its
  output makes this obvious unless `-v` is read carefully. `--noproxy ''`
  overrides it; still, curl one request at a time cannot report throughput or
  latency percentiles across many requests.
- **Apache Bench** (`ab`), the one load-testing tool macOS ships, has a `-X
  proxy:port` option for exactly this, but its keep-alive handling through a
  proxy did not behave predictably in practice (connections did not appear to
  be reused the way `-k` implies), which is exactly what a proxy load test
  needs to be measuring correctly.
- Neither gives the proxy a **parent that actually asks for authentication**.
  A load test against a bare, no-auth-needed backend never exercises the
  parent-connection handshake or its pooling, which is a large part of what
  makes a corporate-proxy client's design (gatir's, or any other's) worth
  measuring in the first place; a proxy that authenticates once per
  connection and one that re-authenticates every request can look identical
  against a backend that never challenges either of them.

`gatir-loadgen` is a thin wrapper around the same low-level `hyper` client
gatir itself uses, so what it measures is genuine HTTP/1.1 keep-alive traffic
with no tool-specific quirks in the way.

## `serve-parent`: something real to authenticate to

```sh
gatir-loadgen serve-parent [--user U] [--domain D] [--password P]
```

Starts a parent proxy that actually challenges for NTLM (defaults:
`bench`/`BENCH`/`change-me`), on an ephemeral port, and prints it:

```
listening on 127.0.0.1:54321
credentials: user=bench domain=BENCH password=change-me
(Ctrl-C to stop)
```

Every request it accepts, once authenticated, gets the same small fixed
reply, so the origin's own response time never confounds what is being
measured. It answers with an explicit `Connection: keep-alive` — some
proxies only treat a connection as reusable when told so outright, not merely
by the absence of `Connection: close` that HTTP/1.1 already implies, so a
partner that says so explicitly is the fairer, more representative one to
benchmark against.

Point the proxy under test's configuration at the address it printed, with
matching credentials, e.g. for gatir:

```toml
listen = ["127.0.0.1:3128"]
parents = ["127.0.0.1:54321"]

[credentials]
method = "ntlmv2"
username = "bench"
domain = "BENCH"
password = "change-me"
```

## `bench`: the load

```sh
gatir-loadgen bench <proxy-host:port> <origin-host:port> <connections> <seconds>
```

`origin-host:port` is `serve-parent`'s own address here (the request target
does not have to be real: `serve-parent` answers everything the same way).
Opens `connections` persistent connections to the proxy, and on each fires
`GET`s back to back for `seconds`, waiting for the full response before
sending the next — real keep-alive traffic, not pipelining. A connection that
drops for any reason is simply reopened, so a dropped socket lowers the
count instead of ending the run: what is measured is the proxy's throughput,
not this tool's tolerance for a single dropped connection.

```
connections=10 requests=69028 errors=0 seconds=5 rps=13805.6
latency_us: p50=406 p90=816 p95=914 p99=1241 max=57237
```

`errors` counts a request that failed outright (the connection dropped
mid-request) or came back with a non-2xx status; a growing `errors` count
across otherwise-identical runs is itself a finding worth explaining before
trusting the `rps`/latency numbers next to it.

## Soaking

The same `bench` command with a longer `seconds` is the soak test: run it for
several minutes at a concurrency the proxy handles cleanly at short duration,
and watch its resident memory over that time (`ps -o rss= -p <pid>` sampled
every so often, or Activity Monitor) for growth that does not level off — a
leak, as opposed to memory that grows once and then stays flat.

## A known pitfall of loopback benchmarking on macOS

Pushing many short-lived connections through 127.0.0.1 can exhaust the
ephemeral port range (`sysctl net.inet.ip.portrange.first`/`.last`, 16384
ports by default) before any of them naturally leave `TIME_WAIT`
(`sysctl net.inet.tcp.msl`, so roughly twice that many milliseconds): both the
proxy under test and `gatir-loadgen` itself then start seeing `Can't assign
requested address` on new outbound connections. This is a limit of the local
machine's own port pool during a synthetic loopback test, not necessarily a
statement about the proxy's real capacity, and it gets worse across
consecutive runs if a previous one churned through connections quickly (the
`TIME_WAIT` sockets it left behind take their own ~30 seconds to clear, all
the while shared with whatever a following run tries to do). Give a machine a
short pause between high-concurrency runs, or lower the concurrency, if this
shows up.

## Comparing against another proxy

Since `serve-parent` speaks real NTLM over a real port, any other proxy that
can authenticate to a corporate NTLM proxy can be pointed at it the same way
gatir is above, with the same credentials, and benchmarked with the same
`bench` command — a same-backend, same-load-tool comparison, which is the
only kind worth drawing conclusions from.
