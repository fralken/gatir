# Load-testing gatir

`gatir-loadgen` measures gatir's throughput and latency as an HTTP proxy, with a
parent that really asks for NTLM. It is in this workspace (`crates/loadgen`): run
it with `cargo run --release -p gatir-loadgen --`, or build it and run
`gatir-loadgen`.

The usual tools did not fit:

- **curl** in a loop cannot report throughput or latency percentiles, and it
  obeys `no_proxy` even with `-x`: a destination on `127.0.0.1` is often listed
  there, and curl then bypasses the proxy without saying so. (`--noproxy ''`
  turns that off.)
- **Apache Bench** (`ab`) has `-X proxy:port`, but through a proxy it did not
  reuse connections the way `-k` should, and connection reuse is what a proxy
  test must get right.
- **Neither gives the proxy a parent that asks for authentication.** Without
  one, the authentication of new connections and their pooling are never
  exercised: a proxy that authenticates once per connection and one that
  authenticates every request look the same.

`gatir-loadgen` uses the same `hyper` client as gatir, so it sends real HTTP/1.1
keep-alive traffic.

## `serve-parent`: a parent that asks for NTLM

```sh
gatir-loadgen serve-parent [--user U] [--domain D] [--password P]
```

This starts a parent proxy that asks for NTLM (by default `bench`, `BENCH`,
`change-me`) on a free port, and prints its address:

```
listening on 127.0.0.1:54321
credentials: user=bench domain=BENCH password=change-me
(Ctrl-C to stop)
```

Once a connection is authenticated, every request gets the same small reply, so
no origin server's response time affects the measurement. The reply says
`Connection: keep-alive` explicitly, because some proxies reuse a connection
only when told so.

Point the proxy under test at the printed address, with the same credentials.
For gatir:

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

- `origin-host:port` can be `serve-parent`'s own address: the target does not
  have to exist, since `serve-parent` answers every request the same way.
- `bench` opens `connections` persistent connections to the proxy, and on each
  sends `GET`s one after another for `seconds`, waiting for each full response
  before the next: keep-alive, not pipelining.
- A connection that drops is reopened, so a dropped socket lowers the count
  instead of ending the run.

```
connections=10 requests=69028 errors=0 seconds=5 rps=13805.6
latency_us: p50=406 p90=816 p95=914 p99=1241 max=57237
```

`errors` counts requests that failed (the connection dropped mid-request) or got
a status other than 2xx. If `errors` grows across identical runs, explain that
before trusting the `rps` and latency next to it.

## Soak testing

For a soak test, run the same `bench` for several minutes, at a concurrency the
proxy handles cleanly in a short run. Sample the proxy's resident memory now and
then (`ps -o rss= -p <pid>`, or Activity Monitor). Memory that grows once and
then stays flat is normal; memory that keeps growing is a leak.

## Port exhaustion on macOS

Many short-lived connections through `127.0.0.1` can use up the ephemeral port
range (16384 ports by default: `sysctl net.inet.ip.portrange.first` and
`.last`) while closed sockets wait in `TIME_WAIT` (about twice
`sysctl net.inet.tcp.msl` milliseconds). Both the proxy and `gatir-loadgen` then
fail new connections with `Can't assign requested address`.

This is a limit of the local computer in a loopback test, not of the proxy.
It gets worse when runs follow each other closely, since the sockets left by one
run take about 30 seconds to clear. Pause between high-concurrency runs, or
lower the concurrency.

## Comparing with another proxy

`serve-parent` speaks real NTLM on a real port, so any other proxy that
authenticates to an NTLM parent can be pointed at it with the same credentials,
and measured with the same `bench` command. Only a comparison with the same
parent and the same load tool is worth drawing conclusions from.
