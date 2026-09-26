# The PAC script engine

gatir runs PAC (proxy auto-configuration) scripts with **QuickJS**, through the
`rquickjs` crate. This records why, what was measured, and what the choice
costs.

## What was needed

- A JavaScript engine that can be embedded, with native helper functions
  (`dnsResolve`, `isInNet`, ...) defined by the host.
- Limits an embedder can enforce on a script it did not write: time, memory,
  stack. A PAC file is configuration, but a bug in it must not hang or crash
  the proxy.
- Enough of the language for the scripts found in the wild: they are often
  written for old browsers and use `substr`, `escape` and `Date.parse` on
  formats that are not ISO 8601.
- A small dependency tree, since gatir audits its dependencies.

## What was measured

Release builds on macOS (arm64), with a fixed time zone and a deterministic
stand-in for DNS. Node (V8) evaluated the same scripts as a reference. The
scripts were a 61 KB PAC written for a real corporate network (kept out of this
repository) evaluated for 1094 URLs, three generated PACs of 80 to 190 KB that
call helpers thousands of times per evaluation, and 36 cases of ordinary and
hostile scripts, each in its own process with a time limit.

| | `rquickjs` 0.14 (QuickJS, C) | `boa_engine` 0.22 (Rust) |
|---|---|---|
| Ordinary and hostile cases passed (of 36) | 35 | 32, with the `annex-b` feature |
| Differences from V8 on the real PAC | 0 | 0, with `annex-b` |
| Time per evaluation of the real PAC | 39 us | 74 us |
| Generated PACs, per evaluation | 0.85 ms, 1.5 us, 0.46 ms | 2.0 ms, 5.1 us, 1.0 ms |
| Start, with a 61 KB script | 1.4 ms | 5.8 ms |
| Binary / resident memory | 1.7 MB / 4.8 MB | 12.2 MB / 13 MB |
| Crates added | 8 | 174 |
| Infinite loop | stopped at a time limit | stopped by an iteration count |
| Memory that grows without end | stopped by a memory limit | hangs, and can exhaust the process |
| Catastrophic regular expression | stopped at the time limit | hangs |
| `Date.parse("January 15, 2020 10:00:00 GMT")` | works | `NaN` |

Boa only runs `substr`, `escape` and `unescape` when it is built with its
`annex-b` feature, which is not on by default. Without it, it failed on the real
PAC.

Neither engine can stop a long loop inside a built-in function, such as
`new Array(4294967295).join("x")`.

## Decision

QuickJS. It has the limits that matter (an interrupt handler, a memory limit, a
stack limit), it runs the scripts correctly, and it is small.

The cost is C code in the process. It is Fabrice Bellard's QuickJS (MIT), widely
used, and it is kept behind `pac::engine`: nothing else in gatir calls into it.
What limits the damage a bad script can do:

- time, memory and stack limits on every evaluation, configurable;
- the one runaway the engine cannot interrupt is caught from outside: the worker
  is given up on and replaced, and after too many, the script is declared broken
  and requests get an error that says so;
- name lookups, which a script cannot interrupt either, run on their own threads
  with a time limit.

If this ever needs to be stronger, the evaluation can move to a separate
process that can be killed, which would also contain a crash of the engine.

## What was not chosen

- **Boa**: pure Rust, and correct on the scripts once built with `annex-b`, but
  with no limit on time or memory, so a runaway script hangs the proxy or takes
  its memory. It also pulls in many more crates.
- **Brimstone**: complete and active, but not published as a crate, it says it is
  not ready for production, its library has no embedding interface (host
  functions are defined with the engine's internal macros), and it has no limits
  on time or stack.

## When to look again

If a pure-Rust engine appears that can be embedded with host functions and
enforces limits on time and memory, it would let gatir drop the only C code it
has.
