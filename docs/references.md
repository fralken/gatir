# References

The specifications gatir is implemented from. They are linked, not copied: this
repository does not redistribute third-party documents. When code follows a new
specification, add it here, and cite the section next to the code or test that
depends on a detail of it.

| Document | Revision used | Used for | Where |
|---|---|---|---|
| [MS-NLMP] NT LAN Manager (NTLM) Authentication Protocol | 37.0 (v20260330) | The NTLM messages, password hashes and challenge responses, and the test vectors | `crates/gatir/src/auth/ntlm/` |
| RFC 9110, HTTP Semantics | June 2022 | Connection-specific header fields (7.6.1), idempotent methods (9.2.2), authentication to proxies (11.7), conditional requests with `ETag` and `Last-Modified` (13.1), and redirection (15.4) | `proxy/headers.rs`, `proxy/forward.rs`, `auth/negotiate.rs`, `pac/fetch.rs` |
| RFC 3986, URI: Generic Syntax | January 2005 | Resolving a `Location` against the address it came from (5.2), including removal of dot segments (5.2.4) | `pac/fetch.rs` |
| RFC 4559, SPNEGO-based Kerberos and NTLM HTTP Authentication in Microsoft Windows | June 2006 | The `Negotiate` scheme (4), which a proxy applies with `Proxy-Authenticate` and `Proxy-Authorization` | `auth/negotiate.rs` |
| RFC 9112, HTTP/1.1 | June 2022 | Message framing, in particular a request with both `Content-Length` and `Transfer-Encoding` (6.3) | `tests/proxy.rs` |
| RFC 6585, Additional HTTP Status Codes | April 2012 | `431 Request Header Fields Too Large` (5) | `proxy/server.rs` |
| RFC 1928, SOCKS Protocol Version 5 | March 1996 | The messages of the server: method selection (3), the request (4) and the reply (6), with the CONNECT command only | `proxy/socks5.rs` |
| RFC 1929, Username/Password Authentication for SOCKS V5 | March 1996 | The authentication messages of the server | `proxy/socks5.rs`, `config/socks5.rs` |
| Proxy Auto-Configuration (PAC) file format, as described by MDN (the Netscape original is no longer hosted) | 2026 | The helper functions of a PAC script, the argument forms of `dateRange`, `timeRange` and `weekdayRange`, and the result format | `pac/` |
| IPv6 extensions to the PAC format, Microsoft | 2026 | `dnsResolveEx`, `isResolvableEx`, `isInNetEx`, `myIpAddressEx`, `sortIpAddressList` and `FindProxyForURLEx` | `pac/` |

## Links

- [MS-NLMP], every published revision:
  <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4>
- [MS-NLMP] revision 37.0, PDF:
  <https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-NLMP/%5bMS-NLMP%5d-260330.pdf>
- RFC 9110: <https://www.rfc-editor.org/rfc/rfc9110>
- RFC 9112: <https://www.rfc-editor.org/rfc/rfc9112>
- RFC 3986: <https://www.rfc-editor.org/rfc/rfc3986>
- RFC 1928: <https://www.rfc-editor.org/rfc/rfc1928>
- RFC 1929: <https://www.rfc-editor.org/rfc/rfc1929>
- RFC 4559: <https://www.rfc-editor.org/rfc/rfc4559>
- RFC 6585: <https://www.rfc-editor.org/rfc/rfc6585>
- PAC file format (MDN):
  <https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file>
- IPv6 extensions to the PAC format (Microsoft):
  <https://learn.microsoft.com/en-us/windows/win32/winhttp/ipv6-extensions-to-navigator-auto-config-file-format>

## [MS-NLMP]: sections used

| Section | Content | Used in |
|---|---|---|
| 2.2.1.1 to 2.2.1.3 | NEGOTIATE, CHALLENGE and AUTHENTICATE messages | `message.rs` |
| 2.2.2.1, 2.2.2.5, 2.2.2.7 | AV pairs, negotiate flags, the NTLMv2 client blob | `message.rs`, `response.rs` |
| 3.3.1, 3.3.2 | NTLMv1 and NTLMv2 authentication: hashes and responses | `hash.rs`, `response.rs` |
| 4.2 | Cryptographic values for validation: the test vectors | tests in `hash.rs`, `response.rs`, `message.rs` |
| 6 | Appendix A, cryptographic operations (`DESL`) | `response.rs` |

The test vectors are the hex dumps of section 4.2. They were compared with
revision 37.0 and match, and the section numbers cited in the code exist under
the same headings in it.

The AUTHENTICATE examples of 4.2.3.3 and 4.2.4.3 are compared field by field,
not byte for byte: the specification's messages carry a version field and a
larger flag set (and, for NTLMv2, an encrypted session key) that gatir does not
send.
