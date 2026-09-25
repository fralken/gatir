# References

The specifications gatir is implemented from. They are linked, not copied: this
repository does not redistribute third-party documents. When code follows a new
specification, add it here, and cite the section next to the code or test that
depends on a detail of it.

| Document | Revision used | Used for | Where |
|---|---|---|---|
| [MS-NLMP] NT LAN Manager (NTLM) Authentication Protocol | 34.0 (v20210625) and 37.0 (v20260330) | The NTLM messages, password hashes and challenge responses, and the test vectors | `crates/gatir/src/auth/ntlm/` |
| RFC 9110, HTTP Semantics | June 2022 | Connection-specific header fields (7.6.1) and idempotent methods (9.2.2) | `proxy/headers.rs`, `proxy/forward.rs` |
| RFC 9112, HTTP/1.1 | June 2022 | Message framing, in particular a request with both `Content-Length` and `Transfer-Encoding` (6.3) | `tests/proxy.rs` |
| RFC 6585, Additional HTTP Status Codes | April 2012 | `431 Request Header Fields Too Large` (5) | `proxy/server.rs` |

## Links

- [MS-NLMP], every published revision:
  <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4>
- [MS-NLMP] revision 34.0, PDF:
  <https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-NLMP/%5bMS-NLMP%5d-210625.pdf>
- [MS-NLMP] revision 37.0, PDF:
  <https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-NLMP/%5bMS-NLMP%5d-260330.pdf>
- RFC 9110: <https://www.rfc-editor.org/rfc/rfc9110>
- RFC 9112: <https://www.rfc-editor.org/rfc/rfc9112>
- RFC 6585: <https://www.rfc-editor.org/rfc/rfc6585>

## [MS-NLMP]: sections used

| Section | Content | Used in |
|---|---|---|
| 2.2.1.1 to 2.2.1.3 | NEGOTIATE, CHALLENGE and AUTHENTICATE messages | `message.rs` |
| 2.2.2.1, 2.2.2.5, 2.2.2.7 | AV pairs, negotiate flags, the NTLMv2 client blob | `message.rs`, `response.rs` |
| 3.3.1, 3.3.2 | NTLMv1 and NTLMv2 authentication: hashes and responses | `hash.rs`, `response.rs` |
| 4.2 | Cryptographic values for validation: the test vectors | tests in `hash.rs`, `response.rs`, `message.rs` |
| 6 | Appendix A, cryptographic operations (`DESL`) | `response.rs` |

The test vectors are the hex dumps of section 4.2. They were compared with
revisions 34.0 and 37.0 and are the same in both, and the section numbers cited
in the code have the same headings in both.

The AUTHENTICATE examples of 4.2.3.3 and 4.2.4.3 are compared field by field,
not byte for byte: the specification's messages carry a version field and a
larger flag set (and, for NTLMv2, an encrypted session key) that gatir does not
send.
