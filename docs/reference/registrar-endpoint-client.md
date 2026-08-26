<!-- markdownlint-configure-file {
  "MD013": { "tables": false }
} -->

# Registrar endpoint client (reference implementation)

This file describes `src/registrar/endpoint/client.rs`, the in-repository
caller of the registrar endpoint. It is the **reference behaviour** this
repository expects of a registrar that dials the endpoint, written as running
code and covered by tests; it is **not** the deployed caller, which is roxyd in
another repository and dials the socket itself.

It is checked in outside the mirrored `docs/en/` + `docs/ko/` operator pair, on
the precedent of `docs/reference/registrar-client-identity.md` and
`docs/reference/registrar-wire-contract.md`: it is cross-repository reference
material rather than operator documentation, so `mkdocs.yml` lists it in
neither locale's nav and there is no `docs/ko/` counterpart.

## 1. How it is constructed

The client is built from four paths and one name, and from nothing else:

| Argument | What it names |
| --- | --- |
| socket path | The host-local `AF_UNIX` socket the endpoint is activated on. |
| pin file path | The trust-anchor pin file described in `docs/reference/registrar-client-identity.md`. |
| certificate path | The registrar client leaf, and whatever chain follows it, as PEM. |
| key path | That leaf's private key, as PEM. |
| expected endpoint name | The endpoint server identity the presented leaf must carry. |

It reads no configuration file and introduces no `agent.toml` key. Every value
arrives as an argument, which keeps configuration ownership where it already is
and makes the client directly constructible from a temporary directory in a
test.

The expected endpoint name is the one `registrar_endpoint_identity` composes,
`<instance>.bootroot-registrar-endpoint.<host>.<domain>`, where `<domain>` is
the configured `network.domain` appended as a **suffix of whatever label count
it was configured with** rather than as a single label. The composed name is
therefore three labels in front of that suffix and its total label count is not
fixed — a one-, two- or three-label domain all compose validly. The client
stores the name and asserts nothing about its shape.

## 2. One request per connection

The endpoint's contract is exactly one request and one response per connection,
after which it closes. The client dials, hands over one encoded request, reads
one response to the end of the stream, and closes. It does not pool, reuse or
pipeline connections, and it never writes a second request on a connection that
has carried one.

A request payload longer than the envelope's `MAX_FRAME_PAYLOAD_BYTES` is
refused locally, with a typed error and before the socket is dialed. The
endpoint would refuse such a frame with a bare close, and there is no reason to
make a caller learn that over the wire.

## 3. What it verifies

Every trust decision belongs to `endpoint_server_verifier`: the trust anchors
are exactly the SHA-256 digests listed in the pin file, and the presented
end-entity certificate must carry one DNS SAN equal to the expected endpoint
name. The client composes that verifier with its own client certificate and
key, and holds no second copy of either rule.

Both halves are rebuilt **on every dial**, so the pin file and the client pair
are re-read every time. A pin file that is missing, unreadable or malformed is
a typed failure of the dial — never a fallback to trusting whatever the peer
presents.

The name handed to the TLS connector is inert: a handshake over `AF_UNIX` has
no hostname to match against, so the verifier ignores the dialed name and
applies the pinned expected name instead.

A server refused by the pin — one chaining to no pinned anchor, or one carrying
a SAN other than the expected name — fails the dial before a request byte is
written, with its own error variant naming the **expected** name. The client
does not parse the peer's certificate, so it does not report the name the
server actually presented.

## 4. The two timeouts and the response bound

| Bound | Value | What it covers |
| --- | --- | --- |
| Connect timeout | 5 s | The dial alone. A host-local `AF_UNIX` connect, at the same scale as the endpoint's own handshake deadline. |
| Read timeout | 30 s | The TLS handshake, the request write and the response read together. It spans the endpoint's verb execution, which has no server-side deadline of its own, with clear headroom over every server-side deadline. |
| Response bound | 65,540 bytes | The response prefix plus the largest payload the endpoint will write, defined by referencing the endpoint's own constants so the two cannot drift. |

The two timeouts are separately observable: a caller can tell which one
elapsed. A response whose prefix declares more than the bound allows fails
before the payload is read, and the read buffer never grows past the bound.

## 5. When the response is complete

The response is complete once the four-byte prefix and exactly the declared
number of payload bytes have arrived. The client then reads **once more**, and
that read decides the exchange:

- a **clean end of stream** completes it, and the payload is decoded only after
  that. This is what the endpoint does: it finishes the frame and shuts the
  connection down, which sends `close_notify`;
- **any byte after the declared payload** fails the exchange with its own error
  variant. The payload is not decoded and no outcome is returned, so a peer
  cannot append a second frame behind a well-formed one and have the first
  honoured;
- an **error** — including the `UnexpectedEof` that `rustls` reports for a peer
  that vanished without `close_notify` — is a transport failure carrying the
  phase it happened in. A response that arrived in full behind an unclean close
  is reported that way rather than returned.

A connection the endpoint ends cleanly after zero application bytes has its own
variant, distinct from a decode failure and from a truncation. That is the
endpoint's designed shape for a caller it will not serve.

One limitation the wire cannot carry: a connection the endpoint refuses
*before* the handshake completes — for capacity, or for peer credentials — has
no application stream to close, so it reaches the client as a connect- or
handshake-level failure and is not distinguishable there from an ordinary one.

## 6. Success or refusal

The endpoint answers a mint with a mint response, a deregister with a
deregister response, and either verb with a refusal response, and the envelope
carries no status field to choose between them. The client fixes one rule, and
it is a rule about the **membership** of the `class` key rather than about that
key's value:

> A response payload that is a JSON object carrying a top-level `class` member
> — whatever that member's value — is a refusal. A JSON object carrying no
> top-level `class` member is the success shape for the operation that was
> sent.

`class` is required and non-nullable on the refusal shape and appears in
neither success shape, while `outcome` is required on both success shapes and
appears in no refusal. The rule rests on `class` never being added to a success
shape, which would be a change to the wire contract in
`docs/reference/registrar-wire-contract.md` rather than something an
implementation may do.

Three consequences follow:

- `{"class": null, …}`, `{"class": 7, …}` and any other wrongly typed `class`
  is a **malformed refusal**, not a success. It reaches the refusal decoder,
  which rejects it, and the client reports a decode failure;
- a payload that is not a JSON object at all — an array, a string, a number, a
  bare `null`, or bytes that are not JSON — fails the discrimination itself,
  and **no** decoder runs;
- exactly one decoder runs for every payload that is a JSON object, and none
  falls back to a second. A decode failure therefore names one shape rather
  than being the residue of two attempts.

**A decoded refusal is a successful exchange.** It is returned in the `Ok`
position, in the refusal arm of the verb's reply, carrying the wire error
identifier and its transient-versus-permanent class exactly as they arrived.
The client does not retry it, reclassify it, collapse two identifiers into one,
or promote it to an error. It implements no retry policy of any kind — not on
connect, not on handshake, not on a transient refusal — because retry semantics
belong with the code that owns the reasons for retrying.
